#!/usr/bin/env python3
"""Generate the labeled-by-construction mutation corpus (make mutations).

Plants parameterized secret-handling attack instances (and hard negatives) into
realistic MCP-server-shaped host modules, one planted site per file. Everything is
deterministic (index-driven, no RNG) so `make mutations` reproduces byte-identical
output; the tree hash is asserted like the real corpus.

Design guards against the two ways this fails (wargame Move 1.3):
  - Overfitting the planting TEMPLATE: idioms are varied (secret name, sink fn,
    assignment style, host skeleton) and there are NO planting markers in the
    emitted code (no marker comments, no telltale variable names).
  - A meaningless recall number: entire mutation CLASSES are held out. Detectors
    tune on the `tune` split and are scored on the `holdout` split + the
    hand-labeled real findings. The split is a property of the class, not the
    instance.

Planted secret VALUES are structurally defanged (see CLAUDE.md fixture convention):
obviously fake and failing provider validators, while still matching shape rules a
detector may define. corpus/mutations/ is gitignored and regenerated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEST = REPO_ROOT / "corpus" / "mutations"
MANIFEST = REPO_ROOT / "corpus" / "mutations.json"

# --- idiom pools (varied so detectors can't key on a single template) -----------

SECRETS = [
    ("API_KEY", "apiKey"),
    ("GITHUB_TOKEN", "ghToken"),
    ("SLACK_BOT_TOKEN", "slackToken"),
    ("DATABASE_URL", "dbUrl"),
    ("STRIPE_SECRET_KEY", "stripeKey"),
    ("OPENAI_API_KEY", "modelKey"),
]
LOG_SINKS = ["console.log", "console.error", "console.warn"]
# Defanged fake token literals: fake to a human AND failing provider validators
# (wrong length/checksum), while still shape-matching. Never real.
FAKE_TOKENS = [
    ("ghp_", '"ghp_FAKE0000000000000000000000000000"'),
    ("xoxb-", '"xoxb-11111-22222-FAKEabcdefghijklmnop"'),
    ("AKIA", '"AKIAFAKE0000EXAMPLE0"'),
]

# host skeletons — realistic surrounding code, {BODY} is the planted region ------

HOSTS = [
    # tool-handler shape
    '''import {{ Server }} from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({{ name: "svc-{n}", version: "0.1.0" }});

async function handleTool(args: {{ query: string }}) {{
{BODY}
  return {{ ok: true }};
}}

export {{ server, handleTool }};
''',
    # class-method shape
    '''export class ServiceClient {{
  private endpoint = "https://api.example.com/v1";

  async run(input: string): Promise<void> {{
{BODY}
  }}
}}
''',
    # top-level init shape
    '''const settings = {{ region: "us-east-1", retries: 3 }};

export function init(): void {{
{BODY}
}}
''',
]

INDENT = "  "


def env_read(assign_style: str, env_name: str, var: str) -> str:
    if assign_style == "const":
        return f"const {var} = process.env.{env_name};"
    if assign_style == "let":
        return f"let {var} = process.env.{env_name};"
    if assign_style == "destructure":
        return f"const {{ {env_name}: {var} }} = process.env;"
    raise ValueError(assign_style)


# --- mutation classes -----------------------------------------------------------
# Each returns the planted BODY lines (list[str]) and the 0-based index of the
# line that carries the leak (the "sink line"). label: "bad" (must catch) or
# "good" (hard negative — must NOT flag).

def c_direct_env_log(i, env, var, sink, style):
    return [f"{sink}(process.env.{env});"], 0, "bad"


def c_aliased_log(i, env, var, sink, style):
    return [env_read(style, env, var), f"{sink}({var});"], 1, "bad"


def c_template_log(i, env, var, sink, style):
    return [env_read(style, env, var), f"{sink}(`config: {var}=${{{var}}}`);"], 1, "bad"


def c_secret_in_url(i, env, var, sink, style):
    return [env_read(style, env, var),
            f'await fetch(`https://api.example.com/x?token=${{{var}}}`);'], 1, "bad"


def c_secret_in_header(i, env, var, sink, style):
    return [env_read(style, env, var),
            f'await fetch("https://api.example.com/x", {{ headers: {{ "X-Secret": {var} }} }});'], 1, "bad"


def c_secret_in_body(i, env, var, sink, style):
    return [env_read(style, env, var),
            f'await fetch("https://api.example.com/x", {{ method: "POST", body: JSON.stringify({{ token: {var} }}) }});'], 1, "bad"


def c_cross_function_hop(i, env, var, sink, style):
    # interprocedural: v1 intra-file taint is expected to MISS this — recall here
    # measures the documented known-miss, not detector quality.
    helper = f"emit{i}"
    return [f"function {helper}(v: string) {{ {sink}(v); }}",
            env_read(style, env, var),
            f"{helper}({var});"], 2, "bad"


def c_hardcoded_token(i, env, var, sink, style):
    _, literal = FAKE_TOKENS[i % len(FAKE_TOKENS)]
    return [f"const token = {literal};", f'await fetch("https://api.example.com/x", {{ headers: {{ Authorization: token }} }});'], 0, "bad"


def c_secret_to_file(i, env, var, sink, style):
    return [env_read(style, env, var),
            f'await fs.writeFile("/tmp/out", {var});'], 1, "bad"


# hard negatives (must NOT be flagged) — the real-world FP idioms, planted
def n_name_not_value(i, env, var, sink, style):
    return [f'{sink}("{env} environment variable is required");'], 0, "good"


def n_path_not_secret(i, env, var, sink, style):
    pathenv = env.replace("KEY", "PATH").replace("TOKEN", "FILE").replace("URL", "PATH")
    if pathenv == env:
        pathenv = env + "_PATH"
    return [f"const p = process.env.{pathenv};", f"{sink}(`loading from ${{p}}`);"], 1, "good"


CLASSES = [
    # id, fn, split
    ("direct-env-log", c_direct_env_log, "tune"),
    ("aliased-log", c_aliased_log, "tune"),
    ("template-log", c_template_log, "tune"),
    ("secret-in-url", c_secret_in_url, "tune"),
    ("secret-in-header", c_secret_in_header, "tune"),
    ("secret-in-body", c_secret_in_body, "tune"),
    ("cross-function-hop", c_cross_function_hop, "holdout"),
    ("hardcoded-token", c_hardcoded_token, "holdout"),
    ("secret-to-file", c_secret_to_file, "holdout"),
    ("neg-name-not-value", n_name_not_value, "negative"),
    ("neg-path-not-secret", n_path_not_secret, "negative"),
]

ASSIGN_STYLES = ["const", "let", "destructure"]


def indent_body(lines: list[str]) -> tuple[str, list[int]]:
    """Indent planted lines into a host BODY; return text + per-line file numbers.

    Line numbers are resolved after host substitution by the caller."""
    return "\n".join(INDENT + ln for ln in lines), list(range(len(lines)))


def tree_sha256(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(path.relative_to(root).as_posix().encode())
        h.update(b"\0")
        h.update(hashlib.sha256(path.read_bytes()).hexdigest().encode())
        h.update(b"\n")
    return h.hexdigest()


def generate() -> dict:
    if DEST.exists():
        shutil.rmtree(DEST)
    instances = []
    idx = 0
    for class_name, fn, split in CLASSES:
        # vary idioms deterministically: cross secrets × sinks × styles × hosts
        combos = []
        for si in range(len(SECRETS)):
            for hi in range(len(HOSTS)):
                combos.append((si, hi))
        # cap per class to keep the corpus focused but well over 100 total
        for k, (si, hi) in enumerate(combos):
            env, var = SECRETS[si]
            sink = LOG_SINKS[(idx) % len(LOG_SINKS)]
            style = ASSIGN_STYLES[(si + hi) % len(ASSIGN_STYLES)]
            body_lines, sink_ofs, label = fn(idx, env, var, sink, style)
            body_text, _ = indent_body(body_lines)
            host = HOSTS[hi].format(n=idx, BODY=body_text)
            # locate the planted region: first planted line inside the host
            host_lines = host.splitlines()
            planted_first = next(li for li, ln in enumerate(host_lines)
                                 if ln.strip() == body_lines[0].strip())
            sink_line = planted_first + sink_ofs + 1  # 1-based
            rel = Path(split) / class_name / f"m{idx:03d}.ts"
            out = DEST / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(host)
            instances.append({
                "id": f"m{idx:03d}",
                "class": class_name,
                "split": split,
                "label": label,
                "file": rel.as_posix(),
                "sink_line": sink_line,
                "env": env,
                "idiom": {"sink": sink, "assign": style, "host": hi},
            })
            idx += 1

    manifest = {
        "version": 1,
        "generated_by": "scripts/plant_mutations.py",
        "note": "Labeled-by-construction. label=bad => a credential detector must fire on sink_line; label=good => it must NOT. Splits: tune (detector development), holdout (scored, never tuned on), negative (precision hard-cases). cross-function-hop is a known intra-file-taint MISS for v1 — its recall documents the limitation, it is not a bug.",
        "splits": {
            s: sum(1 for x in instances if x["split"] == s)
            for s in ("tune", "holdout", "negative")
        },
        "classes": {c: {"split": sp} for c, _, sp in CLASSES},
        "counts": {
            "total": len(instances),
            "bad": sum(1 for x in instances if x["label"] == "bad"),
            "good": sum(1 for x in instances if x["label"] == "good"),
        },
        "instances": instances,
    }
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="regenerate and assert the committed manifest is unchanged")
    args = ap.parse_args()

    manifest = generate()
    tree = tree_sha256(DEST)
    manifest["tree_sha256"] = tree

    if args.check:
        if not MANIFEST.exists():
            print("ERROR: no committed manifest to check against", file=sys.stderr)
            return 1
        committed = json.loads(MANIFEST.read_text())
        if committed.get("tree_sha256") != tree:
            print(f"ERROR: mutation tree hash drift\n  committed {committed.get('tree_sha256')}\n  actual    {tree}",
                  file=sys.stderr)
            return 1
        print(f"[check] mutations reproducible: {manifest['counts']['total']} instances, tree {tree[:12]}")
        return 0

    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    c = manifest["counts"]
    print(f"[done] {c['total']} instances ({c['bad']} bad / {c['good']} good) "
          f"across {len(CLASSES)} classes; splits {manifest['splits']}")
    print(f"[hash] {tree}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
