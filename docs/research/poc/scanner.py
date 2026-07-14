#!/usr/bin/env python3
"""
mcp-scan POC — throwaway spike scanner for MCP server security hygiene.
Stdlib only. Static analysis of MCP server source (.ts/.js/.py) + tool schemas.

Purpose of this POC: answer ONE question — does a heuristic static scanner surface
REAL, non-trivial findings on REAL MCP servers, with low enough noise to be credible?
NOT production code. Checks are intentionally a representative subset across three lenses:
  A. Tool-description injection ("tool poisoning")   — the LLM-behavior surface
  B. Credential / secret handling                    — the differentiation lens (least-privilege moat)
  C. Capability / permission over-scoping            — exec, SSRF, SQL, fs breadth

Usage: python3 scanner.py <path-to-repo-or-dir> [more dirs...]
"""
import os, re, sys, json, unicodedata
from collections import defaultdict

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ---- A. Tool-description injection patterns (aimed at the AGENT, hidden from the user) ----
INJECTION_PHRASES = [
    r"\bignore (all |the |previous |above )?(instructions|prompts?)\b",
    r"\bdo not (tell|mention|inform|reveal|notify)\b",
    r"\bwithout (telling|informing|notifying|alerting) the user\b",
    r"\byou must (always|first|immediately)\b",
    r"\bbefore (using|calling) (any|other|the) (other )?tools?\b",
    r"\b(system|developer) prompt\b",
    r"<important>|<secret>|<system>|<instructions?>",
    r"\bdo not (describe|explain) (this|these)\b",
    r"\balways (call|use|invoke|run)\b",
    r"\bnever (tell|reveal|show|disclose)\b",
]
INJECTION_RE = re.compile("|".join(INJECTION_PHRASES), re.IGNORECASE)

# Invisible / control characters used to smuggle hidden instructions into descriptions.
HIDDEN_CHARS = {
    "​": "ZERO WIDTH SPACE", "‌": "ZWNJ", "‍": "ZWJ",
    "⁠": "WORD JOINER", "﻿": "BOM/ZWNBSP",
    "‪": "LTR EMBEDDING", "‫": "RTL EMBEDDING", "‮": "RTL OVERRIDE",
    "⁦": "LTR ISOLATE", "⁧": "RTL ISOLATE", "⁨": "FIRST STRONG ISOLATE",
}

# ---- B. Hardcoded secret patterns ----
SECRET_PATTERNS = [
    ("GitHub token",      re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("Slack token",       re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("AWS access key",    re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key",    re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Generic assigned secret",
        re.compile(r"""(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"][A-Za-z0-9/+_\-]{12,}['"]""")),
]
# env credential names (used for the credential-flow lens)
CRED_ENV_RE = re.compile(r"""(?:process\.env\.|os\.environ(?:\.get)?\(?['"]?)([A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CRED|OAUTH|AUTH)[A-Z0-9_]*)""")

# ---- C. Capability / permission surfaces ----
CAP_PATTERNS = [
    ("high",     "Command execution surface",
        re.compile(r"\b(child_process|execSync|exec\(|spawnSync|spawn\(|os\.system|subprocess\.(?:run|call|Popen|check_output))\b")),
    ("critical", "Dynamic code eval",
        re.compile(r"(?<![\w.])eval\(|new Function\(|\bexec\(compile\(")),
    ("medium",   "Outbound fetch (SSRF surface if URL is caller-controlled)",
        re.compile(r"\b(fetch\(|axios\.|https?\.get\(|https?\.request\(|requests\.(?:get|post|put|delete)\(|urlopen\()")),
    ("medium",   "SQL built from string interpolation (injection surface)",
        re.compile(r"""(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\b[^;'"]*(\$\{|\+\s*\w|%s|%\(|\.format\(|f['"])""")),
    ("low",      "Broad filesystem access",
        re.compile(r"\b(fs\.(?:readFile|writeFile|unlink|rmdir|readdir)|open\([^)]*['\"]w|shutil\.(?:rmtree|move)|os\.remove)\b")),
]

CODE_EXT = (".ts", ".js", ".mjs", ".cts", ".mts", ".py")
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv", "vendor"}
# v2: exclude test/example files — they carry spawn/exec that isn't the server's attack surface
SKIP_FILE_RE = re.compile(r"(__tests__|__mocks__|/tests?/|/examples?/|\.test\.|\.spec\.|conftest\.)")
# v2: assignment of an env-var VALUE to a local variable (so we can taint-track the value, not the name)
CRED_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+(\w+)\s*=\s*process\.env\.([A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CRED|OAUTH|AUTH)[A-Z0-9_]*)"""
    r"""|(\w+)\s*=\s*os\.environ(?:\.get)?\(?['"]([A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|CRED|OAUTH|AUTH)[A-Z0-9_]*)""")
SINK_RE = re.compile(r"(console\.(?:log|error|warn|info)|logging\.(?:info|debug|error|warning)|print|res\.send|return)\s*\(")
# Extract the string value of a `description: "..."` (TS) or description="..."/docstring (Py)
DESC_TS_RE = re.compile(r"""description\s*:\s*(?:`([^`]*)`|"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""")
DESC_PY_RE = re.compile(r"""description\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|"{3}(.*?)"{3})""", re.DOTALL)


def iter_files(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            full = os.path.join(dp, fn)
            if fn.endswith(CODE_EXT) and not SKIP_FILE_RE.search(full):
                yield full


def lineno(text, idx):
    return text.count("\n", 0, idx) + 1


def descriptions(text, is_py):
    out = []
    rx = DESC_PY_RE if is_py else DESC_TS_RE
    for m in rx.finditer(text):
        val = next((g for g in m.groups() if g is not None), "")
        out.append((val, m.start()))
    return out


def scan_file(path, rel):
    findings = []
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return findings
    is_py = path.endswith(".py")

    def add(sev, cat, msg, idx, snippet):
        findings.append({"severity": sev, "category": cat, "message": msg,
                         "file": rel, "line": lineno(text, idx),
                         "snippet": snippet.strip()[:130]})

    # A. injection language inside tool DESCRIPTIONS (high signal: aimed at the model)
    for val, idx in descriptions(text, is_py):
        for m in INJECTION_RE.finditer(val):
            add("high", "tool-poisoning",
                f"Imperative/secrecy instruction in tool description: '{m.group(0)}'",
                idx, val)
        if len(val) > 900:
            add("low", "tool-poisoning",
                f"Unusually long tool description ({len(val)} chars) — hidden-instruction vector",
                idx, val[:80])
    # A. hidden unicode anywhere (very high signal)
    for i, ch in enumerate(text):
        if ch in HIDDEN_CHARS:
            add("high", "tool-poisoning",
                f"Hidden/control character {HIDDEN_CHARS[ch]} (U+{ord(ch):04X}) — invisible-instruction smuggling",
                i, text[max(0, i-30):i+10])
            break  # one per file is enough signal

    # B. hardcoded secrets
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            add("critical", "credential", f"Possible hardcoded {name}", m.start(),
                m.group(0)[:12] + "…")
    # B. credential env flow (the differentiation lens) — v2: taint the VALUE variable, not the name.
    # Bind each local var that holds a secret value, then flag only if THAT VARIABLE reaches a sink.
    creds = set(m.group(1) for m in CRED_ENV_RE.finditer(text))
    tainted = {}  # varname -> env cred it holds
    for m in CRED_ASSIGN_RE.finditer(text):
        var = m.group(1) or m.group(3); env = m.group(2) or m.group(4)
        if var and env:
            tainted[var] = env
    if tainted:
        for sm in SINK_RE.finditer(text):
            call = text[sm.start():sm.start()+160]
            args = call[call.find("(")+1:]
            for var, env in tainted.items():
                # word-boundary match on the value variable inside the sink's arguments
                if re.search(rf"\b{re.escape(var)}\b", args):
                    add("high", "credential",
                        f"Secret value ({env}) may reach a log/response sink via `{var}` (leakage)",
                        sm.start(), call.splitlines()[0])
                    break
            else:
                continue
            break

    # C. capability / permission surfaces
    for sev, cat, rx in CAP_PATTERNS:
        for m in rx.finditer(text):
            add(sev, "capability", cat, m.start(), text[m.start():m.start()+90].splitlines()[0])

    return findings, sorted(creds)


def scan_target(root):
    rootname = os.path.basename(root.rstrip("/"))
    all_findings, all_creds = [], set()
    nfiles = 0
    for path in iter_files(root):
        nfiles += 1
        rel = os.path.relpath(path, root)
        res = scan_file(path, rel)
        if not res:
            continue
        fnd, creds = res
        all_findings.extend(fnd)
        all_creds.update(creds)
    return {"server": rootname, "files": nfiles, "creds": sorted(all_creds),
            "findings": all_findings}


def main():
    targets = sys.argv[1:]
    if not targets:
        print("usage: scanner.py <dir> [dir...]"); sys.exit(2)
    # expand: each immediate child dir with code is a 'server'
    servers = []
    for t in targets:
        subdirs = [os.path.join(t, d) for d in sorted(os.listdir(t))
                   if os.path.isdir(os.path.join(t, d)) and d not in SKIP_DIRS] if os.path.isdir(t) else []
        code_subdirs = [d for d in subdirs if any(iter_files(d))]
        servers.extend(code_subdirs if code_subdirs else [t])

    reports = [scan_target(s) for s in servers]
    reports = [r for r in reports if r["files"]]

    # ---- summary ----
    tot = defaultdict(int)
    cat = defaultdict(int)
    print(f"\n{'='*74}\nmcp-scan POC — scanned {len(reports)} MCP servers\n{'='*74}")
    print(f"{'server':<26}{'files':>6}{'crit':>6}{'high':>6}{'med':>6}{'low':>6}  creds")
    print("-"*74)
    for r in sorted(reports, key=lambda r: -sum(SEV[f['severity']] for f in r['findings'])):
        c = defaultdict(int)
        for f in r["findings"]:
            c[f["severity"]] += 1; tot[f["severity"]] += 1; cat[f["category"]] += 1
        print(f"{r['server']:<26}{r['files']:>6}{c['critical']:>6}{c['high']:>6}"
              f"{c['medium']:>6}{c['low']:>6}  {','.join(r['creds'])[:30]}")
    print("-"*74)
    print(f"TOTALS  critical={tot['critical']} high={tot['high']} medium={tot['medium']} low={tot['low']}")
    print(f"by category: {dict(cat)}\n")

    # sample the highest-signal findings
    flat = [f for r in reports for f in ({**x, 'server': r['server']} for x in r['findings'])]
    flat.sort(key=lambda f: -SEV[f["severity"]])
    print("Top findings (highest severity first):")
    for f in flat[:16]:
        print(f"  [{f['severity']:<8}] {f['server']}/{f['file']}:{f['line']} — {f['category']}: {f['message']}")

    json.dump({"servers": reports, "totals": dict(tot)},
              open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "findings.json"), "w"), indent=2)
    print(f"\nfull findings -> findings.json")


if __name__ == "__main__":
    main()
