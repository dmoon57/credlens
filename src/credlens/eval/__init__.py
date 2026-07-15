"""Eval harness — the measuring instrument (wargame Phase 1 spine).

Scores a detector on two ground truths and emits precision/recall + overall FP rate
(JSON + markdown). Two things are measured:

  * Real-server credential precision. Ground truth from corpus/labels.json: the
    reference servers contain ZERO real secret leaks (every credential/misparse
    finding hand-adjudicated false; ADR-0002 inventory excluded). So any credential
    *finding* a detector emits on corpus/servers is a false positive. precision =
    1.0 when it emits none.
  * Mutation recall + negative precision. Ground truth by construction from
    corpus/mutations.json: `bad` instances must be caught on their sink line,
    `good` (hard-negative FP idioms) must not. Recall is reported per split;
    the `holdout` number is the honest one (its classes are never tuned on).

Overall FP rate is reported against the ~78% directional single-study industry
figure — cited as directional, never as our denominator (README methodology).
"""

from __future__ import annotations

import json
from pathlib import Path

from collections import Counter

from credlens.detectors import (
    BaselineDetector,
    CredentialDetector,
    Finding,
    LeastPrivDetector,
)
from credlens.detectors.base import LENS_CREDENTIAL
from credlens.scan import SCAN_SUFFIXES, scan_tree

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "corpus"
SERVERS = CORPUS / "servers"
MUTATIONS = CORPUS / "mutations"
RESULTS = REPO / "eval" / "results.json"
REPORT = REPO / "eval" / "report.md"
FLOOR = REPO / "eval" / "floor.json"


def _run_detector(detector, root: Path) -> list[tuple[str, Finding]]:
    """Scan every source file under root; return (relpath, finding) pairs.

    Thin wrapper over the shared walker (credlens.scan) so eval and the hosted
    scan share one code path. Single-detector call site, so wrap it in a list.
    """
    return scan_tree(root, [detector]).findings


def _credential_findings(pairs):
    return [(rel, f) for rel, f in pairs
            if f.lens == LENS_CREDENTIAL and f.kind == "finding"]


def score_real_servers(detector) -> dict:
    """Ground truth: zero real leaks. Any credential finding is a false positive.

    The synthetic control (`local/…`) is a planted positive control, not a real
    server — it is excluded here and scored via the mutation/label ground truth.
    """
    if not SERVERS.exists():
        return {"available": False}
    pairs = _run_detector(detector, SERVERS)
    pairs = [(rel, f) for rel, f in pairs if not rel.startswith("local/")]
    cred = _credential_findings(pairs)
    fp = len(cred)  # every credential finding here is false (no real leaks)
    tp = 0
    precision = 1.0 if (tp + fp) == 0 else tp / (tp + fp)
    return {
        "available": True,
        "credential_findings": fp,
        "true_positive": tp,
        "false_positive": fp,
        "precision": round(precision, 4),
        "examples": [f"{rel}:{f.line} {f.message}" for rel, f in cred[:8]],
    }


def score_mutations(detector) -> dict:
    if not MUTATIONS.exists():
        return {"available": False}
    manifest = json.loads((CORPUS / "mutations.json").read_text())
    by_id = {i["id"]: i for i in manifest["instances"]}

    caught = {}   # id -> bool (a credential finding landed on the sink line ±1)
    for inst in manifest["instances"]:
        path = MUTATIONS / inst["file"]
        text = path.read_text(errors="replace")
        cred = [f for f in detector.scan_text(inst["file"], text)
                if f.lens == LENS_CREDENTIAL and f.kind == "finding"]
        sink = inst["sink_line"]
        caught[inst["id"]] = any(abs(f.line - sink) <= 1 for f in cred)

    def recall_over(predicate):
        ids = [i for i in by_id.values() if i["label"] == "bad" and predicate(i)]
        if not ids:
            return None
        hit = sum(1 for i in ids if caught[i["id"]])
        return {"caught": hit, "total": len(ids), "recall": round(hit / len(ids), 4)}

    def recall(split):
        return recall_over(lambda i: i["split"] == split)

    # per-class recall (diagnostic)
    classes = {}
    for inst in manifest["instances"]:
        if inst["label"] != "bad":
            continue
        c = classes.setdefault(inst["class"],
                               {"caught": 0, "total": 0, "split": inst["split"],
                                "taint_scope": inst["taint_scope"]})
        c["total"] += 1
        c["caught"] += int(caught[inst["id"]])
    for c in classes.values():
        c["recall"] = round(c["caught"] / c["total"], 4)

    # recall by taint scope — the gated number is intra_file; interprocedural and
    # exfil_v2 are documented v1 known-misses, reported but never gated.
    scopes = sorted({i["taint_scope"] for i in by_id.values() if i["label"] == "bad"})
    by_scope = {
        scope: recall_over(lambda i, s=scope: i["taint_scope"] == s)
        for scope in scopes
    }
    # the headline gate: intra-file recall on the held-out classes (never tuned on)
    intra_holdout = recall_over(
        lambda i: i["taint_scope"] == "intra_file" and i["split"] == "holdout")

    good = [i for i in by_id.values() if i["label"] == "good"]
    flagged_good = sum(1 for i in good if caught[i["id"]])
    caught_bad = sum(1 for i in by_id.values() if i["label"] == "bad" and caught[i["id"]])
    denom = caught_bad + flagged_good
    precision = 1.0 if denom == 0 else round(caught_bad / denom, 4)

    return {
        "available": True,
        "recall": {s: recall(s) for s in ("tune", "holdout", "negative") if recall(s)},
        "recall_by_scope": {k: v for k, v in by_scope.items() if v},
        "recall_intra_file_holdout": intra_holdout,
        "by_class": classes,
        "negatives": {"total": len(good), "false_positives": flagged_good},
        "precision": precision,
    }


def score_inventory() -> dict:
    """Least-privilege permission surface across the real servers (never scored TP/FP).

    Runs the least-priv + credential detectors, tallies inventory by category and by
    how many distinct servers exhibit it — the 'permission surface of the MCP ecosystem'
    data. Asserts these emit zero `kind="finding"` (so precision is unaffected)."""
    if not SERVERS.exists():
        return {"available": False}
    detectors = [LeastPrivDetector(), CredentialDetector()]
    by_category: Counter = Counter()
    servers_with: dict[str, set] = {}
    leaked_findings = 0
    for path in sorted(SERVERS.rglob("*")):
        if path.suffix not in SCAN_SUFFIXES or not path.is_file():
            continue
        rel = path.relative_to(SERVERS).as_posix()
        if rel.startswith("local/"):
            continue
        server = "/".join(rel.split("/")[:2])  # source/server
        text = path.read_text(errors="replace")
        for det in detectors:
            for f in det.scan_text(rel, text):
                if f.kind != "inventory":
                    leaked_findings += 1  # a least-priv/inventory pass must never assert
                    continue
                cat = f.message.split("(")[0].split("—")[0].strip().rstrip(":")
                by_category[cat] += 1
                servers_with.setdefault(cat, set()).add(server)
    return {
        "available": True,
        "leaked_findings": leaked_findings,
        "by_category": {
            cat: {"occurrences": n, "servers": len(servers_with.get(cat, ()))}
            for cat, n in by_category.most_common()
        },
    }


def evaluate(detector) -> dict:
    real = score_real_servers(detector)
    mut = score_mutations(detector)
    inventory = score_inventory()

    # overall FP rate across all asserted credential findings the detector emitted
    fp = 0
    total_findings = 0
    if real.get("available"):
        fp += real["false_positive"]
        total_findings += real["credential_findings"]
    if mut.get("available"):
        fp += mut["negatives"]["false_positives"]
        caught_bad = sum(v["caught"] for v in mut["by_class"].values())
        total_findings += caught_bad + mut["negatives"]["false_positives"]
    fp_rate = round(fp / total_findings, 4) if total_findings else 0.0

    return {
        "detector": detector.name,
        "real_servers": real,
        "mutations": mut,
        "inventory": inventory,
        "overall": {
            "false_positive_rate": fp_rate,
            "industry_baseline_note": "~78% flagged-findings-false is a single 33-server study — directional only, NOT our denominator (see README methodology).",
        },
    }


def render_markdown(results: dict) -> str:
    r, m = results["real_servers"], results["mutations"]
    lines = [f"# credlens eval — detector `{results['detector']}`", ""]
    lines.append("## Real-server credential lens (precision)")
    if r.get("available"):
        lines += [
            f"- credential findings emitted: **{r['credential_findings']}** "
            f"(ground truth: 0 real leaks → all false positives)",
            f"- precision: **{r['precision']}**",
        ]
        if r["examples"]:
            lines.append("- examples:")
            lines += [f"  - `{e}`" for e in r["examples"]]
    else:
        lines.append("- corpus not assembled (`make corpus`)")
    lines += ["", "## Mutation corpus (recall + negative precision)"]
    if m.get("available"):
        ih = m.get("recall_intra_file_holdout")
        if ih:
            lines.append(f"- **intra-file holdout recall (gated): {ih['recall']}** "
                         f"({ih['caught']}/{ih['total']})")
        for scope, rc in m.get("recall_by_scope", {}).items():
            tag = "" if scope == "intra_file" else " — documented v1 known-miss, not gated"
            lines.append(f"- {scope} recall: {rc['recall']} ({rc['caught']}/{rc['total']}){tag}")
        for split, rc in m["recall"].items():
            lines.append(f"- {split} split recall (all scopes): {rc['recall']} "
                         f"({rc['caught']}/{rc['total']})")
        lines.append(f"- negative precision (hard-negatives not flagged): **{m['precision']}** "
                     f"({m['negatives']['false_positives']} of {m['negatives']['total']} FP)")
        lines.append("")
        lines.append("| class | split | scope | recall |")
        lines.append("|---|---|---|---|")
        for c, v in sorted(m["by_class"].items()):
            lines.append(f"| {c} | {v['split']} | {v['taint_scope']} | "
                         f"{v['recall']} ({v['caught']}/{v['total']}) |")
    else:
        lines.append("- mutations not generated (`make mutations`)")
    inv = results.get("inventory", {})
    if inv.get("available"):
        lines += ["", "## Least-privilege inventory (real servers — never scored TP/FP)"]
        lines.append(f"- asserted findings leaked into inventory pass: "
                     f"**{inv['leaked_findings']}** (must be 0)")
        lines.append("")
        lines.append("| category | occurrences | servers |")
        lines.append("|---|---|---|")
        for cat, v in inv["by_category"].items():
            lines.append(f"| {cat} | {v['occurrences']} | {v['servers']} |")
    lines += ["", "## Overall",
              f"- false-positive rate: **{results['overall']['false_positive_rate']}**",
              f"- _{results['overall']['industry_baseline_note']}_", ""]
    return "\n".join(lines)


def _gate(results: dict) -> int:
    if not FLOOR.exists():
        print("no eval/floor.json — nothing to gate against (run `make eval` then record a floor)")
        return 0
    floor = json.loads(FLOOR.read_text())
    eps = 1e-9
    checks = []
    real = results["real_servers"]
    if real.get("available") and "real_server_precision" in floor:
        checks.append(("real_server_precision", real["precision"], floor["real_server_precision"]))
    mut = results["mutations"]
    if mut.get("available"):
        # primary recall gate: intra-file classes on the held-out split (the
        # interprocedural known-miss is reported but never gated)
        if "mutation_recall_intra_file_holdout" in floor and mut.get("recall_intra_file_holdout"):
            checks.append(("mutation_recall_intra_file_holdout",
                           mut["recall_intra_file_holdout"]["recall"],
                           floor["mutation_recall_intra_file_holdout"]))
        elif "mutation_recall_holdout" in floor and "holdout" in mut["recall"]:
            checks.append(("mutation_recall_holdout", mut["recall"]["holdout"]["recall"],
                           floor["mutation_recall_holdout"]))
        if "mutation_precision" in floor:
            checks.append(("mutation_precision", mut["precision"], floor["mutation_precision"]))
    failed = [(k, got, flo) for k, got, flo in checks if got + eps < flo]
    for k, got, flo in checks:
        mark = "FAIL" if (k, got, flo) in failed else "ok"
        print(f"  [{mark}] {k}: {got} (floor {flo})")
    if failed:
        print(f"GATE FAILED: {len(failed)} metric(s) regressed below the release floor.")
        return 1
    print("GATE PASSED.")
    return 0


DETECTORS = {"credential": CredentialDetector, "baseline": BaselineDetector}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Run the credlens eval harness.")
    ap.add_argument("--detector", choices=sorted(DETECTORS), default="credential",
                    help="detector under test (default: credential — the shipping lens)")
    ap.add_argument("--gate", action="store_true", help="exit 1 if a metric is below eval/floor.json")
    ap.add_argument("--record-floor", action="store_true",
                    help="write current metrics as the new eval/floor.json")
    args = ap.parse_args(argv)

    results = evaluate(DETECTORS[args.detector]())
    RESULTS.parent.mkdir(exist_ok=True)
    RESULTS.write_text(json.dumps(results, indent=2) + "\n")
    REPORT.write_text(render_markdown(results))
    print(render_markdown(results))

    if args.record_floor:
        floor = {
            "detector": results["detector"],
            "recorded": "set by --record-floor",
        }
        if results["real_servers"].get("available"):
            floor["real_server_precision"] = results["real_servers"]["precision"]
        mut = results["mutations"]
        if mut.get("available"):
            if mut.get("recall_intra_file_holdout"):
                floor["mutation_recall_intra_file_holdout"] = \
                    mut["recall_intra_file_holdout"]["recall"]
            floor["mutation_precision"] = mut["precision"]
        FLOOR.write_text(json.dumps(floor, indent=2) + "\n")
        print(f"\nrecorded floor → {FLOOR.relative_to(REPO)}: {floor}")

    if args.gate:
        return _gate(results)
    return 0
