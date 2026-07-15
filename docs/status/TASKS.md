---
type: status
title: "credlens — tasks"
created_date: 2026-07-14
last_modified: 2026-07-14 18:27 PDT
---

# Tasks

## Phase 0 — Scaffold ✅
- [x] Name + collision check (npm/PyPI/GitHub + incumbents)
- [x] Public repo `dmoon57/credlens`
- [x] Gitleaks pre-commit + CI secrets workflow, before any other code
- [x] uv + Python 3.12 + tree-sitter (ts/js/py) + pytest + ruff
- [x] CI: lint · test · eval-gate slot · eval-integrity guard
- [x] OKF docs tree (plan, ADR-0001/0002, status, research/POC)

## Phase 1 — Evals harness ✅
- [x] `corpus/manifest.json` (pinned SHAs) + fetch script (`make corpus`)
- [x] Mirror corpus tarballs to release `corpus-v1` (archived repos rot); mirror-only fetch verified
- [x] Hand-adjudicate POC's 60 findings → `corpus/labels.json` (before detector work) — 8 TP / 7 FP / 45 inventory
- [x] Mutation corpus: 198 instances, 11 classes, class-level holdout (`make mutations`, `--check`)
- [x] Harness: per-lens precision/recall + FP rate (JSON + `eval/report.md`) · `make eval` / `make eval-ci`
- [x] Baseline (ported POC) measured; floor recorded (`eval/floor.json`)
- [x] CI gate demonstrated red-then-green on a planted regression (exit 1 → exit 0)

## Phase 2 — Credential / least-priv lens
- [x] Four named FP classes as fixtures (before taint work) — 11 tests, all green
- [x] Intra-file taint on tree-sitter (ts/js) — bindings not name-tokens; aliasing + destructure +
  template/object/JSON.stringify propagation. ADR-0001 tree-sitter path held (no semgrep fork needed)
- [x] Source/sink model with confidence tiers (log/file/subprocess = finding; outbound = inventory)
- [x] Targets MET: real-server precision **1.0** · intra-file holdout recall **0.9167** · FP **0.0**
- [x] Move 2.3 — least-priv inventory checks (`detectors/leastpriv.py`): oauth-scope breadth,
  network-exposed transports, fs-write/delete/exec/eval/network capability, token-passthrough
  (caller-controlled vs own-token). All `kind=inventory`; 0 findings on real servers; ecosystem
  inventory summary in `eval/report.md`. 6 tests.
- [ ] Optional recall lift: embedded-cred URLs (DATABASE_URL class) · scoped exfil-host check

## Phase 3 — Hosted scan-by-URL
- [ ] Threat model (before building) — see plan §Phase 3
- [ ] Deploy behind security review gate (fallback: static demo)

## Phase 4 — Ecosystem scan + write-ups
- [ ] Launch post draft (no build dependency — any day)
- [ ] Server list: top-N, intersection-of-≥2-sources rule, published criteria
- [ ] Disclosure protocol executed before publication
- [ ] Data-story post draft
