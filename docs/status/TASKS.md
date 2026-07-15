---
type: status
title: "credlens — tasks"
created_date: 2026-07-14
last_modified: 2026-07-14 20:20 PDT
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
- [x] 3.1a Threat model + spec (before building) — [specs/hosted-scan.md](../specs/hosted-scan.md)
- [x] 3.1b Codex gate round 1: REVISE, 21 findings, all accepted (1 negotiated) → spec v2
  (see [REVIEW_NOTES.md](REVIEW_NOTES.md))
- [x] 3.1c Codex round 2: REVISE (12 resolved · 8 partial · 8 new · negotiated fix accepted
  conditionally) → spec v3 + [ADR-0003](../adr/0003-hosted-output-publication-semantics.md) +
  plan §Phase 3 amendment
- [ ] 3.1d Codex round 3 convergence pass on spec v3 → APPROVE before build code
- [ ] 3.2a Runtime probe, Deployment-Protection-enabled: wheel imports, worker kill semantics,
  /tmp, fluid:false, maxDuration, T11 upstream matrix. Kill criterion: probe fails ⇒ fallback
- [ ] 3.2b Scan core, local: shared `scan.py` walker factor-out + `hosted/` fetch/streamed-extract/
  limits/worker, TDD against adversarial fixtures — no network in tests
- [ ] 3.3 Web surface, local: handler contract + static pages/assets + atomic quotas +
  XSS/CSP/MIME tests; `vercel dev` smoke
- [ ] 3.4 Gated deploy: protected preview (asserted) → deployed-surface tests → full `/cso` →
  operator approval → WAF + spend caps → public alias + README link
- [ ] Fallback if any gate fails: static demo of pre-scanned reports (always green)

## Phase 4 — Ecosystem scan + write-ups
- [ ] Launch post draft (no build dependency — any day)
- [ ] Server list: top-N, intersection-of-≥2-sources rule, published criteria
- [ ] Disclosure protocol executed before publication
- [ ] Data-story post draft
