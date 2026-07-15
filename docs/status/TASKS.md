---
type: status
title: "credlens — tasks"
created_date: 2026-07-14
last_modified: 2026-07-14 23:43 PDT
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
- [x] 3.1d Codex round 3: **APPROVE-WITH-CHANGES** — 7 should-fix + 2 nits folded as spec v3.1;
  **3.1 gate CLOSED** (21 → 9+8 → 0 blocking across three rounds)
- [x] 3.2a Runtime probe — **PASSED 2026-07-14 23:10** (`moonman/credlens`, protected preview
  `credlens-rheukmtlq`; unauthenticated denial asserted: 302→SSO). Authenticated report (iad1,
  Python 3.12.13, x86_64, /tmp 512 MB): wheels install + all 3 grammars parse · **worker
  group-kill: rc=-9, zero group survivors, own session** · /tmp 1 MiB roundtrip + cleanup ·
  T11 codeload matrix (normal 200+gzip · nonexistent 404 · **rename transparent-200** = documented
  residual · huge 200). Provenance: `scratchpad/probe-3.2a-report.json`.
- [ ] **3.2a owed deploy-gate action:** project defaults `fluid: true`; not settable via v9 API on
  the current CLI → disable Fluid Compute at 3.4 (dashboard toggle / newer CLI). Code-level
  per-request detector instances are the enforced guarantee; no public ship until fluid is off.
- [x] 3.2b Scan core, local — **DONE 2026-07-14 23:40** (97 tests green, CI green). Shared
  `scan.py` walker factor-out (eval pure-refactor, numbers identical) + `hosted/`: `extract`
  (streamed metered gzip→tar, dirs+regular-files only, links/devices/traversal rejected),
  `frame`+`validate` (length-prefixed 2 MiB frame, hand-rolled closed-schema validator drift-guarded
  vs `hosted-scan-schema.json`), `worker`+`runner` (scrubbed subprocess in its own process group,
  per-file stall + total deadline, SIGKILL the group incl. grandchildren, ScanFailed/ScanRejected),
  `redact` (token-shape + high-entropy scrub of repo-derived strings, service metadata exempt,
  combined findings+inventory caps), `fetch` (parse-don't-fetch identifier, pinned-host codeload,
  redirects refused, compressed cap). 38 hosted tests incl. all adversarial fixtures.
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
