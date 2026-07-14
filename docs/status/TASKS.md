---
type: status
title: "credlens — tasks"
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
---

# Tasks

## Phase 0 — Scaffold ✅
- [x] Name + collision check (npm/PyPI/GitHub + incumbents)
- [x] Public repo `dmoon57/credlens`
- [x] Gitleaks pre-commit + CI secrets workflow, before any other code
- [x] uv + Python 3.12 + tree-sitter (ts/js/py) + pytest + ruff
- [x] CI: lint · test · eval-gate slot · eval-integrity guard
- [x] OKF docs tree (plan, ADR-0001/0002, status, research/POC)

## Phase 1 — Evals harness
- [ ] `corpus/manifest.json` (pinned SHAs) + fetch script (`make corpus`)
- [ ] Mirror corpus tarballs to a release asset (archived repos rot)
- [ ] Hand-adjudicate POC's 60 findings → `corpus/labels.json` (before detector work)
- [ ] Mutation corpus: ≥100 planted instances, ≥8 classes, class-level holdout
- [ ] Harness: per-lens precision/recall + FP rate (JSON + md) · `make eval` / `make eval-ci`
- [ ] CI gate demonstrated red-then-green on a planted regression

## Phase 2 — Credential / least-priv lens
- [ ] Four named FP classes as fixtures (before taint work)
- [ ] Intra-file taint on tree-sitter scopes (2-day box; then ADR-0001 fork decision)
- [ ] Source/sink model with confidence tiers
- [ ] Least-priv inventory checks
- [ ] Targets: precision ≥0.90 holdout · mutation recall ≥0.80 intra-file · FP rate <20%

## Phase 3 — Hosted scan-by-URL
- [ ] Threat model (before building) — see plan §Phase 3
- [ ] Deploy behind security review gate (fallback: static demo)

## Phase 4 — Ecosystem scan + write-ups
- [ ] Launch post draft (no build dependency — any day)
- [ ] Server list: top-N, intersection-of-≥2-sources rule, published criteria
- [ ] Disclosure protocol executed before publication
- [ ] Data-story post draft
