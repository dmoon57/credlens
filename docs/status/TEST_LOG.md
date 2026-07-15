---
type: status
title: "credlens — test log"
created_date: 2026-07-14
last_modified: 2026-07-14 17:30 PDT
---

# Test log

- **2026-07-14 15:09 PDT — Phase 0 scaffold.** `uv run pytest` → 2 passed (version; all three
  tree-sitter grammars load and parse). `uv run ruff check .` → clean. gitleaks pre-commit hook
  executed and passed on the root commit.
- **2026-07-14 17:30 PDT — Phase 1 evals harness.** `uv run pytest` → 14 passed (labels, mutations,
  eval gate logic, baseline-reproduces-POC). `uv run ruff check .` → clean. `make corpus` assembles
  22 servers, tree hash verified; mirror-only fetch verified against release `corpus-v1`.
  `make mutations` → 198 instances, `--check` hash stable.
  - **Baseline eval:** real-server credential precision **0.0** (3 FPs: brave-search, gitlab,
    google-maps — name-not-value/window-overshoot, reproducing the POC); mutation recall tune 0.6019
    / holdout 0.5185; negative precision 0.9029; overall FP rate 0.1226. Recorded as `eval/floor.json`.
  - **Regression gate red-then-green:** planted regression (disabled hardcoded-token detection) →
    holdout recall 0.5185→0.1852, `--gate` **exit 1** with `[FAIL]` lines; revert → `--gate` **exit
    0** `GATE PASSED`. Exit codes confirmed directly (not via a masking pipe).
