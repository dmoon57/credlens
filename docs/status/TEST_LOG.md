---
type: status
title: "credlens — test log"
created_date: 2026-07-14
last_modified: 2026-07-14 18:27 PDT
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
- **2026-07-14 18:02 PDT — Phase 2 credential lens.** `uv run pytest` → 25 passed (adds 11
  credential-fixture tests + generator/harness updates). `uv run ruff check .` → clean.
  - **Credential detector eval:** real-server credential precision **1.0** (0 findings on the
    reference servers — all 3 baseline FPs killed); intra-file holdout recall **0.9167** (33/36);
    intra-file overall 0.8667; negative precision **1.0** (0/36 FP); overall FP rate **0.0**.
    Documented known-misses, reported not gated: outbound `exfil_v2` 0.0, interprocedural 0.0.
  - **Four-FP-class fixtures:** name-not-value ×3, window-overshoot ×2, path-not-secret ×2 → 0
    findings each; aliased-flow → finding at the sink line. Authored in an isolated subagent context.
  - **Gate red-then-green at the new floor:** broke aliasing → holdout recall 0.9167→0.6389, gate
    **exit 1**; revert → **exit 0**.
- **2026-07-14 18:27 PDT — Move 2.3 least-priv inventory.** `uv run pytest` → 31 passed (+6 leastpriv:
  everything-is-inventory, confused-deputy-flagged, own-token-not-passthrough, scope-breadth,
  aggregate-once-per-file, real-servers-zero-findings). `uv run ruff check .` → clean. Credential gate
  unchanged → PASS.
  - **Ecosystem inventory (real servers, `eval/report.md`):** 0 asserted findings leaked; surface =
    secret-in-outbound 14/2 servers · fs-write 8/3 · fs-delete 7/2 · outbound-network 6/6 · http-server
    4/1 · network-transport 2/1 · subprocess 1/1 · oauth-scope 1/1 (gdrive, narrow). The blog-#2 seed.
