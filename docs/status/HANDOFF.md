---
type: status
title: "credlens — handoff"
created_date: 2026-07-14
last_modified: 2026-07-14 17:30 PDT
---

# Handoff

**Goal:** v1 core by 2026-07-20 (evals harness + credential lens beating the FP target on holdout +
launch post drafted); hosted scan-by-URL + ecosystem scan + data-story draft by 2026-07-27.
Full plan: [../plan/plan.md](../plan/plan.md).

**Phase:** 1 (evals harness — the spine) — **complete** 2026-07-14. Phase 0 scaffold complete same day.

**Done (Phase 1):**
- **Move 1.1** — `corpus/manifest.json` pins the 22-server corpus (servers @ d31124c, servers-archived
  @ 9be4674, + in-repo synthetic control); `make corpus` assembles it and verifies a tree hash;
  release `corpus-v1` mirrors the source tarballs; the mirror-only fetch path is verified.
- **Move 1.2** — all 60 POC findings hand-adjudicated into `corpus/labels.json` (8 true-positive —
  all planted in the synthetic control; 7 false-positive — name-not-value ×2, path-not-secret,
  window-overshoot, heuristic-length, misparse ×2; 45 inventory per ADR-0002), anchors re-checked
  against the pinned corpus. Committed before any detector code (eval-integrity invariant).
- **Move 1.3** — `scripts/plant_mutations.py` generates 198 labeled-by-construction instances (162
  bad / 36 hard-negative) across 11 classes with class-level holdout; deterministic, `--check`
  asserts the tree hash.
- **Move 1.4** — the eval harness (`python -m credlens.eval`) scores a detector for real-server
  credential precision + per-split mutation recall + negative precision + overall FP rate (JSON +
  `eval/report.md`). The POC heuristic is ported as the measured **baseline** and reproduces the
  spike's story as numbers: **real-server precision 0.0** (3 name/window FPs), **cross-function-hop
  recall 0.0** (documented intra-file-taint miss), hardcoded-token 1.0. Floor recorded in
  `eval/floor.json`; the CI `eval-gate` job runs `make eval-ci`; gate demonstrated **red-then-green**
  on a planted regression (holdout recall 0.5185→0.1852 → exit 1; revert → exit 0).

**Baseline numbers (eval/floor.json):** real-server credential precision 0.0 · holdout recall 0.5185
· negative precision 0.9029 · overall FP rate 0.1226. These are the floor Phase 2 must beat.

**Exact next step:** Phase 2 — the credential/least-privilege lens (ADR-0001 tree-sitter intra-file
taint). Kill the four named FP classes first, as fixtures, before the taint pass; then source/sink
model; target credential-lens precision ≥0.90 on holdout, mutation recall ≥0.80 intra-file, overall
FP <20%. Do **not** harden `detectors/baseline.py` — the lens is a new module measured against it.

**Verification state:** `uv run pytest` → 14 passed · `uv run ruff check .` → clean · `make eval-ci`
gate → PASS · red-then-green regression demo → exit 1 then 0.
