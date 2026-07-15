---
type: status
title: "credlens — handoff"
created_date: 2026-07-14
last_modified: 2026-07-14 18:02 PDT
---

# Handoff

**Goal:** v1 core by 2026-07-20 (evals harness + credential lens beating the FP target on holdout +
launch post drafted); hosted scan-by-URL + ecosystem scan + data-story draft by 2026-07-27.
Full plan: [../plan/plan.md](../plan/plan.md).

**Phase:** 2 (credential/least-priv lens) — **core complete** 2026-07-14. Phases 0 + 1 complete same day.

**Done (Phase 2 — credential lens):**
- Spec: [../specs/credential-lens.md](../specs/credential-lens.md) (taint model, the 4 FP classes,
  confidence tiers, targets).
- **Move 2.1** — the four named FP classes killed as fixtures first (authored in an isolated
  context, `tests/fixtures/credential/` + `expected.json`, 11 tests): name-not-value ×3,
  window-overshoot ×2, path-not-secret ×2 all emit **zero** findings; aliased-flow fires correctly.
- **Move 2.2** — `detectors/credential.py`: tree-sitter (ts/js) intra-file def-use taint. Taint on
  value **bindings**, never on name tokens (kills name-not-value); `return` is not a sink (kills
  window-overshoot); `*_PATH` env vars aren't secret sources (kills path-not-secret); aliasing +
  destructure-rename + template/object/`JSON.stringify` propagation all tracked.
- **Sink model** (ADR-0002): log / file-write-content / subprocess = **finding**; outbound request =
  **inventory** (a token to its own API is legitimate auth; auth-vs-exfil needs destination-taint,
  deferred to v2). This is the decision that keeps real-server precision at 1.0.

**Results vs targets (all met):** real-server credential precision **1.0** (≥0.90 target — zero
findings on the reference servers) · intra-file holdout recall **0.9167** (≥0.80) · negative
precision **1.0** · overall FP rate **0.0** (<0.20). Documented known-misses, reported not gated:
outbound (`exfil_v2`) and interprocedural/field (`cross-function-hop`) recall 0.0. Floor re-recorded
at these numbers; gate re-proven red-then-green (holdout recall 0.9167→0.6389 → exit 1).

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

**Current floor (eval/floor.json, credential detector):** real-server precision 1.0 · intra-file
holdout recall 0.9167 · negative precision 1.0. The baseline detector stays in-tree for comparison
(`--detector baseline`).

**Exact next step (Phase 2 remainder → Phase 3):**
- **Move 2.3** — least-privilege *inventory* checks (over-broad fs roots, wildcard OAuth scopes,
  missing/optional auth on transports, token-passthrough/confused-deputy). Emit as `inventory`;
  not precision-gated. Optional recall lift: `DATABASE_URL`-style embedded-credential URLs (the 1/6
  secret name the lens currently skips) and a scoped exfil-to-caller-controlled-host check (would
  convert the `exfil_v2` known-miss into findings — do it precisely or leave documented).
- **Phase 3** — hosted scan-by-URL (threat-model first, security-review gate before public).
- Do **not** harden `detectors/baseline.py`; it is the measured baseline. New detection = new module.

**Verification state:** `uv run pytest` → 25 passed · `uv run ruff check .` → clean · `make eval-ci`
gate (credential) → PASS · red-then-green regression demo → exit 1 then 0.
