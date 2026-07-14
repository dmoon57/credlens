---
type: status
title: "credlens — handoff"
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
---

# Handoff

**Goal:** v1 core by 2026-07-20 (evals harness + credential lens beating the FP target on holdout +
launch post drafted); hosted scan-by-URL + ecosystem scan + data-story draft by 2026-07-27.
Full plan: [../plan/plan.md](../plan/plan.md).

**Phase:** 0 (scaffold) — **complete** 2026-07-14.

**Done:** public repo created; gitleaks pre-commit + CI secrets workflow (wired before any other
code, verified live on the root commit); Python 3.12 + uv scaffold; tree-sitter spine with ts/js/py
grammars (smoke-tested: all three load and parse); pytest + ruff green; CI with lint, test,
eval-gate slot, and the eval-integrity guard; OKF docs tree with plan + 2 ADRs.

**Exact next step:** Phase 1, step 1 — `corpus/manifest.json` with pinned commit SHAs for the
22-server corpus + a fetch script (`make corpus`), then mirror tarballs to a release asset the same
day. Then hand-adjudicate the POC's 60 findings
([../research/poc/findings.json](../research/poc/findings.json)) into `corpus/labels.json` **before
any detector work**.

**Verification state:** `uv run pytest` → 2 passed · `uv run ruff check .` → clean · gitleaks hook
ran on root commit → passed.
