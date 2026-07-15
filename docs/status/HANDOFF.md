---
type: status
title: "credlens — handoff"
created_date: 2026-07-14
last_modified: 2026-07-14 23:43 PDT
---

# Handoff

**Goal:** v1 core by 2026-07-20 (evals harness + credential lens beating the FP target on holdout +
launch post drafted); hosted scan-by-URL + ecosystem scan + data-story draft by 2026-07-27.
Full plan: [../plan/plan.md](../plan/plan.md).

**Phase:** 3 (hosted scan-by-URL) — **3.1 (spec+gate), 3.2a (runtime probe), and 3.2b (scan core)
all COMPLETE** 2026-07-14 evening. Phases 0 + 1 + 2 completed earlier the same day.

**3.2b scan core (DONE, 97 tests green, CI green):** the whole local pipeline
fetch→extract→scan→frame→validate→redact is built and adversarially tested. Modules in
`src/credlens/hosted/`: `fetch` (parse-don't-fetch identifier + pinned codeload, redirects
refused), `extract` (streamed metered gzip→tar; only dirs+regular files; links/devices/traversal/
bombs rejected), `frame`+`validate` (2 MiB length-prefixed frame + hand-rolled closed-schema
validator, drift-guarded vs `docs/specs/hosted-scan-schema.json`), `worker`+`runner` (scrubbed
subprocess in its own process group; per-file stall + total deadline; SIGKILL the whole group incl.
grandchildren; ScanFailed vs ScanRejected), `redact` (token-shape + high-entropy scrub of every
repo-derived string, service metadata exempt, combined caps). `src/credlens/scan.py` is the shared
network-free walker (eval repointed to it — pure refactor, eval numbers identical).

**3.2a probe result (PASSED):** protected preview deploy proved, on the real Vercel runtime (iad1,
Python 3.12.13, x86_64, /tmp 512 MB): tree-sitter wheels install + all 3 grammars parse · worker
process-group kill takes the whole tree (rc=-9, zero survivors) · /tmp roundtrip+cleanup · T11
codeload matrix. **One owed deploy-gate action:** project defaults `fluid: true`, not API-settable
on the current CLI → disable at 3.4 (dashboard/newer CLI); the code-level per-request detector
guarantee is what actually enforces isolation.

**Done (Phase 3 · 3.1):**
- Threat-model-first spec: [../specs/hosted-scan.md](../specs/hosted-scan.md) — 13-row threat
  table, tarball-not-clone pinned-host fetch, env-scrubbed killable worker subprocess,
  parent-boundary framing/validation, atomic Lua admission, ephemeral result policy, enforced
  Deployment Protection, stdlib-only web layer, zero new runtime deps.
- **Codex gate converged in 3 rounds** (REVISE 21 → REVISE 9 partial + 8 new → APPROVE-WITH-CHANGES,
  all folded as v3.1). Full history: [REVIEW_NOTES.md](REVIEW_NOTES.md).
- [ADR-0003](../adr/0003-hosted-output-publication-semantics.md): ephemeral on-demand output =
  tool output; persistent/GET-servable = publication under invariant 5. Plan §Phase 3 amended.
- Feasibility de-risked early: all four tree-sitter packages resolve as manylinux/abi3 x86_64
  wheels for CPython 3.12 (~2.4 MB).

**Exact next step (3.3 — web surface, mostly local):** build `api/scan.py` (the stdlib handler:
POST-only admission contract, one atomic Lua admission transition → leader/follower/busy/
rate_limited, cache lookup + revalidation state machine, then fetch→runner→redact→respond) + the
static pages/assets (`web/index.html`, `web/scan.html`, external `scan.js`/`scan.css` — CSP header
via `vercel.json`, textContent-only render, bidi/control escaping) + the status→error matrix and
response schemas from the spec. Tests: quota/lease atomicity, cached-hit-consumes-request-budget,
MIME/rewrite, XSS/CSP render (DOM-asserted). **One operator touchpoint mid-3.3:** provision Upstash
Redis + the ACL-scoped token (`credlens:` prefix) — I'll bring the exact `upstash` CLI commands;
ACL is a public-launch precondition (DECISIONS.md), default token = preview-only. Then 3.4 (protected
preview → deployed-surface tests → full `/cso` → operator approval → WAF+spend → public).

**Owed 3.4 config:** disable Fluid Compute (project defaults `fluid:true`, not API-settable on the
current CLI — dashboard/newer CLI); code-level per-request detector instances already enforce the
isolation the toggle backstops. The probe project `moonman/credlens` is linked and protected.

---

**Phase 2 record (COMPLETE 2026-07-14, Moves 2.1–2.3):**

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

- **Move 2.3** — `detectors/leastpriv.py`: least-privilege **inventory** (ADR-0002, never scored
  TP/FP): oauth-scope breadth, network-exposed transports (SSE/HTTP), fs-write/delete/exec/eval/
  network capability, and token-passthrough (distinguishes a **caller-controlled** Authorization
  value = confused-deputy from a server sending its **own** configured token — github/gitlab are NOT
  flagged). Emits **0 findings** on real servers (precision untouched). The harness now prints an
  **ecosystem permission-surface summary** (`eval/report.md`) — the blog-#2 data seed.

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

**Exact next step (Phase 2 done → Phase 3):**
- **Phase 3 — hosted scan-by-URL.** Threat-model the tool's own surface FIRST (SSRF via clone URL,
  zip-bomb/monster repos, symlink escape, parser DoS, **stored XSS in findings pages**, abuse) — see
  [../plan/plan.md](../plan/plan.md) §Phase 3. Parse-only (never execute target code); GitHub-URL
  allowlist. Ship behind a **security-review gate** before public (fallback: static demo of
  pre-scanned reports).
- **Optional recall lift** (any time, no build dep): `DATABASE_URL`-style embedded-credential URLs
  (the 1/6 secret name the lens skips) · a scoped exfil-to-caller-controlled-host check (would
  convert the `exfil_v2` known-miss into findings — do it precisely or leave documented).
- **Launch post #1** ("why": threat model + the skipped credential dimension) — no build dependency,
  draftable any day from the spec + research.
- Do **not** harden `detectors/baseline.py`; it is the measured baseline. New detection = new module.

**Verification state:** `uv run pytest` → 31 passed · `uv run ruff check .` → clean · `make eval-ci`
gate (credential) → PASS · red-then-green regression demo → exit 1 then 0.
