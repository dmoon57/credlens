---
type: checkpoint
project: credlens
status: in-progress
branch: main
timestamp: 2026-07-14T19:03:34-07:00
files_modified: []
last_modified: 2026-07-14 19:03 PDT
---
## Working on: credlens — Phase 2 complete, next Phase 3 or launch post

### Summary
credlens = the FDE-campaign flagship: a precision-first, eval-backed MCP-server security auditor
(credential/least-priv lens). Public repo `dmoon57/credlens`, executed from the vault-side wargame
`~/BENDER/new_beginnings/goodbye_walmart/flagship-wargame.md`. **Phases 0, 1, and 2 are all
complete (2026-07-14), CI green on `b388621`, working tree clean, nothing uncommitted.**

- **Phase 0** — public repo, gitleaks-first scaffold, uv + tree-sitter, OKF docs.
- **Phase 1** — evals harness (the spine): SHA-pinned 22-server corpus (release `corpus-v1`
  mirror), 60 POC findings hand-adjudicated (`corpus/labels.json`: 8 TP / 7 FP / 45 inventory),
  198-instance mutation corpus (`scripts/plant_mutations.py`), eval harness + CI regression gate.
- **Phase 2** — the headline. Credential lens (`detectors/credential.py`, tree-sitter intra-file
  taint) hits ALL targets: **real-server precision 1.0, intra-file holdout recall 0.9167, FP 0.0**.
  Least-priv inventory (`detectors/leastpriv.py`) adds oauth-scope/transport/capability/
  confused-deputy — all `kind=inventory`, 0 findings on real servers. 31 tests pass.

Verification: `uv run pytest` → 31 passed · `uv run ruff check .` → clean · `make eval-ci` gate →
PASS · clean-state `make corpus && make mutations && make eval-ci` reproduces the numbers.

### Decisions Made
- **Outbound = inventory, not finding (load-bearing).** A secret in an outbound request is most
  often legitimate auth (a token to its own API — the gitlab/github reference servers). Flagging it
  destroyed precision (14 FPs). Telling auth from exfiltration needs destination-taint
  (caller-controlled host) — deferred to v2. The `secret-in-url/header/body` mutation classes are
  tagged `exfil_v2`, reported-not-gated. This is what keeps real-server precision at 1.0. (DECISIONS.md)
- **Taint on value BINDINGS, never on the env-var name token.** Single idea that kills all three
  real-world FP classes (name-not-value, window-overshoot, path-not-secret) at once.
- **v1 taint is intra-file, local-binding only.** Interprocedural / instance-field (`this.secret`)
  flows are documented known-misses (`cross-function-hop` class, `aliased_class_method` fixture),
  reported not gated.
- **ADR-0001 tree-sitter path held** — the semgrep fork trigger did not fire; targets cleared well
  inside the 2-day box.
- **Confused-deputy vs own-token:** the passthrough check flags only a CALLER-controlled auth value;
  a server's own configured token (github/gitlab) is correctly NOT flagged.
- **Two subagent fixtures reconciled** to the settled model (token→own-API = inventory; field
  cross-method = v1 miss) — the legitimate "spec changed" exception, documented in `expected.json`.
- Eval-integrity: corpus labels and detector code never change in one commit (CI guard on
  `corpus/labels*` + `src/credlens/detectors/`). Baseline detector kept in-tree for comparison.

### Remaining Work
Phase 2 done → pick the next move (both ready, no blockers):
1. **Phase 3 — hosted scan-by-URL.** Threat-model the tool's OWN surface FIRST (SSRF via clone URL,
   zip-bomb/monster repos, symlink escape, parser DoS, **stored XSS in findings pages**, abuse).
   Parse-only (never execute target code), GitHub-URL allowlist. Ship behind a **/cso security-review
   gate** before public (fallback: static demo of pre-scanned reports). Default target Vercel. This
   is the heavier lift (hostile-input web surface + mandatory gate). See `docs/plan/plan.md` §Phase 3.
2. **Launch post #1** (the "why": threat model + the skipped credential dimension) — no build
   dependency, draftable any day from the spec + research. Pure writing.
3. **Optional recall lift** (any time): `DATABASE_URL`-style embedded-credential URLs (the 1/6
   secret name the lens skips); a scoped exfil-to-caller-controlled-host check (converts `exfil_v2`
   to findings — do it precisely or leave documented).
4. **Phase 4** (later): ecosystem scan (N≈75, intersection of ≥2 registries) + disclosure protocol
   BEFORE the scan + data-story post #2. The least-priv inventory summary in `eval/report.md` is
   already the blog-#2 data seed.

### Notes
- **Do NOT harden `detectors/baseline.py`** — it is the measured baseline (the ported POC heuristic);
  new detection goes in a new module.
- **Campaign constraint:** flagship is an AMPLIFIER, applications stay primary. Abort tripwire —
  flagship displacing applications >2 consecutive days = freeze at last green milestone. The repo is
  presentable at every milestone boundary by design.
- **gh needs the keyring credential** for writes: run repo/release mutations as
  `env -u GH_TOKEN -u GITHUB_TOKEN gh …` (the ambient wrapper token is a fine-grained PAT that can't
  createRepository / read check runs).
- **Fixture secrets are double-defanged** (fake to a human AND structurally invalid so GitHub push
  protection + gitleaks pass); fixture/generator paths are allowlisted in `.gitleaks.toml`. Any
  `FAKE`/`EXAMPLE`-marked line is allowlisted.
- Generated dirs (`corpus/servers/`, `corpus/mutations/`) are gitignored — regenerate with
  `make corpus && make mutations`. `mutations.json` (the manifest) IS committed.
- Vault sync done through 2026-07-14 18:28: `projects/credlens/index.md`, projects registry,
  DASHBOARD credlens row + refresh log, wargame Phase 2 ✅ EXECUTED.
- Repo state: branch `main`, HEAD `b388621`, clean, pushed, both CI workflows (ci + secrets) green.
