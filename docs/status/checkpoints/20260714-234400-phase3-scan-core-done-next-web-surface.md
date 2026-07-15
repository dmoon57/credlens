---
type: checkpoint
project: credlens
status: in-progress
branch: main
timestamp: 2026-07-14T23:44:00-07:00
files_modified: []
last_modified: 2026-07-14 23:44 PDT
---
## Working on: credlens Phase 3 hosted scan-by-URL — 3.1 gate + 3.2a probe + 3.2b scan core all DONE, next 3.3 web surface

### Summary
credlens = the FDE-campaign flagship (precision-first eval-backed MCP-server security auditor).
Phase 3 = a hosted scan-by-URL service. **Milestones 3.1, 3.2a, 3.2b are complete; CI green;
HEAD clean.** The whole local scan pipeline (fetch→extract→scan→frame→validate→redact) is built
and adversarially tested (97 tests). Next is 3.3 (the web handler + static pages + Upstash).

- **3.1 (spec + adversarial gate) — DONE.** Threat-model-first spec `docs/specs/hosted-scan.md`
  converged through THREE codex rounds (REVISE 21 → REVISE 9 partial+8 new → APPROVE-WITH-CHANGES,
  all folded, now v3.1). ADR-0003 settles publication semantics (ephemeral on-demand = tool output;
  persistent/GET-servable = publication under invariant 5); plan §Phase 3 amended off the
  "shareable findings page" model. Closed response/frame contract: `docs/specs/hosted-scan-schema.json`.
- **3.2a (runtime probe) — PASSED.** Protected Vercel preview (`moonman/credlens`) proved on the real
  runtime: tree-sitter wheels install, worker process-group kill (grandchildren die), /tmp, T11
  codeload matrix. Probe code: `api/probe.py`. Owed: disable Fluid Compute at 3.4 (defaults true, not
  API-settable on this CLI; code-level per-request detector instances enforce isolation regardless).
- **3.2b (scan core) — DONE.** `src/credlens/scan.py` (shared network-free walker; eval repointed,
  pure refactor, numbers identical) + `src/credlens/hosted/`: fetch, extract, limits, frame, validate,
  worker, runner, redact. 38 hosted tests incl. every adversarial tarball fixture + worker-isolation.

### Decisions Made
- Publication semantics = ADR-0003 (ephemeral results; share URL is a click-to-run pointer).
- Worker isolation = env-scrubbed subprocess in its own process group + ACL-scoped Upstash token
  (ACL is a public-launch precondition; default token = preview-only). Parent-boundary framing +
  hand-rolled closed-schema validation (zero new runtime deps — no jsonschema).
- Fetch = tarball-not-clone (pinned codeload host, redirects refused, parse-don't-fetch identifier).
- Fixture secrets assembled from concatenated parts so no complete secret literal in source (CI
  gitleaks scans git-history mode and flagged a FAKE-marked literal; concatenation is scanner-proof).

### Remaining Work (ordered)
1. **3.3 web surface (mostly local):** `api/scan.py` stdlib handler — POST-only admission contract,
   one atomic Lua admission transition (leader/follower/busy/rate_limited), cache lookup +
   revalidation state machine, then fetch→runner→redact→respond per the status→error matrix. Static
   `web/index.html`, `web/scan.html`, external `scan.js`/`scan.css` (CSP header via vercel.json,
   textContent-only render, bidi/control escaping). Tests: quota/lease atomicity,
   cached-hit-consumes-request-budget, MIME/rewrite, XSS/CSP render DOM-asserted; `vercel dev` smoke.
   **Operator touchpoint:** provision Upstash Redis + ACL-scoped token (`credlens:` prefix) — bring
   the exact `upstash` CLI commands to Daniel.
2. **3.4 gated deploy:** protected preview (asserted) → deployed-surface tests → **full /cso** →
   **operator approval** → WAF rule + $20/mo spend cap → disable Fluid Compute → public alias + README.
3. Fallback if any gate fails: static demo of pre-scanned reports (always green).

### Notes
- Repo HEAD clean, CI (ci + secrets) green. Checkpoint pool: `~/src/credlens/docs/status/checkpoints/`.
- `gh` writes need `env -u GH_TOKEN -u GITHUB_TOKEN gh …` (ambient PAT can't do repo mutations).
- Do NOT harden `detectors/baseline.py` (measured baseline). Generated corpus dirs are gitignored.
- Vercel: project `moonman/credlens` linked (.vercel/ gitignored), preview protected, PROBE_TOKEN env
  set (preview+prod), probe token at `~/.config/vercel/credlens-probe-token`.
- Campaign constraint: flagship is an amplifier; applications stay primary (tripwire >2 days).
