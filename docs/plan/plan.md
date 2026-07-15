---
type: plan
title: "credlens v1 — evals-first build plan"
status: active
created_date: 2026-07-14
last_modified: 2026-07-14 20:20 PDT
tags: [mcp, security, evals, static-analysis]
---

# credlens v1 — evals-first build plan

**Goal:** by **2026-07-20**: v1 core — a working **evals harness** emitting precision/recall + a
**credential/least-privilege lens** beating the false-positive target on a held-out corpus — and the
launch post drafted. By **2026-07-27**: hosted **scan-by-URL** deployed (post security review), the
**ecosystem scan** run with the disclosure protocol executed, and the data-story post drafted.

The audience is security-literate; credibility errors (false positives, hype, disclosure missteps)
cost more than missing features. Under-claim, over-prove.

Priority stack and binding invariants live in [CLAUDE.md](../../CLAUDE.md) — when cutting, cut from
the bottom of the stack.

## Phase 0 — Scaffold ✅ (2026-07-14)

Public repo, gitleaks wired before any other code, Python 3.12 + `uv`, tree-sitter parsing spine
(typescript/javascript/python grammars), pytest, CI with lint + tests + eval-gate slot +
eval-integrity guard.

## Phase 1 — Evals harness FIRST (the spine)

Build the measuring instrument before hardening detectors — it is the only defense against
self-deception.

1. **Corpus manifest, pinned.** The 22-server POC corpus (21 real reference servers from
   `modelcontextprotocol/servers` + `servers-archived`, + 1 synthetic control) via
   `corpus/manifest.json` of pinned commit SHAs + a fetch script. `make corpus` reproduces a
   byte-identical tree on any machine. Archived repos rot — mirror tarballs to a release asset the
   same day the manifest is written; the manifest records both SHA and mirror URL.
2. **Hand-adjudicated labels.** The POC's 60 findings adjudicated into `corpus/labels.json` with
   reason codes, *before* any detector work (labels created by someone not yet invested in the
   detector's answer). Ambiguity is resolved by the finding-vs-inventory distinction
   ([ADR-0002](../adr/0002-finding-vs-inventory.md)).
3. **Mutation corpus.** A script plants parameterized attack instances into copies of the real
   servers — each class × idiom variants (direct env-value log vs name-only log; aliased assignment;
   template-literal interpolation; cross-function hop; secret into outbound URL vs header vs body;
   hardcoded token shapes). Target ≥100 planted instances across ≥8 classes. Anti-overfit: hold out
   entire mutation **classes** (tune on 1–6, report on 7–8 + hand-labeled real findings); vary
   insertion idioms; no planting markers in code.
4. **Harness + CI gate.** Runner emits per-lens precision/recall + overall FP rate (JSON +
   markdown); CI fails on regression below the last-release floor. Demonstrate the gate
   red-then-green on a deliberately planted regression before trusting it.

**Metric honesty:** report **precision** as the primary number and define it in the README
methodology section. The oft-cited ~78% industry false-positive figure is a single 33-server study —
cite it as directional, never as the denominator of a marketing claim.

## Phase 2 — Credential / least-privilege lens (the headline)

1. **Kill the four named FP classes first** — written as fixtures before the taint pass (all four
   are hand-verified real-world failures from the POC):
   name-vs-value (`console.error("BRAVE_API_KEY is required")` — the *name* as a string literal is
   not the tainted *value*) · window-overshoot (`return apiKey` near a log call is not a log of it) ·
   path-not-secret (`*_PATH`/`*_FILE` env vars are pointers) · aliased flow (must still catch:
   `const key = process.env.X; log(key)`).
2. **Source/sink model.** Sources: env reads with secret-shaped names, known token shapes (`ghp_`,
   `xoxb-`, `AKIA…`), high-entropy literals, config reads. Sinks: log/console/error paths, HTTP
   response bodies, outbound request URL/query/headers/body, file writes, child-process args.
   Confidence tiers per source×sink pair; only high tiers are `finding`, the rest `inventory`.
3. **Least-priv checks** (static, cheap): over-broad fs roots, wildcard OAuth scopes,
   missing/optional auth on network-exposed transports, token-passthrough / confused-deputy shapes.
   Framed as inventory unless provably wrong.

**Engine fork ([ADR-0001](../adr/0001-tree-sitter-engine.md)):** v1 taint is intra-file def-use on
tree-sitter scopes. If the four FP classes aren't cleanly killed after ~2 days of taint work, switch
the engine to semgrep-CE taint mode and keep every other layer (corpus, labels, metrics, report,
deploy) unchanged. The fork does not extend the deadline.

**Numeric targets (set now, argued never):** credential-lens precision ≥0.90 on holdout ·
planted-mutation recall ≥0.80 on intra-file classes · overall tool FP rate <20%. If unreachable by
**2026-07-22**: demote sub-threshold checks to `inventory`, ship honest numbers, and reframe the
story as *"why this is hard: an eval harness that proves the industry baseline"* — stated in the
write-up, not hidden.

**Known-miss classes** (documented, not chased in v1): cross-file/module taint flows; Python corpus
depth (TS-heavy corpus); dynamic/runtime behavior (rug-pulls, live manifest diffing).

## Phase 3 — Deploy: hosted scan-by-URL

*Amended 2026-07-14 (codex rounds 1–2; [ADR-0003](../adr/0003-hosted-output-publication-semantics.md)):
fetch is a pinned-host **tarball download** (not a clone), and the output is a **click-to-run share
pointer with ephemeral results** — a persistent shareable findings page would publish unverified
named findings, violating invariant 5. Binding detail now lives in
[specs/hosted-scan.md](../specs/hosted-scan.md).*

Minimal surface: GitHub URL in → pinned tarball fetch (size cap, timeout) → **parse-only** scan →
ephemeral findings view behind a shareable click-to-run pointer. Threat-model the tool's own
surface **before** building it:

- SSRF via clone URL (`git://`, `file://`, redirects) → allowlist `https://github.com/…` only,
  resolve + validate before clone.
- Zip-bombs / monster repos → depth-1, size cap, wall-clock timeout, tmpdir jail.
- Symlink escape in hostile layouts → no symlink following outside the scan root.
- Parser DoS → per-file try/except + per-file timeout.
- **Stored XSS in findings pages** — rendered findings are attacker-controlled strings from the
  scanned repo (tool descriptions are literally the injection payloads this tool hunts). Escape
  everything; treat every rendered string as hostile.
- Abuse → per-IP rate limit, queue depth cap, no secrets in the scan worker's env.

**Gate:** a full security review of the deploy before it goes public. Fallback if the review or the
clock fails: ship the CLI + a hosted static demo of pre-scanned reports (no user input = no attack
surface) and defer live scan-by-URL.

Default target: Vercel (parse-only fits serverless via wasm tree-sitter). Fork trigger: >30% of
scans hitting serverless limits → move the scan worker to a job queue behind the same front.

## Phase 4 — Ecosystem scan + write-ups

1. **Launch post** ("why": the threat model and the skipped credential dimension) — no build
   dependency; draft any day from the research.
2. **Server list:** top-N (default N≈75) as the **intersection of ≥2 sources** (official MCP
   registry, Smithery/PulseMCP, npm downloads) + a manual sanity pass; publish the inclusion
   criteria.
3. **Disclosure protocol BEFORE the scan runs.** At published base rates, scanning ~75 popular
   servers will surface real vulnerabilities in named projects. Severity-gate results; criticals go
   to maintainers via GitHub security advisory / SECURITY.md with a 30d (config-level) / 90d
   (code-level) window. **Never publish a named critical unverified or inside its window** — every
   named finding is hand-verified first. The v1 data-story post publishes aggregates, anonymized
   examples, named *good* exemplars, and named criticals only where fixed.
4. **The scan runs as a plain deterministic script**; raw results persist in-repo as the data
   story's provenance.

## Verification paths (exercised before reporting any phase done)

- Fresh-clone `make eval` reproduces the published numbers.
- The synthetic control scans end-to-end through whatever surface exists (CLI now, URL later).
- The CI regression gate demonstrated red-then-green on a deliberately planted regression.
