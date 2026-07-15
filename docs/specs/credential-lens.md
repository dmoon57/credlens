---
type: spec
title: "Credential / least-privilege lens (Phase 2)"
status: active
created_date: 2026-07-14
last_modified: 2026-07-14 17:45 PDT
tags: [mcp, security, credential, taint, tree-sitter]
---

# Credential / least-privilege lens — spec

The headline detector: does an MCP server's code let a **secret value** reach an
observable sink (a log, an HTTP response, an outbound request, a file, a subprocess)?
Built on ADR-0001 (tree-sitter intra-file def-use taint) and ADR-0002 (finding vs
inventory). Plan context: [../plan/plan.md](../plan/plan.md) §Phase 2.

## Goal & non-goals

- **Goal:** high-precision detection of secret-value → sink dataflow within a single
  file, plus hardcoded-secret detection. Precision is the product; a false positive on
  a named project is the credibility kill-shot.
- **Non-goals (v1, documented known-misses):** cross-file / cross-module taint;
  interprocedural taint across function boundaries (the `cross-function-hop` mutation
  class exists to *measure* this miss, not to pass it); deep Python coverage;
  dynamic/runtime behavior. Reading a credential *file* and logging its contents is a
  known-miss (we flag the write-to-path as inventory, not a finding).

## The four FP classes this lens must kill (Move 2.1 — fixtures first)

These are the POC's hand-verified real-world false positives. Fixtures encode them from
the real server code **before** the taint pass is written.

1. **name-not-value** — `console.error("BRAVE_API_KEY environment variable is required")`.
   The env-var *name* appears as a string literal; the *value* binding never reaches the
   sink. Expected: **no finding.** (brave-search, gitlab)
2. **window-overshoot** — `return apiKey` sits near a `console.error(...)`. Proximity is
   not dataflow; `return` is not a sink and the log arg is a string literal. Expected:
   **no finding.** (google-maps)
3. **path-not-secret** — a `*_PATH`/`*_FILE`/`*_DIR` env var is a pointer, not a secret;
   writing *to* that path is not a secret leak. Expected: **no finding.** (gdrive)
4. **aliased flow (must still catch)** — `const key = process.env.API_KEY; log(key)`.
   The value is aliased through a binding and reaches a sink. Expected: **a finding.**

## Taint model (intra-file def-use)

**Sources (a value is secret):**
- `process.env.NAME` where NAME matches a secret-shaped name (`*KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH*`)
  and is **not** path-shaped (`*_PATH|_FILE|_DIR` or `PATH|FILE|DIR` suffix).
- Hardcoded token literals (structural shapes: `ghp_…`, `xox[baprs]-…`, `AKIA…`).
- (Deferred: high-entropy string literals — off in v1 to protect precision; documented.)

**Propagation:** taint is on **bindings**, never on name tokens.
- `const x = <tainted>` / `let` / destructure → `x` tainted.
- `x` tainted and `const y = x` (or `` `…${x}…` ``, `x + …`, `x.foo`) → the derived
  expression is tainted.
- A **string literal** is never tainted, even if it textually contains a secret name —
  this is precisely what kills name-not-value.

**Sinks:** a tainted expression reaching any of —
- logging: `console.log|error|warn|info`, `logger.*`
- outbound: `fetch(url, opts)` — the URL arg and `opts.headers` / `opts.body` values
- file writes: `fs.writeFile|writeFileSync|appendFile*` (the *content* arg, not the path)
- subprocess: `exec|execSync|spawn|execFile*` args
- `return` is **not** a sink.

**Confidence tiers (ADR-0002):** only high-confidence pairs are `kind="finding"`; the
rest are `kind="inventory"` and never scored TP/FP.
- **finding (unambiguous leaks):** secret value → log/console/logger; secret value →
  file-write content; secret value → subprocess arg; hardcoded token literal present.
- **inventory (ambiguous):** secret value → **outbound request** (URL/header/body). A
  secret in an outbound request is most often *legitimate authentication* — sending an
  API key to its own API is the key's intended use (this is exactly the gitlab/github
  reference servers). Telling legitimate auth from **exfiltration** requires
  destination-taint (is the host caller-controlled / attacker-influenced?), which is a
  **v1 known-miss deferred to v2**. Emitting these as inventory keeps real-server
  precision at 1.0 while still surfacing the surface for least-privilege review.
- **Decision (2026-07-14):** classifying all secret→outbound as inventory in v1 is the
  call that makes precision honest. Its cost is measured: the `secret-in-url/header/body`
  mutation classes are tagged `taint_scope: exfil_v2` and **reported, not gated** —
  visible in `eval/report.md`, never hidden.

## Least-privilege inventory (Move 2.3)

Static, cheap, framed as **inventory** (`kind="inventory"`, ADR-0002) — the factual
permission surface a reviewer wants, never counted TP/FP and never affecting precision.
The v1 checks (`detectors/leastpriv.py`), grounded in what the reference corpus actually
contains, aggregate **one item per category per file**:

- **oauth-scope** — declared OAuth scopes (`scopes: [...]`), each tagged breadth
  `narrow` (`*.readonly`/`read`) vs `broad` (full/write/admin/wildcard). *(gdrive
  declares `drive.readonly` — narrow, good.)*
- **network-exposed-transport** — `SSEServerTransport` / `StreamableHTTPServerTransport`
  / `express()` / `http.createServer` with no visible auth check. *(the `everything`
  server exposes SSE + HTTP.)* Stdio transport is local, not flagged.
- **capability** — raw capability regardless of secrets: `fs-write`, `fs-delete`,
  `process-exec`, `dynamic-eval`, `outbound-network`.
- **token-passthrough / confused-deputy** — a **caller-controlled** value (a function
  parameter / tool arg) used as an `Authorization` credential on an outbound request.
  This is the genuine confused-deputy shape — distinct from a server sending its *own*
  configured token (github/gitlab do that; **not** flagged).

These emit **zero `kind="finding"`** by construction, so real-server precision stays 1.0.
The aggregate becomes the "permission surface of the MCP ecosystem" data for the report.

## Targets (from the wargame; argued never)

- credential-lens **precision ≥ 0.90 on holdout** (real-server credential findings are
  all false by ground truth → the lens must emit **zero** on the reference servers).
- planted-mutation **recall ≥ 0.80 on intra-file classes** (the interprocedural
  `cross-function-hop` class is excluded from this gate and reported as a known-miss).
- overall tool **FP rate < 20%**.

If a target is unreachable by 2026-07-22 after the ADR-0001 fork has fired: demote
sub-threshold checks to inventory, ship honest numbers, reframe per the plan.

## Verification

- The four FP-class fixtures pass (3 no-finding, 1 finding) — authored before the detector.
- `make eval` with the credential detector: real-server precision = 1.0 (zero findings),
  intra-file holdout recall ≥ 0.80, negatives not flagged, overall FP < 0.20.
- The `cross-function-hop` known-miss is visible in `eval/report.md`, not hidden.
