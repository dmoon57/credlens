---
type: spec
title: "Hosted scan-by-URL (Phase 3)"
status: active
created_date: 2026-07-14
last_modified: 2026-07-14 23:17 PDT
tags: [mcp, security, deploy, vercel, threat-model]
---

# Hosted scan-by-URL — spec & threat model

Phase 3 of [the plan](../plan/plan.md): a minimal public surface — GitHub repo URL in → parse-only
scan → findings for the requester. **This tool audits other people's security; its own surface is
the first thing a security-literate audience will probe.** The threat model below was written
before any build code, and every mitigation in it is an acceptance criterion.

> **v3.1 (2026-07-14).** Codex round 1: REVISE, 21 findings → v2. Codex round 2: 12 resolved,
> 9 partial, 8 new (2 blocking), negotiated worker isolation accepted-for-v1 with conditions →
> v3. Codex round 3: **APPROVE-WITH-CHANGES** — 7 should-fix + 2 nits, folded here as v3.1
> (atomic admission transition, redaction-last assembly, status→error matrix, coverage-on-success
> semantics, combined output caps, full Bidi_Control set, schema-file deliverable). Gate closed. Deltas: publication semantics formalized as [ADR-0003](../adr/0003-hosted-output-publication-semantics.md)
> + plan amendment; request-level admission before any cache/revalidation work; parent-boundary
> framing and validation of everything the worker or Redis returns; per-file progress deadline;
> explicit gzip metering boundary; lease/WAF/spend/body-cap numbers; revalidation state machine;
> process-group kill + parent-owned tmpdir; hosted redaction boundary. Resolution maps in the
> appendix.

## Goal & acceptance criteria

- A public GitHub repo URL produces a findings view (findings + least-priv inventory + coverage
  manifest) for the person who requested the scan.
- The synthetic control scans end-to-end through the URL surface (plan verification path).
- Every adversarial fixture in §Verification is handled safely (rejected or rendered inert).
- Scan path stays deterministic: **no LLM calls, no target-code execution** (CLAUDE.md
  invariant 2); the shared scanner performs **no network I/O** (§No-network boundary).
- **Results are ephemeral** per [ADR-0003](../adr/0003-hosted-output-publication-semantics.md) —
  no persistent, GET-servable output asserts unverified findings about a named repo.
- **No unprotected deployment at any point:** every pre-gate deployment runs behind Vercel
  Deployment Protection, asserted by an unauthenticated-denial test, until the `/cso` gate and
  operator approval open it.

## Non-goals (v1)

Accounts/auth · scan history UI · non-GitHub hosts · private repos · monorepo special-casing ·
LLM triage · re-scan scheduling · badges/API for third parties · verified-findings curation
workflow (post-v1; until it exists, only ephemeral results).

## Result policy (ADR-0003; codex r1 #6/#7/#14, r2 #6/#7)

- **Share URL = pointer, not archive.** `/scan/{owner}/{repo}` renders a landing card (repo name,
  limits, methodology) with an explicit **"Run scan" click** — it never auto-runs or auto-displays.
  Results render only after the visitor's own admitted POST, `Cache-Control: no-store`, under a
  fixed banner: *automated, unverified results; strings below derive from the scanned repository*.
- **Hosted redaction boundary (r2 #7, r3 #2).** The `Finding` schema has no snippet field and none
  may be added for hosted use — but `message`/`file` are arbitrary strings and least-priv messages
  embed raw repo values. So the parent **assembles the complete response first** (findings +
  inventory + coverage manifest — skipped-file paths included), then **redacts token-shaped and
  high-entropy substrings** (the detector's own source-shape rules, reused) from **every
  repository-derived string field**, with service-generated metadata (`digest`, `scanned_at`,
  `schema`, counts) explicitly exempt so redaction can't eat its own bookkeeping; then final
  per-field byte caps, then serialize/cache. Redaction is the last transform before caps — nothing
  repo-derived is appended after it. Test: a live-shaped token planted in an OAuth scope value
  never appears in response JSON.
- **Internal cache = cost control, never publication:** keyed `casefold(owner)/casefold(repo)`,
  TTL **24 h**, value records tarball sha256 + scan time (digest + time displayed); only ever
  served into an admitted POST response, after revalidation:
- **Revalidation state machine (r2 new #3):** a redirect-refusing HEAD of
  `https://github.com/{owner}/{repo}` →
  `200` = **public-at-this-path** ⇒ serve cache; `301/404/410/451` = **authoritatively
  not-public-here** ⇒ delete entry, fall through to fresh-scan path; timeout/5xx/other =
  **indeterminate** ⇒ `503 Retry-After`, **no deletion**. Successful revalidations are memoized
  60 s (per repo key) so cache-hit floods don't multiply probes. Residual (documented): path-based
  identity — a repo transferred and its name re-registered within the 24 h TTL could serve the
  predecessor's results under the successor's name until expiry; digest + scan time on the page
  bound the confusion. Operator purge path: documented `DEL credlens:cache:<key>` one-liner.

## Architecture

**Runtime: Python on Vercel serverless, reusing the existing detectors.** One source of truth for
detection logic — the published eval numbers describe exactly the hosted code. Verified locally
2026-07-14: all four tree-sitter packages resolve as manylinux2014/abi3 x86_64 wheels for CPython
3.12 (~2.4 MB); runtime import + subprocess semantics are proven by the **runtime probe milestone
(3.2a) before the core build**. Vercel Python runtime is Beta — priced by the probe and the
always-green fallback.

**Concurrency model (r1 #2):** the **enforced** guarantee is per-request detector construction —
no detector instance or mutable scan state at module scope (they mutate internal state, e.g.
`_src`, during a scan), asserted by a two-repo concurrent test. `fluid: false` is the
belt-and-suspenders project toggle on top of that. **Probe finding (3.2a, 2026-07-14): the Vercel
project defaults to `fluid: true` and the toggle is not settable via the v9 projects API on the
current CLI** — so disabling Fluid Compute is an **owed 3.4 deploy-gate action** (dashboard toggle
or a newer `vercel` CLI), tracked in TASKS. v1 does not ship publicly until it's off; the code-level
per-request guarantee holds regardless.

**Isolation (r1 #1/#4 negotiated; r2 accepted-for-v1 with conditions):** extraction + parsing —
everything touching hostile bytes — runs in a **separately killable worker subprocess**:

- **Scrubbed environment** (empty env: no Upstash token, no proxy vars); the parent holds the only
  secret — an Upstash token **ACL-restricted to the `credlens:` key prefix and required commands**.
  **Condition (r2): if an ACL-scoped token cannot be provisioned, public launch is blocked** —
  default full-privilege token is preview-only, full stop.
- **Process-group containment (r2 new #6):** the parent creates the tmpdir and removes it in
  `finally`; the worker runs in its own process group (`setsid`); on deadline or failure the parent
  kills and reaps the **group**; inherited descriptors closed. Repeated forced-death test asserts
  no `/tmp` accumulation and no surviving descendants.
- **Per-file progress deadline (r1 #1 partial → r2 #1):** the `Detector` protocol has no timeout
  parameter and detector code stays untouched — so the enforceable mechanism is the worker's
  progress stream: it emits a marker before each file; the parent kills the group if any single
  file stalls > **5 s** or the whole scan exceeds its budget. Python exceptions inside the worker
  skip one file into the coverage manifest; **native death or progress-stall kill fails the whole
  scan, which is never cached as complete**.
- **Parent-boundary framing (r2 new #2, blocking):** the worker returns results over a pipe as
  **length-prefixed JSON with a parent-enforced 2 MiB frame cap**; worker stdout/stderr reads are
  capped (64 KiB, truncated); the parent **schema-validates before anything else** — enum values,
  field allowlist, per-field byte caps, extra fields rejected. Only the parent serializes, redacts
  (§Result policy), and writes to Redis; Redis **reads** are likewise size-capped and
  schema-validated before serving. A compromised worker or poisoned cache value yields a 500, not
  parent memory exhaustion or schema smuggling.

**No-network boundary (r2 new #7):** the shared scanner (`scan_tree` + detectors) takes a local
root path and performs no I/O beyond reading files under it — fetch, cache, and Upstash live only
in the hosted layer, structurally outside the shared module. The eval path therefore stays
network-free (CLAUDE.md invariant 2). Test: the shared scanner runs its full suite with socket
creation monkeypatched to raise.

**Fetch: GitHub tarball, never `git clone`.** The scanner downloads
`https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD` — a URL **constructed from validated
components, never from the user's string**. No git binary, no `git://`/`file://`/ssh schemes, no
`.git` config/hook tricks, no submodule surface. Unauthenticated codeload reaches public repos
only → private repos unreachable by construction; **no GitHub token exists anywhere**.

Request flow (order is normative — r1 #15, r2 new #1/#4):

```
POST /api/scan
  → request admission FIRST (method/headers/body caps + atomic request-rate limit, §Interface)
  → parse & canonicalize owner/repo (one parser, ASCII, casefold for keys)
  → cache lookup (hit ⇒ revalidate [60 s memo, state machine] ⇒ serve, no-store)
  → ONE atomic Lua admission transition (r3 #1 — in-flight check + per-IP 10/h + global 200/day
    + active-scan cap + lease acquisition as a single Redis transition) returning exactly one of:
    leader (quota charged, leases held) | follower (202, UNCHARGED) | rate_limited | busy
    — fail closed on Upstash error
  → codeload fetch (pinned host, redirects refused, streamed byte cap, proxy-blind opener)
  → worker subprocess (scrubbed env, own pgroup): metered extract → scan_tree → framed result
  → parent: validate frame → ASSEMBLE the complete response (findings + inventory + coverage)
    → redact every repository-derived string field (service-generated metadata — digest,
    scanned_at, schema — exempt; r3 #2) → enforce final caps → serialize → cache put (TTL 24 h)
  → response (no-store)   [finally: release leases by owner token, remove tmpdir]
```

Components:

- `api/scan.py` — the single dynamic endpoint (stdlib-only handler; contract in §Interface).
- `web/index.html`, `web/scan.html` + **external `web/scan.js`/`scan.css`** (no inline script/
  style/handlers; CSP header-delivered, `'self'`-only); `/scan/{owner}/{repo}` rewrites to
  `scan.html` via an **anchored two-segment rewrite**, everything else 404s.
- `src/credlens/scan.py` — shared tree walker factored out of `credlens.eval._run_detector`
  (pure refactor; detector code and labels untouched — eval-integrity invariant holds).
- `src/credlens/hosted/` — fetch, streamed safe-extract, limits, worker protocol, redaction;
  unit-testable with no network (fetcher injected; adversarial tarballs are local fixtures).

## Threat model

Every row is binding: a mitigation here is a test or a config, not a hope.

| # | Threat | Vector | Mitigation | Residual |
|---|--------|--------|------------|----------|
| T1 | SSRF | `git://`, `file://`, redirects, internal hosts via crafted URL | The user string is **parsed, never fetched**: one parser, ASCII-only, `re.fullmatch` — `owner` `[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})`, `repo` `[A-Za-z0-9._-]{1,100}` **excluding `.` and `..`**; accepted forms: `owner/repo` or literal-prefix `https://github.com/owner/repo` (no port/userinfo/query/fragment/percent-escapes, exactly two path segments); fetch URL rebuilt from components; host pinned to `codeload.github.com`; **custom urllib opener: no proxy discovery, redirects refused** (any 3xx = clean failure); https only | None known — the fetcher can only ever address codeload |
| T2 | Resource bombs | gzip bomb, monster repo, 10⁶ files, link farms | Streamed download aborts over **30 MB compressed**; **explicit metering boundary (r2 #11):** raw stream → compressed-byte counter (30 MB cap) → `gzip.GzipFile` → **decompressed-byte counter that raises at 150 MB** → `tarfile.open(mode="r|", fileobj=…)` — the tar layer only ever sees capped, already-metered plaintext; never `getmembers()`/blind `extractall()`; caps: written file bytes **100 MB**, members **5 000**, per-file **1 MB**, name length **512**, duplicate resolved paths rejected; **any over-cap member aborts the whole archive**; **45 s scan wall-clock** inside one monotonic end-to-end deadline; worker RSS cap | Burst CPU within one invocation, bounded by timeout |
| T3 | Path traversal / link escape | hostile member paths, symlink/hardlink members | `tarfile.data_filter` **wrapped in a stricter policy: only directories and regular files accepted — every symlink, hardlink, sparse/special/unknown type rejected**; extraction into the parent-owned per-request tmpdir; walker uses `lstat`-based checks, never follows links | None known; adversarial fixtures prove it |
| T4 | Parser hang / native crash | pathological source files | Two enforceable tiers: **per-file progress deadline (5 s) + whole-scan deadline**, both parent-enforced via the worker progress stream and process-group kill; Python exceptions skip one file into the coverage manifest; **native death / stall-kill fails the scan and is never cached as complete**; **parse-only — target code never executes** | Native crash DoSes one request, never poisons results |
| T5 | **XSS in findings view** | rendered strings originate in the scanned repo | Findings travel as **JSON only** (`application/json; charset=utf-8` + `nosniff` on **every** status); page renders **exclusively via `textContent`**; no inline script/style — external assets only; **CSP delivered as an HTTP header via vercel.json on every route** (`default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`) + `X-Frame-Options: DENY`; **control & bidi chars visibly escaped as codepoint sequences before display — the full Unicode `Bidi_Control` set (LRE/RLE/LRO/RLO/PDF/LRI/RLI/FSI/PDI/ALM/LRM/RLM) plus C0/C1 and zero-width (r2 #13, r3 nit)**; `textContent` + CSS `unicode-bidi: isolate` handle direction, escaping handles visibility; bidi/control fixture (covering an embedding control, e.g. LRE, not just overrides) asserted via DOM | XSS requires both a renderer bug **and** a CSP bypass |
| T6 | Abuse / cost DoS | scripted floods, cross-site amplification, cache-hit floods | **Request-level admission before any work (r2 new #1): atomic 60 POST/h/IP** limit ahead of cache/revalidation; on cache miss, **one atomic Lua transition (r3 #1)** combines in-flight detection + scan budget (**10/h/IP + 200/day global**) + **active-scan cap 2** + per-repo single-flight lease acquisition, returning exactly one of `leader` (charged, leases held) / `follower` (202, uncharged) / `rate_limited` / `busy` — no separate check-then-charge steps, fail closed on Upstash error; **leases: TTL 90 s, random owner token, compare-and-delete release, no renewal (deadline < TTL)**; POST-only + `application/json` + `X-Credlens-Scan: 1` + `Sec-Fetch-Site` same-origin/absent + **no CORS**; IP = **`x-vercel-forwarded-for` only**, `ipaddress`-parsed, IPv6 quota'd at /64, fail closed if absent; followers get **202 `{"status":"in-flight","retryAfter":5}` + `Retry-After: 5`** (r2 new #4); cache makes repeats cheap | Post-cap request-layer spend bounded by WAF + spend caps (numbers below) |
| T7 | Secrets near hostile input | worker compromise reads credentials | Hostile bytes processed in the **env-scrubbed worker** (holds nothing); parent holds the single **ACL-scoped** Upstash token (`credlens:` prefix + required commands only); **everything crossing back from the worker or Redis is capped, framed, and schema-validated at the parent boundary** before use; no GitHub token, no LLM keys. **ACL token unprovisionable ⇒ public launch blocked** (preview may run on the default token) | /proc parent-env reach from a native worker RCE — documented, accepted for v1 (r2 concurred); `/cso` re-examines |
| T8 | Info disclosure | stack traces, tmp paths, env in errors | Uniform terse JSON errors (schema in §Interface); detail only in structured, escaped server logs | — |
| T9 | Content spoofing / phishing | attacker-authored strings shown to visitors | Ephemeral render under a fixed banner naming the scanned repo + unverified notice; findings content never linkified; only outbound link is `github.com/{owner}/{repo}` rebuilt from validated components | Screenshot spoofing — out of scope |
| T10 | Cache poisoning / staleness / retention | cached results outliving repo visibility or identity | Cache = cost control only: POST-gated, TTL 24 h, **revalidation state machine before every cached serve** (§Result policy — authoritative-gone deletes, indeterminate 503s without deleting, 60 s memo), digest + scan time displayed, redaction boundary strips secret-shaped content, size-capped schema-validated reads, operator purge path | Path-identity reuse within TTL (§Result policy residual); ≤24 h staleness, displayed |
| T11 | Upstream drift | codeload behavior is not a documented contract | Fail-closed: require status 200 **and** gzip magic; every other outcome maps through the **single status→error matrix (r3 #3)** in §Interface — one authoritative mapping shared by this row, the handler, and the acceptance matrix. **Acceptance matrix with defined outcomes (r2 #9; observed 2026-07-14, probe run):** normal ⇒ 200 + scan completes *(observed)* · renamed/transferred ⇒ **either** transparent 200 (observed for `nodejs/io.js` — scan proceeds under the requested name; the T10/T11 residual, TTL-bounded) **or** 3xx/404 ⇒ `not_found` — both outcomes defined · deleted/nonexistent/blocked ⇒ 404/410/451 ⇒ `not_found` *(404 observed, no Location header)* · huge repo ⇒ 200 + gzip, streamed early-abort works *(observed against torvalds/linux)* · empty repo ⇒ valid tarball, 0 scannable files, manifest `complete` (a no-commit repo 404s ⇒ `not_found`) · LFS ⇒ pointer files scanned as text, noted in limitations · over-limit repo ⇒ `payload_too_large`. Probe passes iff every case produces a defined outcome | A rename served transparently as 200 caches under the old name ≤24 h |
| T12 | Output amplification | small archive → millions of findings | Binding caps **at the parent boundary before serialization or cache**, applied to the **combined findings + inventory record population (r3 #6)**: 100 records/file · 1 000 records total · bounded UTF-8 bytes per field · 2 MiB worker frame · 1 MiB serialized result; deterministic truncation with omitted-counts **by kind and reason**; scan marked `partial` | — |
| T13 | Silent partial coverage | unsupported language/extension reads as "clean" | **Versioned coverage manifest in every success (200) response (r3 #4)**: supported languages/extensions, files seen/scanned/skipped + reasons, deadline status, `complete|partial`; prominent partial banner. **Whole-scan failure is represented solely by the error envelope (`scan_failed`)** — no coverage object in 4xx/5xx. Walker suffix set vs detector support reconciled in its own eval-gated change | — |

Supply-chain posture: zero new runtime dependencies — stdlib `urllib` (fetch + Upstash REST),
`tarfile`, `gzip`, `re`, `json`, `ipaddress`. Vercel build installs the existing pinned deps via
`uv export`-generated hashed requirements.

## Interface & limits

| Route | What |
|---|---|
| `GET /` | static landing: input form, methodology blurb, limits |
| `GET /scan/{owner}/{repo}` | static share page — repo card + **Run scan** button; never auto-scans |
| `POST /api/scan` | body `{"repo": "owner/repo"}` — admission → cached-or-fresh scan → JSON, `no-store` |

**Handler contract (r1 #19, r2 #19/new #5):** POST only (405 otherwise) · request-target ≤ 256
bytes · **`Content-Length` required and ≤ 1 024; raw body read capped at 1 024 bytes before JSON
decoding** · body must be a JSON object with **exactly one member `repo`** (duplicate keys rejected
via `object_pairs_hook`; extra members rejected) · strict ASCII, no percent-escape tricks ·
`Content-Type: application/json` required · `X-Credlens-Scan: 1` required · `Sec-Fetch-Site`
absent or `same-origin` · no CORS headers ever · one **monotonic end-to-end deadline** spanning
fetch → extract → scan → cache → response with per-stage deadlines · structured escaped logging.

**Response schemas (r2 #19, r3 #5):**
- Success `200`: `{"schema": 1, "repo", "digest", "scanned_at", "coverage", "findings",
  "inventory", "truncated"}` — the **only** status carrying `coverage` (r3 #4); field set closed,
  byte-capped, redacted.
- In-flight `202`: `{"status": "in-flight", "retryAfter": 5}` + `Retry-After: 5`.
- Errors `4xx/5xx`: `{"error": "<short-code>"}` — closed enum
  (`bad_request`, `not_found`, `payload_too_large`, `rate_limited`, `busy`, `upstream_unsupported`,
  `scan_failed`, `unavailable`), never free text, never a coverage object.
- The prose above is schematic by design: **milestone 3.2b's first deliverable is a versioned
  JSON Schema (`docs/specs/hosted-scan-schema.json`) with closed objects, typed/enumed nested
  fields, and per-field byte caps** — the parent-boundary validator, the renderer, and the tests
  all consume that file; hand-rolled ad-hoc validation is out.

**Status→error matrix (r3 #3 — the single authoritative mapping; T11 and the handler share it):**

| Condition | HTTP | `error` code |
|---|---|---|
| invalid identifier / malformed request | 400 | `bad_request` |
| body or repo over caps | 413 | `payload_too_large` |
| codeload 3xx (rename/transfer — redirects refused) | 404 | `not_found` |
| codeload 404/410/451 | 404 | `not_found` |
| codeload other non-200, or 200 without gzip magic | 502 | `upstream_unsupported` |
| request-rate or scan-budget exceeded | 429 | `rate_limited` |
| active-scan cap reached | 503 + `Retry-After` | `busy` |
| worker native death / stall kill / frame violation | 500 | `scan_failed` |
| Upstash unreachable, revalidation indeterminate | 503 + `Retry-After` | `unavailable` |

All statuses: `application/json; charset=utf-8`, `nosniff`, `no-store`.

Limits (displayed on the landing page — stated limitations are credibility):
30 MB tarball · 150 MB decompressed / 100 MB written · 5 000 files · 1 MB/file · 45 s scan ·
5 s/file progress deadline · 1 000 findings (capped, marked partial) · 60 POST/h/IP ·
10 scans/h/IP · 200 scans/day global · 2 concurrent scans · cache TTL 24 h · public GitHub repos
only · results ephemeral by design ([ADR-0003](../adr/0003-hosted-output-publication-semantics.md)).

**Deploy-time abuse economics (r2 #18, 3.4 acceptance criteria):** Vercel WAF rate-limit rule on
`/api/scan` — **60 req/60 s per IP, block** (the request-layer bound above app quotas); Vercel
Spend Management hard cap **$20/mo with auto-pause**; Upstash free-tier daily command budget is
the Redis spend bound; limiter fails closed on Upstash error (no anonymous free scans).

## Decisions

1. **Tarball over clone** — kills the git attack class structurally; size-cappable stream; private
   repos unreachable by construction.
2. **Python runtime reusing the detectors** — no TS port; eval numbers describe the hosted code.
3. **Stdlib-only web layer** — held at codex rounds 1–2; backed by the explicit handler contract.
4. **Upstash Redis via REST, ACL-scoped token** — atomic Lua admission; fail closed; **no ACL ⇒
   no public launch**.
5. **Ephemeral results, share-URL-as-pointer** — formalized as
   [ADR-0003](../adr/0003-hosted-output-publication-semantics.md); plan §Phase 3 amended.
6. **`fluid: false` + per-request detector instances** — correctness before concurrency.
7. **Worker isolation: env-scrubbed process-group subprocess + parent-boundary framing** — r2
   judged acceptable-for-v1 with the ACL condition and parent-boundary hardening, both absorbed.

## Verification (before the phase is "done")

Adversarial fixtures, built in an isolated context like all fixtures (working agreement):
traversal tar (`../escape`) · absolute-path tar · symlink-escape tar · internal-symlink tar ·
hardlink-farm tar · gzip bomb (multi-GB member early in the stream) · 6 000-file tar · >1 MB
member (aborts archive, not skip) · duplicate-path tar · overlong-name tar · crash-shaped source
file · hanging-parser injection (per-file 5 s stall kill) · worker `os._exit`/segfault simulation
(scan fails, never cached) · **repeated forced worker deaths** (no `/tmp` accumulation, no
surviving process-group descendants) · result-bomb repo (caps + `partial`) · planted live-shaped
token **including in an OAuth scope value** (value never appears in JSON — redaction boundary) ·
**oversized/malformed worker frame** (parent 500s cleanly) · **poisoned oversized cache value**
(parent rejects on read) · XSS-payload repo (`<img onerror>` in env names, tool descriptions,
file paths) rendered inert, asserted via DOM in a real browser (zero CSP violations) ·
**bidi/control-character fixture** (RLO/zero-width in paths and messages → visible escapes).

Plus: URL-validation unit tests (scheme/host/userinfo/port tricks, unicode confusables, `.`/`..`,
casing → one casefolded key, encoded slashes, duplicate params/keys, oversized body) · quota tests
(request-level limit before cache work — **cached-hit flood consumes request budget, not scan
budget**; atomicity under parallel fire; fail-closed on Upstash error; spoofed `X-Forwarded-For`
ignored) · **admission-transition race test (r3 #1): N simultaneous misses for one repo yield
exactly one `leader`, N−1 uncharged `follower`s — never double-charged quota** · lease tests
(active cap 2 held under parallel load; owner-token release; TTL expiry of a crashed holder) ·
revalidation state-machine tests (200/301/404/timeout paths; 60 s memo; no delete on
indeterminate) · error-hygiene (no paths/traces; closed error enum) · MIME/rewrite (exact types on
every status; anchored rewrite; extra segments 404) · cross-request isolation (two repos, unique
markers never cross) · **sockets-disabled run of the shared scanner suite** (no-network boundary) ·
deployment-protection assertion (unauthenticated → denied) · upstream acceptance matrix (T11
outcomes) · `vercel dev` smoke · the synthetic control scanned through the URL surface.

## Milestones & gates

- **3.1 — spec + codex gate.** Round 1 REVISE (21) → v2; round 2 REVISE (8 partial + 8 new,
  negotiated fix accepted) → v3. **Round 3 re-review; converge to APPROVE(-WITH-CHANGES) before
  any build code.**
- **3.2a — runtime probe, protected**: minimal Deployment-Protection-enabled deploy that imports
  every pinned wheel, parses one fixture, spawns and **group-kills** a hanging worker, exercises
  `/tmp` create/cleanup, confirms `fluid: false` + explicit memory/`maxDuration`, and runs the T11
  matrix against its defined outcomes. Kill criterion: any case undefined/unsafe ⇒ fallback.
- **3.2b — scan core, local**: **first deliverable: `hosted-scan-schema.json`** (the closed,
  versioned response/frame schema — validator, renderer, and tests consume it); then `scan.py`
  factor-out + `hosted/` fetch/metered-extract/limits/worker-protocol/redaction, TDD against the
  adversarial fixtures. No network in tests.
- **3.3 — web surface, local**: handler contract + static pages/assets + atomic quotas/leases +
  XSS/CSP/MIME/bidi tests; `vercel dev` smoke.
- **3.4 — gated deploy**: protected preview (asserted) → deployed-surface test suite → **full
  `/cso` review** → fix findings → **operator approval** → WAF rule + spend caps confirmed →
  public alias + README link.

## Fallback (pre-committed)

If the probe fails, the review fails, ACL tokens are unavailable, or the clock runs out: ship the
CLI + a hosted **static demo of pre-scanned reports** (no user input = no attack surface) and
defer live scan-by-URL. This path is always green — and satisfies ADR-0003 trivially.

## Open questions

- Vercel function memory/duration tier for worst-case scans — measured at 3.2a/3.4; plan's fork
  trigger: >30 % of scans hitting limits → job queue behind the same front.

## Appendix — codex resolution maps

**Round 1 (21 findings → v2, all carried into v3):** 1 worker containment (T4, §Isolation) ·
2 fluid/state (§Concurrency) · 3 output caps (T12) · 4 worker secret (negotiated, §Isolation/T7) ·
5 coverage manifest (T13) · 6 disclosure (§Result policy → ADR-0003) · 7 cache retention (§Result
policy) · 8 identifier grammar (T1) · 9 codeload matrix (T11) · 10 link filter (T3) · 11 gzip
metering (T2) · 12 CSP delivery (T5) · 13 rewrite/MIME (§Interface) · 14 GET amplification (T6) ·
15 flow order (request flow) · 16 leases (T6) · 17 IP derivation (T6) · 18 spend (§Interface
deploy-time) · 19 handler contract (§Interface) · 20 probe ordering (3.2a) · 21 protection (Goal).

**Round 2 → v3:** partial 1 → per-file progress deadline (§Isolation, T4) · partial 6 →
[ADR-0003](../adr/0003-hosted-output-publication-semantics.md) + plan amendment · partial 7 →
hosted redaction boundary (§Result policy) · partial 9 → T11 defined outcomes · partial 11 →
explicit metering boundary (T2) · partial 13 → codepoint escaping + bidi fixture (T5) · partial
16 → lease numbers (T6) · partial 18 → WAF/spend numbers (§Interface) · partial 19 → body caps +
response schemas (§Interface) · new 1 → request-level admission first (flow, T6) · new 2 →
parent-boundary framing (§Isolation, T7, T12) · new 3 → revalidation state machine (§Result
policy) · new 4 → uncharged 202 followers (flow, T6) · new 5 → body-byte cap (§Interface) ·
new 6 → process-group kill + parent tmpdir (§Isolation) · new 7 → no-network boundary (§Arch) ·
new 8 → plan §Phase 3 amended + ADR-0003 · negotiated-fix conditions → ACL-or-no-launch (T7,
§Fallback) + parent-boundary hardening.
