---
type: spec
title: "Hosted scan-by-URL (Phase 3)"
status: active
created_date: 2026-07-14
last_modified: 2026-07-14 19:55 PDT
tags: [mcp, security, deploy, vercel, threat-model]
---

# Hosted scan-by-URL — spec & threat model

Phase 3 of [the plan](../plan/plan.md): a minimal public surface — GitHub repo URL in → parse-only
scan → findings for the requester. **This tool audits other people's security; its own surface is
the first thing a security-literate audience will probe.** The threat model below was written
before any build code, and every mitigation in it is an acceptance criterion.

> **v2 (2026-07-14).** Revised after codex adversarial round 1 (verdict REVISE, 21 findings — all
> accepted; one fix negotiated). Deltas: ephemeral result policy (disclosure invariant), killable
> scan worker, streamed extraction accounting, links rejected wholesale, output caps, POST +
> Fetch-Metadata admission, atomic quotas + single-flight, enforced deployment protection, runtime
> probe moved ahead of the build. Resolution map in the appendix.

## Goal & acceptance criteria

- A public GitHub repo URL produces a findings view (findings + least-priv inventory + coverage
  manifest) for the person who requested the scan.
- The synthetic control scans end-to-end through the URL surface (plan verification path).
- Every adversarial fixture in §Verification is handled safely (rejected or rendered inert).
- Scan path stays deterministic: **no LLM calls, no target-code execution** (CLAUDE.md invariant 2).
- **Results are ephemeral** — no persistent, GET-servable page asserts unverified findings about a
  named repo (CLAUDE.md invariant 5; §Result policy).
- **No unprotected deployment at any point:** every pre-gate deployment runs behind Vercel
  Deployment Protection, asserted by an unauthenticated-denial test, until the `/cso` gate and
  operator approval open it.

## Non-goals (v1)

Accounts/auth · scan history UI · non-GitHub hosts · private repos · monorepo special-casing ·
LLM triage · re-scan scheduling · badges/API for third parties · verified-findings curation
workflow (post-v1; until it exists, only ephemeral results).

## Result policy (disclosure invariant, codex #6/#7/#14)

CLAUDE.md invariant 5: named findings about real projects are never *published* unverified. A
persistent shareable page of machine findings **is** publication. Therefore:

- **Share URL = pointer, not archive.** `/scan/{owner}/{repo}` is shareable, but it renders a
  landing card (repo name, limits, methodology) with an explicit **"Run scan" click** — it never
  auto-runs or auto-displays findings. Results render only after the visitor's own admitted POST,
  with `Cache-Control: no-store`, under a fixed banner: *automated, unverified results; strings
  below derive from the scanned repository*.
- **No secret material in results, structurally.** The hosted result schema is frozen to the
  existing `Finding` fields (`file`, `line`, `lens`, `kind`, `message`, `confidence`) — no snippet
  field exists and none may be added for hosted use; messages carry identifier names, never
  matched values. A test plants a live-shaped token and asserts its value never appears in the JSON.
- **The internal cache is cost control, not publication:** keyed `casefold(owner)/casefold(repo)`,
  TTL **24 h**, value records tarball sha256 + scan time (digest + time displayed). It is only ever
  served to an admitted POST, **after revalidating the repo is still publicly reachable** (cheap
  HEAD-equivalent probe; probe failure ⇒ cache entry deleted, scan re-attempted or 404). Operator
  purge path: a documented `redis del` one-liner per key.

## Architecture

**Runtime: Python on Vercel serverless, reusing the existing detectors.** One source of truth for
detection logic — the published eval numbers describe exactly the hosted code. Verified locally
2026-07-14: all four tree-sitter packages resolve as manylinux2014/abi3 x86_64 wheels for CPython
3.12 (~2.4 MB); runtime import + subprocess semantics are proven by the **runtime probe milestone
(3.2a) before the core build**. Vercel Python runtime is Beta — that risk is priced by the probe
and the always-green fallback.

**Concurrency model (codex #2):** `fluid: false` for v1 — one invocation per process. No detector
instance or mutable scan state at module scope; detectors are constructed per request (they mutate
internal state, e.g. `_src`, during a scan). A two-repo concurrent test asserts unique markers
never cross results.

**Isolation (codex #1/#4, negotiated):** extraction + parsing — everything that touches hostile
bytes — runs in a **separately killable worker subprocess with a scrubbed environment** (empty env:
no Upstash token, no proxy vars) and a parent-enforced deadline + RSS cap. Python exceptions skip
one file; **native worker death (segfault/hang-kill) fails the whole scan and is never cached as
complete**. The parent (handler) holds the only secret: an Upstash token, **ACL-restricted** to the
required commands and the `credlens:` key prefix — not the default full-privilege token. Residual
(documented, accepted): a same-uid native RCE in the worker could theoretically reach the parent's
env via /proc; the mitigations are parse-only design, the ACL scope bounding blast radius to cache/
quota keys, and ephemeral results (a poisoned cache can't serve a persistent page). If `/cso`
rejects this residual, the pre-committed fallback applies.

**Fetch: GitHub tarball, never `git clone`.** The scanner downloads
`https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD` — a URL **constructed from validated
components, never from the user's string**. No git binary, no `git://`/`file://`/ssh schemes, no
`.git` config/hook tricks, no submodule surface. Unauthenticated codeload reaches public repos
only → private repos are unreachable by construction, and **no GitHub token exists anywhere**.

Request flow (order is normative — codex #15):

```
POST /api/scan  (admission: method+content-type+custom header+Sec-Fetch-Site, §Interface)
  → parse & canonicalize owner/repo (one parser, ASCII, casefold for keys)
  → cache lookup (hit ⇒ revalidate-public ⇒ serve, no-store)
  → atomic quota admission on miss (per-IP + global daily, one Lua script, fail closed)
  → per-repo single-flight lease + global active-scan lease (TTL'd; full ⇒ 429/202)
  → codeload fetch (pinned host, redirects refused, streamed byte cap, proxy-blind opener)
  → worker subprocess (scrubbed env): streamed tar extract w/ metered accounting → scan_tree
  → coverage manifest + capped findings JSON → cache put (TTL 24 h) → response (no-store)
```

Components:

- `api/scan.py` — the single dynamic endpoint (stdlib-only handler; exact contract in §Interface).
- `web/index.html`, `web/scan.html` + **external `web/scan.js`/`scan.css`** (no inline script/
  style/handlers — CSP is header-delivered and `'self'`-only; codex #12); `/scan/{owner}/{repo}`
  rewrites to `scan.html` via an **anchored two-segment rewrite**, everything else 404s.
- `src/credlens/scan.py` — shared tree walker factored out of `credlens.eval._run_detector`
  (pure refactor; detector code and labels untouched — eval-integrity invariant holds).
- `src/credlens/hosted/` — fetch, streamed safe-extract, limits, worker protocol; unit-testable
  with no network (fetcher injected; adversarial tarballs are local fixtures).

## Threat model

Every row is binding: a mitigation here is a test or a config, not a hope.

| # | Threat | Vector | Mitigation | Residual |
|---|--------|--------|------------|----------|
| T1 | SSRF | `git://`, `file://`, redirects, internal hosts via crafted URL | The user string is **parsed, never fetched**: one parser, ASCII-only, `re.fullmatch` — `owner` `[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})`, `repo` `[A-Za-z0-9._-]{1,100}` **excluding `.` and `..`**; accepted forms: `owner/repo` or a literal-prefix `https://github.com/owner/repo` (no port/userinfo/query/fragment/percent-escapes, exactly two path segments); fetch URL rebuilt from components; host pinned to `codeload.github.com`; **custom urllib opener: no proxy discovery, redirects refused** (any 3xx = clean failure); https only | None known — the fetcher can only ever address codeload |
| T2 | Resource bombs | gzip bomb, monster repo, 10⁶ files, link farms | Streamed download aborts over **30 MB compressed**; **streamed** tar walk (`r|gz`, never `getmembers()`/blind `extractall()`) through a **counted gzip reader**: caps on raw uncompressed tar bytes (**150 MB**), written file bytes (**100 MB**), members (**5 000**), per-file (**1 MB**), name length, duplicate resolved paths; **any over-cap member aborts the whole archive** (no skip-and-continue); **45 s scan wall-clock** inside one monotonic end-to-end deadline; worker RSS cap | Burst CPU within one invocation, bounded by timeout |
| T3 | Path traversal / link escape | hostile member paths, symlink/hardlink members | `tarfile.data_filter` **wrapped in a stricter policy: only directories and regular files are accepted — every symlink, hardlink, sparse/special/unknown type is rejected** (data_filter alone permits inside-destination links — codex #10); extraction into per-request tmpdir; walker uses `lstat`-based checks, never follows links | None known; adversarial fixtures prove it |
| T4 | Parser hang / native crash | pathological source files | Two tiers (codex #1): tree-sitter per-file parse timeout, **plus** the killable worker subprocess with parent deadline — a native hang/segfault kills the worker, **fails the scan, and is never cached as complete**; Python-level exceptions skip one file into the coverage manifest; **parse-only — target code never executes** | Native crash DoSes one request, never poisons results |
| T5 | **XSS in findings view** | rendered strings originate in the scanned repo | Findings travel as **JSON only** (`application/json; charset=utf-8` + `nosniff` on **every** status); page renders **exclusively via `textContent`**; no inline script/style — external assets only; **CSP delivered as an HTTP header via vercel.json on every route** (`default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`) + `X-Frame-Options: DENY`; control/bidi chars rendered visibly-escaped (`<bdi>`/escapes — codex #13) | XSS requires both a renderer bug **and** a CSP bypass |
| T6 | Abuse / cost DoS | scripted scan floods, cross-site amplification | **POST-only** scan admission: `application/json` + fixed custom header + `Sec-Fetch-Site` same-origin, **no CORS allowance** (kills cross-site `<img>`-farm amplification — codex #14); per-IP **10/h** + global **200/day** in **one atomic Lua script** (check+incr+expire; fail closed on Upstash error); IP = **`x-vercel-forwarded-for` only**, parsed via `ipaddress`, IPv6 quota'd at /64, fail closed if absent (codex #17); global active-scan lease + per-repo single-flight (TTL'd; 429 `Retry-After` / 202 in-flight — codex #16); cache makes repeats cheap | Post-cap request-layer spend bounded by WAF rule + spend management (deploy checklist, codex #18) |
| T7 | Secrets near hostile input | worker compromise reads credentials | Hostile bytes are processed in the **env-scrubbed worker** (holds nothing); the parent holds the single secret — an **ACL-scoped** Upstash token (cache/quota keys only); no GitHub token, no LLM keys | /proc parent-env reach from a native worker RCE — documented, accepted for v1 (§Architecture); `/cso` re-examines |
| T8 | Info disclosure | stack traces, tmp paths, env in errors | Uniform terse JSON errors (400/404/413/429/500/503 + short code); detail only in structured, escaped server logs | — |
| T9 | Content spoofing / phishing | attacker-authored strings shown to visitors | Ephemeral render under a fixed banner naming the scanned repo + unverified-results notice; findings content never linkified; the only outbound link is `github.com/{owner}/{repo}` rebuilt from validated components | Screenshot spoofing — out of scope |
| T10 | Cache poisoning / staleness / retention | cached results outliving repo visibility | Cache = cost control only (§Result policy): POST-gated, TTL 24 h, **revalidate-public before every cached serve** (fail ⇒ delete + re-scan/404), digest + scan time displayed, no secret material representable in the schema, operator purge path | ≤24 h staleness, displayed and honest |
| T11 | Upstream drift (renames, redirects, LFS, empty/large repos) | codeload behavior is not a documented contract | Fail-closed: require status 200 **and** gzip magic bytes; any 3xx/other status = "upstream unsupported" error (never silently follow); an **upstream-compatibility acceptance matrix** (normal · renamed · transferred · empty · large · LFS) runs at 3.2a and before ship (codex #9) | A rename served transparently as 200 caches under the old name for ≤24 h |
| T12 | Output amplification | small archive → millions of findings | Binding caps **before serialization or cache** (codex #3): 100 findings/file · 1 000 total · bounded UTF-8 byte length per field · 1 MiB serialized result; deterministic truncation with omitted-counts by reason; scan marked `partial` | — |
| T13 | Silent partial coverage | unsupported language/extension reads as "clean" | **Versioned coverage manifest in every response** (codex #5): supported languages/extensions, files seen/scanned/skipped + reasons, deadline status, `complete|partial|failed`; prominent partial banner. Walker suffix set vs detector support reconciled in its own eval-gated change | — |

Supply-chain posture: the web surface adds **zero new runtime dependencies** — stdlib `urllib`
(fetch + Upstash REST), `tarfile`, `re`, `json`, `ipaddress`. Vercel build installs the existing
pinned deps via `uv export`-generated hashed requirements.

## Interface & limits

| Route | What |
|---|---|
| `GET /` | static landing: input form, methodology blurb, limits |
| `GET /scan/{owner}/{repo}` | static share page — repo card + **Run scan** button; never auto-scans |
| `POST /api/scan` | body `{"repo": "owner/repo"}` — admission → cached-or-fresh scan → JSON, `no-store` |

**Handler contract (codex #19):** POST only (405 otherwise) · request-target length cap · exactly
one `repo` value, strict ASCII (no percent-escape tricks) · `Content-Type: application/json`
required · fixed custom header (`X-Credlens-Scan: 1`) required · `Sec-Fetch-Site` must be absent
or `same-origin` · no CORS headers ever · uniform JSON error bodies · one **monotonic end-to-end
deadline** spanning fetch → extract → scan → cache → response, with shorter per-stage deadlines ·
structured escaped logging.

Limits (displayed on the landing page — stated limitations are credibility):
30 MB tarball · 150 MB raw uncompressed / 100 MB written · 5 000 files · 1 MB/file · 45 s scan ·
1 000 findings (capped, marked partial) · 10 scans/h/IP · 200 scans/day global · cache TTL 24 h ·
public GitHub repos only · results are ephemeral by design.

## Decisions

1. **Tarball over clone** — kills the git attack class structurally; size-cappable stream; private
   repos unreachable by construction.
2. **Python runtime reusing the detectors** — no TS port; eval numbers describe the hosted code.
3. **Stdlib-only web layer** — held at codex round 1 ("no gap found in choosing stdlib over
   FastAPI"), now backed by the explicit handler contract above.
4. **Upstash Redis via REST, ACL-scoped token** — rate-limit + cache; atomic Lua admission;
   missing env or Upstash error ⇒ fail closed (no anonymous free scans).
5. **Ephemeral results, share-URL-as-pointer** (codex #6) — the disclosure invariant outranks the
   original "shareable findings page" phrasing in the plan. Verified-findings curation is post-v1.
6. **`fluid: false` + per-request detector instances** (codex #2) — correctness before concurrency.
7. **Worker isolation negotiated** (codex #4): env-scrubbed killable subprocess + ACL token instead
   of a second secretless deployment — same intent, one deploy; residual documented in T7 and
   re-examined at the `/cso` gate.

## Verification (before the phase is "done")

Adversarial fixtures, built in an isolated context like all fixtures (working agreement):
traversal tar (`../escape`) · absolute-path tar · symlink-escape tar · **internal-symlink tar** ·
**hardlink-farm tar** (thousands of links to one 1 MB file — size-accounting bypass) · gzip bomb
(multi-GB member early in the stream) · 6 000-file tar · >1 MB member (must abort archive, not
skip) · duplicate-path tar · crash-shaped source file · **hanging-parser injection** (deadline
kill) · **worker `os._exit`/segfault simulation** (scan fails, never cached) · **result-bomb repo**
(findings caps + `partial`) · **planted live-shaped token** (value never appears in JSON) · repo
whose strings are XSS payloads (`<img onerror>` in env names, tool descriptions, file paths) —
rendered inert, asserted via DOM in a real browser (zero CSP violations), not eyeball.

Plus: URL-validation unit tests (scheme/host/userinfo/port tricks, unicode confusables rejected by
ASCII-only, `.`/`..`, casing → one casefolded cache key, encoded slashes, duplicate params) ·
quota tests (429 behavior; atomicity under parallel fire; fail-closed on Upstash error; spoofed
`X-Forwarded-For` ignored) · single-flight + active-lease parallel-load test (active scans never
exceed the cap) · error-hygiene tests (no paths/traces in any response) · MIME/rewrite tests
(exact content-types on every status incl. errors; anchored rewrite; extra segments 404) ·
cross-request isolation test (two repos, unique markers never cross) · deployment-protection
assertion (unauthenticated request → denied) · upstream acceptance matrix (T11) ·
`vercel dev` smoke · the synthetic control scanned through the URL surface.

## Milestones & gates

- **3.1 — spec + codex gate.** Round 1 returned REVISE (21 findings); this v2 resolves them.
  **Round 2 re-review before any build code; converge to APPROVE(-WITH-CHANGES).**
- **3.2a — runtime probe, protected** (codex #20): a minimal **Deployment-Protection-enabled**
  deploy that imports every pinned wheel, parses one fixture, spawns and kills a hanging worker
  subprocess, exercises `/tmp`, confirms `fluid: false` + explicit memory/`maxDuration`, and runs
  the T11 upstream matrix. No public endpoint, no UI. Kill criterion: probe fails ⇒ fallback.
- **3.2b — scan core, local**: `scan.py` walker factor-out + `hosted/` fetch/streamed-extract/
  limits/worker, TDD against the adversarial fixtures. No network in tests.
- **3.3 — web surface, local**: handler contract + static pages/assets + quotas + XSS/CSP/MIME
  tests; `vercel dev` smoke.
- **3.4 — gated deploy**: protected preview (protection asserted) → deployed-surface test suite →
  **full `/cso` review** → fix findings → **operator approval** → WAF rule + spend caps confirmed
  (codex #18) → public alias + README link.

## Fallback (pre-committed)

If the probe fails, the review fails, or the clock runs out: ship the CLI + a hosted **static demo
of pre-scanned reports** (no user input = no attack surface) and defer live scan-by-URL. This path
is always green — and it already satisfies the ephemeral-results policy trivially.

## Open questions

- Vercel function memory/duration tier for worst-case scans — measured at 3.2a/3.4; plan's fork
  trigger: >30 % of scans hitting limits → job queue behind the same front.
- Upstash ACL token availability on the current plan — checked when provisioning; if unavailable,
  the default token is treated as a T7 residual escalation for `/cso` to judge.

## Appendix — codex round-1 resolution map

| Finding | Resolution |
|---|---|
| 1 parser containment | T4 two-tier: ts timeout + killable worker; fail-never-cache |
| 2 cross-request state | `fluid: false`, per-request instances, concurrent test (Arch, Decision 6) |
| 3 output amplification | T12 caps + partial marking |
| 4 secret in worker | Negotiated: env-scrubbed worker + ACL token; residual in T7 (Decision 7) |
| 5 silent partial coverage | T13 coverage manifest; suffix fix routed as its own eval-gated change |
| 6 disclosure invariant | §Result policy: ephemeral, click-to-run, no-store (Decision 5) |
| 7 cache retention | TTL 24 h, revalidate-public, schema freeze, token-never-in-JSON test, purge path |
| 8 identifier grammar | T1: one parser, fullmatch, `.`/`..` excluded, casefolded keys |
| 9 codeload assumptions | T11 fail-closed + upstream acceptance matrix at 3.2a |
| 10 data_filter gaps | T3 stricter wrapper: dirs + regular files only; lstat walker |
| 11 gzip accounting | T2 streamed counted reader, no getmembers, abort-on-oversize |
| 12 CSP delivery | T5: header-delivered via vercel.json, external assets, XFO fallback |
| 13 rewrite/MIME | Handler contract + MIME/rewrite tests; bidi/control rendering note in T5 |
| 14 GET amplification | POST + custom header + Fetch Metadata + no CORS (T6); click-to-run |
| 15 cache order/atomicity | Normative flow: cache-before-quota; atomic Lua admission |
| 16 concurrency control | Active-scan lease + per-repo single-flight, TTL'd (T6) |
| 17 IP derivation | `x-vercel-forwarded-for` only, `ipaddress` parse, /64, fail closed (T6) |
| 18 post-cap spend | WAF + spend management as 3.4 acceptance criteria (T6 residual) |
| 19 stdlib contract | §Interface handler contract; proxy-blind no-redirect opener (T1) |
| 20 crux ordering | 3.2a runtime probe before build |
| 21 preview enforceability | Deployment Protection required + asserted from the first deploy |
