---
type: spec
title: "Hosted scan-by-URL (Phase 3)"
status: active
created_date: 2026-07-14
last_modified: 2026-07-14 19:32 PDT
tags: [mcp, security, deploy, vercel, threat-model]
---

# Hosted scan-by-URL — spec & threat model

Phase 3 of [the plan](../plan/plan.md): a minimal public surface — GitHub repo URL in → parse-only
scan → shareable findings page. **This tool audits other people's security; its own surface is the
first thing a security-literate audience will probe.** The threat model below was written before any
build code, and every mitigation in it is an acceptance criterion.

## Goal & acceptance criteria

- A public GitHub repo URL produces a shareable findings page (findings + least-priv inventory).
- The synthetic control scans end-to-end through the URL surface (plan verification path).
- Every adversarial fixture in §Verification is handled safely (rejected or rendered inert).
- Scan path stays deterministic: **no LLM calls, no target-code execution** (CLAUDE.md invariant 2).
- **No public exposure before the security-review gate passes** (fallback: static demo).

## Non-goals (v1)

Accounts/auth · scan history UI · non-GitHub hosts · private repos · monorepo special-casing ·
LLM triage · re-scan scheduling · badges/API for third parties.

## Architecture

**Runtime: Python on Vercel serverless, reusing the existing detectors as-is.** The plan sketched
"wasm tree-sitter" assuming a JS runtime; running the *Python* package directly is strictly better —
one source of truth for detection logic, the eval numbers apply verbatim to the hosted scan.
tree-sitter grammar wheels are manylinux binaries and should install on Vercel's Python runtime;
this is the one feasibility crux, verified at preview-deploy time (fallback in §Fallback).

**Fetch: GitHub tarball, never `git clone`.** The scanner downloads
`https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD` — a URL **constructed from validated
components, never from the user's string**. This kills the whole git attack class structurally: no
git binary, no `git://`/`file://`/ssh schemes, no `.git` config/hook tricks, no submodule surface.
Unauthenticated codeload reaches public repos only → private repos are unreachable by construction,
and **no GitHub token exists in the scan path**.

Request flow:

```
user URL → strict parse (owner/repo regex) → rate limit (per-IP + global)
  → cache check (Upstash, key = owner/repo)
  → codeload fetch (host pinned, redirects refused, streamed with byte cap)
  → safe extract (tarfile filter="data", count/size caps, tmpdir jail)
  → scan_tree (shared walker, per-file isolation + caps, wall-clock budget)
  → findings JSON → cache put (TTL) → static page renders via textContent only
```

Components:

- `api/scan.py` — the single dynamic endpoint (stdlib-only handler).
- `web/index.html`, `web/scan.html` — static landing + findings page; `/scan/{owner}/{repo}`
  rewrites to `scan.html` (vercel.json), which fetches the JSON and renders client-side.
- `src/credlens/scan.py` — shared tree walker factored out of `credlens.eval._run_detector`
  (pure refactor; detector code and labels untouched — eval-integrity invariant holds).
- `src/credlens/hosted/` — fetch + safe-extract + limits, unit-testable without any network
  (fetcher injected; adversarial tarballs are local fixtures).

## Threat model

Written first, per the plan. Every row is binding: a mitigation here is a test or a config, not a hope.

| # | Threat | Vector | Mitigation | Residual |
|---|--------|--------|------------|----------|
| T1 | SSRF | `git://`, `file://`, redirects, internal hosts via crafted URL | The user string is **parsed, never fetched**: regex-validated `owner` `[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})`, `repo` `[A-Za-z0-9._-]{1,100}`; fetch URL rebuilt from components; host pinned to `codeload.github.com`; **redirects refused** (a 3xx is a failure); https only | None known — the fetcher can only ever address codeload |
| T2 | Resource bombs | gzip bomb, monster repo, 10⁶-file tree | Streamed download aborts over **30 MB compressed**; extraction caps: **100 MB total, 5 000 files, 1 MB/file** (over-cap file = skipped, noted in report); `tarfile` `filter="data"`; **45 s scan wall-clock**, function max-duration backstop | Burst CPU within one invocation, bounded by timeout |
| T3 | Path traversal / symlink escape | hostile tar member paths, symlink/hardlink members | Python 3.12 `tarfile` **`filter="data"`** rejects absolute paths, `..`, symlinks, hardlinks, devices; extraction into per-request tmpdir; walker additionally skips symlinks (`is_symlink()` guard) | None known; adversarial fixtures prove it |
| T4 | Parser DoS / crash | pathological source files | Per-file `try/except` (a crashing file = "skipped" note, scan continues); 1 MB/file parse cap; overall wall-clock budget; **parse-only — target code never executes** | Unknown tree-sitter crash class → contained to one file |
| T5 | **Stored XSS in findings page** | rendered strings originate in the scanned repo (paths, names, snippets — literally the payloads this tool hunts) | Findings travel as **JSON only** (`application/json`, `nosniff`); page renders **exclusively via `textContent`** — no `innerHTML` anywhere; **CSP:** `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`; no server-side HTML assembly from findings | XSS requires both a renderer bug **and** a CSP bypass |
| T6 | Abuse / cost DoS | scripted scan floods | Per-IP **10 scans/h** + global **200 scans/day** (Upstash counters); cache (TTL 7 d) makes repeat views free; over-cap → 429, cached results still served | Distributed abuse exhausts the global cap → degrades to cached-only for the day; acceptable |
| T7 | Secrets in scan path | hostile input near credentials | Scan env holds **one** secret: the Upstash REST token (single cache DB, rotateable). No GitHub token (codeload is unauthenticated), no LLM keys (invariant 2). Parse-only ⇒ hostile content has no execution channel to reach even that | Upstash token theft needs an RCE in *our* stack; blast radius = one cache DB |
| T8 | Info disclosure | stack traces, tmp paths, env in errors | Generic terse errors (400/404/413/429/500 + short code); detail goes to server logs only | — |
| T9 | Content spoofing / phishing | attacker-authored strings shown to visitors | Fixed page chrome states the scanned repo + "strings below derive from the scanned repository"; findings content is never linkified; the only outbound link is `github.com/{owner}/{repo}` rebuilt from validated components | Screenshot-based spoofing — out of scope |
| T10 | Cache poisoning / staleness | shared shareable URLs serving wrong content | Cache key = `owner/repo`; value records the tarball's sha256 + scan time, displayed on the page ("scanned <time>, content digest <short>"); TTL 7 d bounds staleness | A push right after a scan shows ≤7 d-old results — displayed, honest |
| T11 | Renamed/moved repos | codeload 3xx on renames | Redirects refused → clean 404-style "repo not found"; user rescans under the new name | — |

Supply-chain posture: the web surface adds **zero new runtime dependencies** — stdlib `urllib`
(fetch + Upstash REST), `tarfile`, `re`, `json`. Vercel build installs the existing pinned deps via
`uv export`-generated hashed requirements.

## Interface & limits

| Route | What |
|---|---|
| `GET /` | static landing: input form, methodology blurb, limitations |
| `GET /api/scan?repo={owner}/{repo}` | validate → rate-limit → cached-or-fresh scan → findings JSON |
| `GET /scan/{owner}/{repo}` | static findings page (fetches the JSON client-side) |

Limits (also displayed on the landing page — stated limitations are credibility):
30 MB tarball · 100 MB extracted · 5 000 files · 1 MB/file · 45 s scan · 10 scans/h/IP ·
200 scans/day global · cache TTL 7 d · public GitHub repos only.

## Decisions

1. **Tarball over clone** — kills the git attack class structurally; no git binary on serverless;
   size-cappable stream; private repos unreachable by construction.
2. **Python runtime reusing the detectors** — no TS port; the published eval numbers describe
   exactly the code that runs hosted.
3. **Stdlib-only web layer** — two endpoints don't justify FastAPI's dependency tree on a
   hostile-input surface; validation is three regexes. (Open to reversal at codex review.)
4. **Upstash Redis via REST** for rate-limit + cache — already-approved integration, no client lib.
   Missing env ⇒ the deploy stays preview-only; per-IP limiting on serverless requires shared state.
5. **Share URL pins name, not SHA** — `/scan/{owner}/{repo}` re-serves the cached scan (digest +
   time displayed). Simple, honest, and the URL survives pushes.

## Verification (before the phase is "done")

Adversarial fixtures, built in an isolated context like all fixtures (working agreement):
traversal tar (`../escape`) · absolute-path tar · symlink-escape tar · hardlink tar · gzip bomb ·
6 000-file tar · >1 MB file · crash-shaped source file · **repo whose strings are XSS payloads**
(`<img onerror>` in env names, tool descriptions, file paths) — page must render them inert
(asserted via DOM, not eyeball).

Plus: unit tests for URL validation (scheme/host/userinfo tricks, unicode confusables, `..`),
rate-limit behavior (429 + cached-still-served), error hygiene (no paths/traces in responses);
`vercel dev` smoke of the full flow; the synthetic control scanned through the URL surface.

## Milestones & gates

- **3.1 — this spec** → **codex gate** on the spec before any build code (Tier 2).
- **3.2 — scan core, local**: `scan.py` walker factor-out + `hosted/` fetch/extract/limits, TDD
  against the adversarial fixtures. No network in tests.
- **3.3 — web surface, local**: handler + static pages + rate limiting + XSS fixture test;
  `vercel dev` smoke.
- **3.4 — deploy**: preview deployment (**not public**) → confirm tree-sitter wheels on the Vercel
  runtime → **full `/cso` review of the deployed surface** → fix findings → **operator approval**
  → public alias + README link.

## Fallback (pre-committed)

If the wheels don't run on Vercel, the review fails, or the clock runs out: ship the CLI + a hosted
**static demo of pre-scanned reports** (no user input = no attack surface) and defer live
scan-by-URL. This path is always green.

## Open questions

- Vercel function memory/duration tier needed for worst-case scans (measure at 3.4; fork trigger
  in the plan: >30 % of scans hitting limits → job queue behind the same front).
- Whether `/api/scan` should also accept full `https://github.com/owner/repo` URLs pasted verbatim
  (default: yes, parsed by the same strict regex after a literal-prefix check).
