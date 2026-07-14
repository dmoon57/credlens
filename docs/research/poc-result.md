---
type: poc-result
title: MCP security scanner — POC result
description: Throwaway POC settling the feasibility+signal crux — does a heuristic static scanner surface real, non-trivial findings on real MCP servers?
created_date: 2026-07-03
last_modified: 2026-07-14 15:09 PDT
tags: [spike, poc, mcp, security]
---

> Provenance: written 2026-07-03 as the result of the time-boxed validation spike that seeded
> credlens; copied here unchanged apart from this note. Artifacts: [poc/](poc/).

# POC result — does a heuristic MCP scanner find real things?

**Crux tested:** can a static, heuristic scanner surface *real, non-trivial* security findings on
*real* MCP servers, with low enough noise to be credible? **Answer: yes, with a sharp nuance that
turns out to be the whole differentiation story** (below).

## What was built (throwaway, cage)

- `scanner.py` — ~230 lines, **stdlib only** (no installs). Walks `.ts/.js/.py`, extracts tool
  `description` strings + code, runs checks across three lenses:
  - **A. Tool-description injection ("tool poisoning")** — imperative/secrecy phrases inside tool
    descriptions, hidden/bidi Unicode, over-long descriptions.
  - **B. Credential / secret handling** *(the differentiation lens)* — hardcoded secret patterns;
    env-var secret **value** taint-tracked to log/response sinks.
  - **C. Capability / permission over-scoping** — command exec, dynamic eval, outbound-fetch (SSRF)
    surface, string-built SQL, broad filesystem ops.
- `synthetic-control/evil-weather-mcp.ts` — a **hand-crafted malicious server** (clearly labeled
  synthetic) as a **positive control**: poisoned descriptions (`<important>…do not tell the user`),
  zero-width + RTL-override Unicode, a hardcoded `ghp_`/`xoxb-` token, and a `ping -c 1 ${host}`
  command-injection sink.

## Corpus

**22 servers:** the 21 real public reference servers from `modelcontextprotocol/servers` (fetch,
filesystem, git, memory, sequentialthinking, time, everything) + `servers-archived` (github,
gitlab, slack, gdrive, google-maps, brave-search, everart, postgres, sqlite, redis, puppeteer,
sentry, aws-kb) — plus the 1 synthetic control. Cloned read-only into an OS scratch cage; **not**
captured here (re-clonable, heavy).

## Results (v2, after two refinement passes)

```
TOTALS  critical=2  high=10  medium=34  low=14
by category: tool-poisoning=6  credential=6  capability=48
```

### ✅ True positives — detector design is sound
Every planted attack in the synthetic control fired: **2 critical** (hardcoded GitHub + Slack
tokens), **4 high** description-injection hits (`<important>`, "Before using any other tool",
"always call", "You must always"), the **zero-width-space** smuggling flag, and the **command-exec**
surface. A scanner *can* catch the canonical MCP attack classes statically.

### ✅ Capability inventory on real servers — genuinely useful
Correctly surfaced the real permission surface of real servers: **SSRF** surface in `brave-search`
and the fetch-style servers, **string-built SQL** in `filesystem`, **command-exec** surfaces, broad
**filesystem** ops. These aren't "bugs" — they're the least-privilege **inventory** a reviewer
wants, which is exactly the credential/permission lens's promise.

### ⚠️ The load-bearing lesson — the credential lens is where naïve heuristics BREAK
All **4** credential-leak "high" findings on the *real* servers are **false positives**, verified by
hand:
- `brave-search`, `gitlab` — local var is named identically to the env var
  (`const BRAVE_API_KEY = process.env.BRAVE_API_KEY`), and that **name appears as a string literal**
  in a `console.error("BRAVE_API_KEY … is required")` message. The value is never logged.
- `google-maps` — sink-window overshoot caught a nearby `return apiKey`, not an actual log of it.
- `gdrive` — flags a credential **path** var reaching a sink (low value, not a secret leak).

None of these servers actually leak secrets — they read from env and print the **variable name** in
"please set this" errors (good practice). Distinguishing "logs the name in a string" from "logs the
value" needs **AST + real taint/data-flow analysis**, not regex/name-proximity.

Two refinement passes measurably cut noise (test/example-file exclusion removed `filesystem`'s
false exec hits and dropped low-severity noise 70→14; value-variable taint cleared `slack`'s false
positive) — but also proved the ceiling of the regex approach on the credential dimension.

## What this settles

1. **Feasibility: settled — yes.** A useful scanner is buildable fast; a credible v1 across lenses
   A + C is days of work, stdlib-only, no exotic deps.
2. **Signal: settled — yes, and it points at the moat.** The *easy* checks (injection, capability
   inventory) work and are already partly served by others. The *hard, valuable, under-served* check
   is the **credential/secret-handling lens done with low false positives** — which demands real
   program analysis (AST + taint), not pattern proximity. That's the defensible wedge, and the
   POC is live proof that the naïve version everyone reaches for is too noisy to ship.
3. **The ecosystem-scan story is real.** In minutes, the POC produced a per-server severity table
   across 21 popular servers — the skeleton of the "I scanned the MCP ecosystem, here's what I
   found" writeup (blog post #2), once the checks are hardened past false positives.

## Honest limitations of the POC
- Regex/window extraction (not a real parser) — the source of the credential false positives; the
  real tool needs AST (tree-sitter / TS compiler API) + taint analysis.
- Tested TS-heavy corpus (reference servers are mostly TS); Python coverage is shallow.
- No runtime/dynamic checks (rug-pull detection, live tool-manifest diffing) — static only.
- The synthetic control is the only "known-bad"; real-world malicious servers may evade these
  specific patterns.

**Time spent:** within the standard-dial box (2 refinement attempts). Crux settled → stopped.
