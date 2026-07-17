---
type: positioning
title: "credlens — positioning, competition & claims to retire"
status: active
created_date: 2026-07-17
last_modified: 2026-07-17 12:49 PDT
tags: [positioning, competition, narrative, honesty, pitch]
---

# Positioning, competition & claims to retire

Honest competitive map for credlens, written to keep the public narrative (blog posts, FDE pitch,
README) inside invariant 4 (*a stated limitation is credibility; a discovered one is
disqualification*) and invariant 5 (*publication hygiene*). Prompted by a "does this fill a real
gap?" pressure-test on 2026-07-17.

> **Volatile-world content.** The competitive landscape moves fast. Named tools, versions, and
> acquisitions below are bound **as of 2026-07-17** and must be re-verified before they go into a
> published post. Treat this as a signal to re-check, not a durable fact.

## Bottom line (the one-paragraph honest pitch)

credlens is **not** the first tool to scan MCP servers, and its taint engine is **not** a novel
contribution to program analysis. It is an **MCP-literate, precision-first credential /
least-privilege lens with a reproducible eval story** — a portfolio-grade demonstration of
precision-first, eval-backed security engineering on a live, messy domain. Its one *demonstrable*
edge over general-purpose SAST is a **domain judgment those tools get wrong**: a server sending its
own API key to its own API is legitimate auth, not a leak (ADR-0002 → `inventory`, not `finding`).

## The competitive landscape (three layers)

### Layer 1 — Claude Code / the LLM host: genuine gap
Claude Code ships **no** built-in taint analysis, **no** default hardcoded-secret detection (only
user-configured substring patterns in the security-guidance plugin), and — explicitly — **no**
MCP-server source auditing. Anthropic's own docs: *"…does not security-audit or manage any MCP
server."* `/security-review` is an LLM pass over *your own* branch diff, not a reproducible audit of
a *third-party* server. So versus the harness, the gap is clean. *(Sources: Claude Code docs —
security.md, security-guidance.md, as of 2026-07-17.)*

### Layer 2 — dedicated MCP scanners: they exist, on a different axis
Dedicated MCP security scanners **predate credlens**. The category leader is **MCP-Scan** (Invariant
Labs, ETH Zurich spinout; **acquired by Snyk June 2025**, now *Snyk Agent Scan*), plus academic tools
and CLIs (Golf Scanner, etc.). **But** their axis is **configuration and tool-metadata**: prompt
injection, tool-poisoning descriptions, rug-pull detection (hashing tool descriptions over time),
allowlists / trusted-tool pinning. They largely do **not** do **source-code credential-taint** of the
server implementation — which is credlens's lens. Different axis, adjacent problem.
*(Sources: appsecsanta.com/mcp-scan, practical-devsecops.com MCP tools, as of 2026-07-17.)*

### Layer 3 — general-purpose SAST: already does the taint, more thoroughly
Secret-value → sink dataflow is **generic SAST territory, not MCP-specific**. **Semgrep, CodeQL,
Checkmarx, SonarQube** all ship taint engines with these queries — CodeQL's *"clear-text logging of
sensitive information"* (CWE-312/532) is a canonical, years-old query — and they do it **more
thoroughly than credlens v1** (interprocedural + cross-file, vs. credlens's intra-file-only
`cross-function-hop` known-miss). credlens concedes this by design: **ADR-0001 says the engine is
deliberately swappable and the moat is the evals + data story**, not the taint code.

## Claims to RETIRE (would not survive an informed reader)

Two claims in the current narrative are false or stale. **Do not publish them.**

1. ❌ **"As of mid-2025 there are no dedicated MCP security tools."**
   (appears in `docs/research/poc-result.md` provenance / early framing) — **false**: MCP-Scan/Snyk
   Agent Scan existed and was acquired by Snyk in June 2025. Correct framing: *"the config/metadata
   axis is served (MCP-Scan → Snyk); the source-code credential-taint axis is under-served."*
2. ❌ **"Novel taint analysis" / "credlens's engine is the innovation."**
   — **false**, and contradicted by our own ADR-0001. Never pitch the engine as the contribution.
   The contribution is the **evals + corpus + domain-tuned precision**.

## Claims that HOLD (defensible, and demo-able)

1. ✅ **MCP-domain-tuned precision — the false positive generic SAST makes and credlens doesn't.**
   Point Checkmarx/CodeQL at a real MCP server and secret→outbound reads as a leak; credlens knows
   that in MCP context it is usually the key's *intended* auth use and demotes it to `inventory`
   (ADR-0002). This is the single most convincing live demo: **same code, generic-SAST false alarm,
   credlens quiet.** *(Verify with a concrete side-by-side before citing it as the headline.)*
2. ✅ **The methodology is the product.** A labeled 22-server MCP corpus, a ~198-instance mutation
   harness, adjudicated ground truth, reproducible precision/recall, and a CI eval gate — a
   *security-evaluation artifact* the config scanners don't publish.
3. ✅ **MCP-specific least-privilege inventory** (OAuth scope breadth, transport auth, confused-deputy)
   — domain framing, not generic taint.
4. ✅ **Zero-config, MCP-literate, third-party-audit posture** — point it at any MCP server repo and
   get an MCP-aware read, vs. authoring Checkmarx/Semgrep rules.

## How to say it (for README / blog / interview)

- **Lead with:** *"MCP-literate, precision-first credential & least-privilege lens, backed by a
  reproducible eval harness."*
- **Never claim:** first-to-scan-MCP, or novel taint analysis.
- **The headline demo:** the auth-vs-exfil `inventory` call — the domain judgment general SAST lacks.
- **The purpose frame (for the FDE pitch):** credlens exists to *demonstrate precision-first,
  eval-backed security engineering*, not to unseat Snyk or Checkmarx. Judge it as a portfolio proof,
  and the bar is rigor and honesty — both of which this doc is part of clearing.

## Open verification before publishing
- [ ] Build the concrete **generic-SAST-vs-credlens side-by-side** on one real server (e.g. run a
      Semgrep/CodeQL secret-in-request rule vs credlens on gitlab/github server) to substantiate
      claim #1 with receipts, not assertion.
- [ ] Re-verify the MCP-scanner landscape (MCP-Scan/Snyk feature set) at publish time — moves fast.
- [ ] Scrub `poc-result.md` and any draft posts for the retired "no MCP tools" claim.
