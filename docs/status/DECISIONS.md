---
type: status
title: "credlens — decisions"
created_date: 2026-07-14
last_modified: 2026-07-14 19:58 PDT
---

# Decisions

- **2026-07-14 · Name: credlens.** Operator pick from a collision-checked shortlist (npm + PyPI free;
  no meaningful GitHub collision; distinct from mcp-scan, mcp-shield, mcp-audit, agent-scan,
  Ramparts, Proximity).
- **2026-07-14 · Public from day 1.** Building in the open; secret scanning wired in the root commit
  as the precondition.
- **2026-07-14 · Execution planning lives outside the repo.** [docs/plan/plan.md](../plan/plan.md)
  is the project's technical plan of record; the operator's fuller execution notes stay in a private
  planning space. Public docs carry everything needed to understand and reproduce the work.
- **2026-07-14 · License: Apache-2.0.** Patent grant suits security tooling; reversible pre-launch.
- **2026-07-14 · Engine: tree-sitter with a pre-committed semgrep fork trigger** — formalized as
  [ADR-0001](../adr/0001-tree-sitter-engine.md).
- **2026-07-14 · Finding vs inventory output classes** — formalized as
  [ADR-0002](../adr/0002-finding-vs-inventory.md).
- **2026-07-14 · Secret → outbound request is inventory in v1, not a finding.** Sending
  an API key to its own API is legitimate authentication (the gitlab/github reference
  servers do exactly this); flagging it destroys precision. Distinguishing auth from
  exfiltration needs destination-taint (caller-controlled host) — deferred to v2. The
  `secret-in-url/header/body` mutation classes are tagged `exfil_v2` and reported, not
  gated. This is the call that keeps real-server precision at 1.0. See
  [../specs/credential-lens.md](../specs/credential-lens.md).
- **2026-07-14 · v1 taint is intra-file, local-binding only.** Flows through instance
  fields (`this.secret`) or across function/method boundaries are documented known-misses
  (`interprocedural` scope, the `cross-function-hop` class + `aliased_class_method`
  fixture), reported not gated.
- **2026-07-14 · Hosted results are ephemeral; the share URL is a pointer, not an archive**
  (codex round 1, finding 6). A persistent GET-servable page of machine findings about a named
  repo is publication of unverified allegations — CLAUDE.md invariant 5 outranks the plan's
  "shareable findings page" phrasing. `/scan/{owner}/{repo}` renders a click-to-run card; results
  are `no-store`, banner-marked unverified; the internal cache is cost control only (POST-gated,
  TTL 24 h, revalidate-public before serve). Verified-findings curation is post-v1. See
  [../specs/hosted-scan.md](../specs/hosted-scan.md) §Result policy.
- **2026-07-14 · Hosted worker isolation: env-scrubbed subprocess, not a second deployment**
  (negotiated from codex finding 4). Extraction + parsing run in a killable subprocess with an
  empty environment; the parent holds the only secret (Upstash token, ACL-scoped to cache/quota
  keys). Residual — same-uid /proc reach from a native RCE — documented in the spec's T7 and
  re-examined at the `/cso` gate; fallback stands if rejected.
- **2026-07-14 · Hosted concurrency: `fluid: false` + per-request detector instances** (codex
  finding 2). The detectors mutate internal state during a scan; correctness before concurrency.
