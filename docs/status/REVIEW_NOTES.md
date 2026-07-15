---
type: status
title: "credlens — review notes"
created_date: 2026-07-14
last_modified: 2026-07-14 20:42 PDT
---

# Review notes

## 2026-07-14 · Codex adversarial round 1 — hosted-scan spec (Phase 3, pre-build gate)

Verdict **REVISE**, 21 findings (9 blocking, 12 should-fix) — all accepted; one fix negotiated
(secretless-worker deployment → env-scrubbed killable subprocess + ACL-scoped Upstash token,
residual documented in T7 for the `/cso` gate). Highest-value catches: `tarfile` `data_filter`
permits internal sym/hardlinks (hardlink-farm size-accounting bypass) · gzip-bomb accounting must
sit at the decompression boundary (`getmembers()` decompresses everything; skip-and-continue still
decompresses) · a shareable unverified-findings page violates CLAUDE.md invariant 5 → reshaped to
ephemeral click-to-run results · native parser crash can't be `try/except`-contained → killable
worker subprocess · GET scan endpoint = cross-site amplification → POST + Fetch Metadata ·
"preview, not public" unenforceable without Vercel Deployment Protection. Full resolution map:
[../specs/hosted-scan.md](../specs/hosted-scan.md) appendix. Spec v2 incorporated all 21.
Review log: codex job `task-mrlgxg9z-ayyn3c` (BENDER workspace state).

## 2026-07-14 · Codex adversarial round 2 — hosted-scan spec v2 (convergence pass)

Verdict **REVISE**: 12/21 round-1 resolutions verified RESOLVED, 9 PARTIAL (mechanisms/numbers
missing, not direction), 8 new findings (2 blocking), and the negotiated worker isolation judged
**acceptable-for-v1** conditional on a genuinely ACL-scoped Upstash token (default token may never
back a public launch) + parent-boundary hardening. Highest-value catches: cache hits evaded all
abuse controls (request-level admission now precedes any cache/revalidation work) · nothing
bounded what the worker or Redis returned to the parent (length-prefixed 2 MiB frames +
schema-validate-before-use) · the per-file parser timeout had no enforceable mechanism (worker
progress stream + 5 s stall kill) · "no secret material structurally" was false — least-priv
messages embed raw repo values (hosted redaction boundary) · the plan itself still required the
forbidden "shareable findings page" (plan amended; publication semantics formalized as
[ADR-0003](../adr/0003-hosted-output-publication-semantics.md)). Spec v3 absorbs all; round 3
convergence pending. Review log: codex job `task-mrlhs1ez-wy8omd`.

## 2026-07-14 · Codex adversarial round 3 — hosted-scan spec v3 (final convergence)

Verdict **APPROVE-WITH-CHANGES** — the 3.1 gate is **CLOSED** (converged in 3 rounds:
21 → 9 partial + 8 new → 0 blocking). Round 3 verified 13/17 checked items RESOLVED; ADR-0003's
reasoning confirmed consistent with invariant 5 and the amended plan. Remaining 7 should-fix +
2 nits all folded as spec v3.1: one atomic Lua admission transition (leader/follower/busy/
rate_limited — kills the quota/lease TOCTOU) · redaction-last response assembly with
service-metadata exemption · a single status→error matrix shared by T11 and the handler ·
coverage manifest on success responses only (whole-scan failure = `scan_failed` envelope) ·
output caps bind the combined findings+inventory population · full `Bidi_Control` escape set +
embedding-control fixture · `hosted-scan-schema.json` as 3.2b's first deliverable · plan.md
clone-era residuals replaced · ADR-0003 cross-ref fixed. Build (3.2a runtime probe onward) may
proceed; the `/cso` + operator-approval gates at 3.4 stand. Review log: codex job
`task-mrliits7-h7lpgu`.

Standing gates:

- **Security review of the hosted scan-by-URL deploy** before it goes public (Phase 3) — findings
  land here.
- **Data-claims review of the ecosystem-scan report** before publication (Phase 4) — every number
  cite-or-cut.
