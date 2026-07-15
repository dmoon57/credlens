---
type: status
title: "credlens — review notes"
created_date: 2026-07-14
last_modified: 2026-07-14 20:20 PDT
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

Verdict **REVISE**: 12/21 round-1 resolutions verified RESOLVED, 8 PARTIAL (mechanisms/numbers
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

Standing gates:

- **Security review of the hosted scan-by-URL deploy** before it goes public (Phase 3) — findings
  land here.
- **Data-claims review of the ecosystem-scan report** before publication (Phase 4) — every number
  cite-or-cut.
