---
type: status
title: "credlens — review notes"
created_date: 2026-07-14
last_modified: 2026-07-14 19:58 PDT
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
[../specs/hosted-scan.md](../specs/hosted-scan.md) appendix. Spec v2 incorporates all 21; round 2
convergence pass pending. Review log: codex job `task-mrlgxg9z-ayyn3c` (BENDER workspace state).

Standing gates:

- **Security review of the hosted scan-by-URL deploy** before it goes public (Phase 3) — findings
  land here.
- **Data-claims review of the ecosystem-scan report** before publication (Phase 4) — every number
  cite-or-cut.
