---
type: adr
title: "ADR-0003 — publication semantics for hosted scan output"
status: accepted
created_date: 2026-07-14
last_modified: 2026-07-14 20:42 PDT
---

# ADR-0003 — publication semantics for hosted scan output

## Context

CLAUDE.md invariant 5: named findings about real projects are **never published unverified** or
inside a disclosure window. Phase 3 hosts a scan-by-URL service whose output names real
repositories. Two codex review rounds pressed the question: the original "shareable findings page"
plainly violates the invariant (round 1, finding 6), and even the revised design returns named,
unverified findings to any anonymous admitted POST (round 2) — so where exactly is the publication
line?

## Decision

**On-demand, ephemeral output delivered to the requester of an admitted scan is *tool output*, not
publication** — the same act as that person running the CLI locally against a public repo. The
service is a lens the requester points, not a statement credlens hosts.

**Publication is anything servable without a fresh admitted request**: a persistent page, a
GET-servable cached result, an archive, a feed. Published named findings remain bound by invariant
5 — verified first, disclosure-windowed.

Binding consequences for the hosted surface:

- Results render only in direct response to the requester's admitted `POST`, with
  `Cache-Control: no-store`, banner-marked *automated, unverified*.
- No GET route ever serves findings; share URLs are click-to-run pointers.
- The internal result cache is cost control: only ever served into an admitted POST response,
  TTL-bounded, never a stable artifact of record.
- Findings-bearing responses carry no secret material (hosted redaction boundary — spec
  §Result policy).
- If a hosted scan surfaces what appears to be a real critical in a named repo, the disclosure
  protocol (plan §Phase 4) governs any *publication* by us; the ephemeral response itself is the
  requester's tool output.

## Alternatives considered

- **Persistent shareable findings pages** (industry norm — SSL Labs, Mozilla Observatory serve
  named on-demand results and even cache them publicly): rejected; invariant 5 is deliberately
  stricter because credlens' findings assert misbehavior, not configuration grades.
- **Inventory-only / verified-only hosted output**: guts the phase (v1 has no verification
  workflow) — kept as the documented post-v1 upgrade path for *persistent* pages.
- **No hosted scan (static demo only)**: remains the pre-committed fallback, not the default.

## Consequences

Plan §Phase 3 wording updated from "shareable findings page" to the pointer/click-to-run model.
The spec's §Result policy implements this ADR; `/cso` re-examines the whole posture at the 3.4
gate. Revisit trigger: a verified-findings curation workflow shipping post-v1 may relax the
persistent-page prohibition for verified content only.
