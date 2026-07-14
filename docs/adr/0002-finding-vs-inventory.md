---
type: adr
title: "ADR-0002 — finding vs inventory"
status: accepted
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
---

# ADR-0002 — finding vs inventory

## Context

Static scanners of MCP servers face an adjudication problem: is an SSRF-capable fetch surface a
"vulnerability"? Counting factual capability surfaces as findings inflates severity and produces the
false-positive noise that makes reviewers distrust the tool.

## Decision

Two disjoint output classes:

- **`finding`** — an asserted misbehavior (e.g. a secret *value* flowing to a log sink). Precision-
  gated: only confidence tiers that clear the precision target ship as findings; everything else is
  demoted.
- **`inventory`** — a factual capability/permission surface (SSRF-capable fetch, broad filesystem
  root, exec surface, OAuth scope breadth), reported as least-privilege review material. Never
  counted as a true/false positive.

## Consequences

- The precision target becomes achievable by construction while staying honest — and the output
  matches how a real security reviewer consumes it.
- Checks that can't clear the precision bar have a dignified fallback (inventory demotion) instead
  of shipping as noise or being silently deleted.
