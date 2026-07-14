---
type: status
title: "credlens — decisions"
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
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
