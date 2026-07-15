---
type: index
title: "credlens — ADRs"
created_date: 2026-07-14
last_modified: 2026-07-14 20:20 PDT
---

# adr/

- [0001-tree-sitter-engine.md](0001-tree-sitter-engine.md) — tree-sitter parsing spine, with a
  pre-committed fork trigger to semgrep-CE taint mode.
- [0002-finding-vs-inventory.md](0002-finding-vs-inventory.md) — findings are precision-gated
  assertions; inventory is factual permission surface.
- [0003-hosted-output-publication-semantics.md](0003-hosted-output-publication-semantics.md) —
  on-demand ephemeral scan output is tool output; anything servable without a fresh admitted
  request is publication, bound by invariant 5.
