---
type: index
title: "credlens — research"
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
---

# research/

The validation work that seeded this project (2026-07-03).

- [poc-result.md](poc-result.md) — the throwaway proof-of-concept: a heuristic scanner vs 21 real
  reference MCP servers + 1 synthetic control. Its headline lesson — every credential-leak "hit" on
  real servers was a false positive — is the reason credlens is precision-first.
- [poc/](poc/) — the POC artifacts, kept as provenance and corpus seed:
  [scanner.py](poc/scanner.py) (the naïve heuristic scanner — deliberately throwaway),
  [findings.json](poc/findings.json) (60 findings across the 22-server corpus — the seed of
  `corpus/labels.json`), and
  [synthetic-control/evil-weather-mcp.ts](poc/synthetic-control/evil-weather-mcp.ts) (a clearly
  labeled malicious server used as a positive control).
