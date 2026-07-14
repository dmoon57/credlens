---
type: status
title: "credlens — risks"
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
---

# Risks

- **Corpus rot** — half the corpus comes from `servers-archived`; archived repos move or vanish.
  Mitigation: pinned SHAs + tarball mirrors on a release asset, same day the manifest is written.
- **Mutation-template overfit** — detectors score perfectly on planted attacks while meaning
  nothing. Signals: holdout ≫ real-server performance; detectors keying on planting artifacts.
  Mitigation: class-level holdout, varied idioms, no planting markers.
- **Engine dead-end** — tree-sitter taint can't kill the four FP classes. Pre-committed countermove:
  ADR-0001 fork to semgrep-CE taint, no deadline extension.
- **Hostile-input deploy surface** — SSRF via clone URLs, zip-bombs, symlink escapes, parser DoS,
  stored XSS from scanned repo strings (the tool renders its own threat class). Mitigation: threat
  model before build, security review gate before public, static-demo fallback.
- **A false-positive public accusation** — the credibility kill-shot for a precision-first tool.
  Mitigation: every named finding hand-verified; disclosure protocol; v1 report publishes aggregates
  and fixed criticals only.
- **Rabbit holes** — any single check consuming >1 day without moving eval numbers gets
  inventory-demoted and moved past.
