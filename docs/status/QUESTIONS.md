---
type: status
title: "credlens — open questions"
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
---

# Open questions

- **Deploy target** — default Vercel (parse-only fits serverless wasm); fork to a job-queue worker
  if >30% of scans hit serverless limits. Operator may override before Phase 3.
- **Ecosystem-scan N + sources** — default N≈75, intersection of ≥2 of: official MCP registry,
  Smithery/PulseMCP, npm downloads. Inclusion criteria published with the report.
- **Disclosure contact identity** — dedicated security-report email to set up before the Phase 4
  scan runs; window policy default 30d config / 90d code.
- **Publish venue for the posts** — undecided; drafting is not blocked by the venue.
