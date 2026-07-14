---
type: guide
title: "credlens — repo conventions"
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
---

# credlens — repo conventions

Precision-first, eval-backed security auditor for MCP servers, leading with the
credential / least-privilege lens. Plan: [docs/plan/plan.md](docs/plan/plan.md).
Current state: [docs/status/HANDOFF.md](docs/status/HANDOFF.md).

> **📌 Documentation standard — OKF (applies to ALL tools, skills, and agents).** Any documentation
> written in this repo MUST follow OKF and live under `docs/`. This binds **every** tool/skill/agent that
> writes docs here — **every** skill, agent, and doc generator (plan/ADR/PRD/spec/status/design) and any
> future tooling. Do **not** write plan/spec/ADR/status/design docs as plain markdown in default
> locations; route them into `docs/` in OKF — correct bundle, `type` frontmatter, `index.md` per bundle,
> standard Markdown links, Pacific `last_modified` (run `date`).

## Invariants (binding — do not relax without an ADR)

1. **Eval integrity.** Never change corpus labels and detector code in the same change. Label edits
   carry a human-readable justification in the commit message. This is "never modify a test to make
   it pass," projected onto evals. CI enforces it on PRs (`eval-integrity` job).
2. **Deterministic scan path.** The scan path makes no LLM calls and no network calls, and never
   executes target code — parse-only static analysis. LLM-assisted triage is a post-v1 idea only,
   and never inside the scan path.
3. **Precision first.** A `finding` asserts misbehavior and is precision-gated. A factual
   capability/permission surface is `inventory`, reported as least-privilege review material — never
   counted as a true/false positive. When a check can't clear the precision bar, demote it to
   inventory rather than shipping noise.
4. **Stated limitations.** Known-miss classes are documented in the README and reports. For a
   security audience, a stated limitation is credibility; a discovered one is disqualification.
5. **Publication hygiene.** Everything in this repo derives from public sources or this repo's own
   scans. No employer-derived content. Named findings about real projects follow the disclosure
   policy in the plan — never published unverified or inside a disclosure window.

## Priority stack (when cutting, cut from the bottom)

1. Evals harness (corpus + metrics + CI gate)
2. Credential/least-priv lens clearing the false-positive target
3. Launch post #1 draft (no build dependency)
4. Minimal hosted scan-by-URL
5. Ecosystem scan + data-story post
6. Table-stakes lens breadth (poisoning/injection/traversal beyond the POC)
7. Polish, docs beyond README, extra output formats

## Verification

- `uv run pytest` — tests (narrowest relevant check after meaningful changes)
- `uv run ruff check .` — lint
- `make eval` — eval harness (lands in Phase 1; becomes the CI release floor)
- gitleaks runs as a pre-commit hook and in CI (`secrets` workflow) — never bypass it

## Working agreements

- Solo repo, pre-v1: direct commits to `main` are fine; CI must stay green at every push — the repo
  is presentable at every milestone boundary by design.
- Corpus label edits are always their own commit (see invariant 1).
- Tests and fixtures are written in a separate context from detector implementation, so fixtures
  don't mirror detector bugs.
- **Planted secrets in fixtures are defanged twice:** obviously fake to a human, AND failing
  GitHub push protection's validators (wrong length or checksum) so pushes aren't blocked — while
  still matching the shape rules credlens defines. Fixture paths are allowlisted in
  `.gitleaks.toml`; never widen that allowlist to real source or config.
- Durable build state lives in [docs/status/](docs/status/index.md) (OKF `type: status`) — a
  deliberate per-repo override of any global `agent/` convention.
