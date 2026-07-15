---
type: adr
title: "ADR-0001 — tree-sitter parsing spine, with a pre-committed fork to semgrep-CE taint"
status: accepted
created_date: 2026-07-14
last_modified: 2026-07-14 15:09 PDT
---

# ADR-0001 — tree-sitter parsing spine, with a pre-committed fork to semgrep-CE taint

## Context

The credential lens needs real dataflow — the proof-of-concept proved proximity heuristics produce
100% false positives on real servers' credential handling. Candidate engines: tree-sitter (uniform
multi-language syntax, no types/dataflow out of the box) vs semgrep-CE taint mode (dataflow
built in, heavier dependency and rule-DSL coupling).

## Decision

Start on **tree-sitter** (typescript/javascript/python grammars). v1 taint is **intra-file def-use**
built on scopes and assignments.

**Pre-committed fork trigger:** if the four named false-positive classes
([plan §Phase 2](../plan/plan.md)) are not cleanly killed after **~2 days** of tree-sitter taint
work, switch the engine to **semgrep-CE taint mode** and keep every other layer — corpus, labels,
metrics, report, deploy — unchanged. The fork does not extend the deadline, and the decision is not
relitigated after the trigger fires.

## Consequences

- The project's moat stays in the evals + data story; the engine is deliberately swappable.
- Cross-file/module taint is a documented known-miss class for v1, whichever engine wins.

## Outcome (2026-07-14)

The tree-sitter path **held** — the fork trigger did not fire. Intra-file def-use taint on
tree-sitter (ts/js) cleanly kills all four named FP classes (real-server precision 1.0) and clears
the intra-file recall target (holdout 0.9167), well inside the 2-day box. Interprocedural / instance-
field flows remain the documented v1 known-miss (the `cross-function-hop` class), as anticipated.
No semgrep migration needed for v1.
