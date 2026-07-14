# credlens

**Precision-first, eval-backed security auditor for MCP servers — leading with the credential and
least-privilege lens.**

> 🚧 **Building in the open.** Day-one repo, working toward a v1 that launches alongside a
> *State of MCP Server Security* report. Roadmap: [docs/plan/plan.md](docs/plan/plan.md).

## Why another MCP security tool?

MCP scanners exist — and most chase breadth. Two things stay underserved:

1. **The credential / least-privilege dimension.** How servers *handle secrets* (env reads flowing
   into logs, responses, and outbound requests) and how much *permission surface* they expose
   (filesystem roots, exec, network reach, OAuth scopes) gets far less attention than tool-poisoning
   pattern matching.
2. **Precision you can trust.** Naïve heuristics drown reviewers in false positives — a proof-of-concept
   scan of the reference MCP servers showed every credential-leak "hit" on real servers was a false
   positive (details: [docs/research/poc-result.md](docs/research/poc-result.md)). Telling *"logs the
   variable's name in an error message"* apart from *"logs the secret's value"* takes real
   AST + taint analysis, not proximity heuristics.

credlens is built evals-first: a labeled corpus and a precision/recall harness exist *before* the
detectors they measure, and CI fails on any regression below the last release's floor.

## Design principles

- **Evals before detectors.** The measuring instrument is the spine of the project, not an afterthought.
- **Findings vs inventory.** A `finding` asserts misbehavior and is precision-gated. An `inventory`
  entry states a factual capability/permission surface for least-privilege review. The two are never mixed.
- **Deterministic scan path.** Parse-only static analysis — no LLM calls, no network, target code is
  never executed.
- **Stated limitations.** Known-miss classes (e.g. cross-module dataflow in v1) are documented, not
  discovered.

## Status

Phase 0 (scaffold) — nothing to run yet. Next: the evals harness (corpus manifest, hand-adjudicated
labels, mutation corpus, CI gate), then the credential/least-privilege lens built against it.

```sh
# dev setup
uv sync
uv run pytest
```

## License

[Apache-2.0](LICENSE)
