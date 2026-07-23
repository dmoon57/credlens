# credlens

**Precision-first, eval-backed security auditor for MCP servers — leading with the credential and
least-privilege lens.**

> 🚧 **Building in the open.** Working toward a v1 that launches alongside a *State of MCP Server
> Security* report. The scan engine and its evals harness work today; a public, point-it-at-your-repo
> surface is next. Roadmap: [docs/plan/plan.md](docs/plan/plan.md).

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

## What it actually does

credlens statically analyzes an MCP server's TypeScript / JavaScript / Python source and emits two
distinct kinds of result — never mixed:

- **Findings** — asserted misbehavior, precision-gated. The **credential lens** builds an intra-file
  def-use taint graph (tree-sitter) and reports only when a secret's *value* actually reaches a
  sink that leaks it — a log call, a file write, a subprocess argument. It taints value *bindings*,
  not name tokens, so `console.error("missing", "GITHUB_TOKEN")` (logs the name) does **not** fire
  while `console.error(process.env.GITHUB_TOKEN)` (logs the value) does. Aliasing, destructure-rename,
  and template/object/`JSON.stringify` propagation are tracked.
- **Inventory** — factual capability / permission surface for least-privilege review, never scored as
  a true/false positive. The **least-privilege lens** reports OAuth-scope breadth, network-exposed
  transports (SSE/HTTP), filesystem-write/delete/exec/eval/network capability, and token-passthrough
  (a *caller-controlled* `Authorization` value = confused-deputy risk, distinguished from a server
  sending its own configured token).

The scan path is **deterministic**: parse-only static analysis, no LLM calls, no network, and the
target's code is **never executed**. Known-miss classes (e.g. cross-module dataflow, outbound-request
exfil) are documented, not discovered.

A result looks like:

```text
FINDING    src/tools.ts:42   credential   secret value (GITHUB_TOKEN) reaches console.error()
INVENTORY  src/index.ts:10   capability   network-exposed transport (SSE)
INVENTORY  src/index.ts:31   capability   caller-controlled Authorization forwarded (confused-deputy)
```

## Measured, not asserted

The evals harness is the spine of the project. Against the pinned 22-server corpus + a
labeled-by-construction mutation corpus, the credential lens currently holds (CI floor,
`eval/floor.json`):

| Metric | Result | Target |
|---|---|---|
| Real-server credential precision | **1.0** (zero findings on reference servers) | ≥ 0.90 |
| Intra-file holdout recall | **0.9167** | ≥ 0.80 |
| Negative precision | **1.0** | — |
| Overall false-positive rate | **0.0** | < 0.20 |

CI fails on any regression below the recorded floor (`make eval-ci`), and the gate is proven
red-then-green on a deliberately planted regression. Methodology and honest limitations:
[docs/specs/credential-lens.md](docs/specs/credential-lens.md).

## Status

Phases 0–2 complete (evals harness + credential/least-privilege lens beating the false-positive
target). Phase 3 — hosted **scan-by-URL** — is in progress: the full local pipeline
(fetch → extract → scan → redact) is built and adversarially tested behind a security-review gate; the
public web surface is the remaining work. Detailed state:
[docs/status/HANDOFF.md](docs/status/HANDOFF.md).

## Try it (dev)

There is **no end-user install yet** — no published package and no `credlens scan <dir>` CLI (both are
[on the roadmap](docs/plan/plan.md#future--post-v1-roadmap-unplanned--grill-before-detailing)). What
runs today is the engine and its evals harness from a clone:

```sh
uv sync                 # dev setup (Python 3.12, tree-sitter grammars)
uv run pytest           # test suite
make corpus             # assemble the pinned 22-server eval corpus
make eval               # run the lenses over the corpus, print precision/recall + report.md
```

`make eval` reproduces the published numbers on a fresh clone. The engine that produces them
(`credlens.scan.scan_tree` + `CredentialDetector` / `LeastPrivDetector`) is the *same* code the hosted
scan runs, so the reported precision describes exactly what a scan does.

## Design principles

- **Evals before detectors.** The measuring instrument is the spine of the project, not an afterthought.
- **Findings vs inventory.** A `finding` asserts misbehavior and is precision-gated. An `inventory`
  entry states a factual capability/permission surface. The two are never mixed.
- **Deterministic scan path.** Parse-only static analysis — no LLM calls, no network, target code is
  never executed.
- **Stated limitations.** Known-miss classes are documented, not discovered.

## Roadmap

Next up (unscoped — grilling before detail): **generalizing the scan surface** (arbitrary local code
and MCP servers, more idioms) and a **user-facing workflow** (a local CLI, packaging, and/or hosted
scan-by-URL) so you can run credlens on your own server. See
[docs/plan/plan.md](docs/plan/plan.md#future--post-v1-roadmap-unplanned--grill-before-detailing).

## License

[Apache-2.0](LICENSE)
