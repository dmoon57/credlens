# credlens eval — detector `baseline`

## Real-server credential lens (precision)
- credential findings emitted: **3** (ground truth: 0 real leaks → all false positives)
- precision: **0.0**
- examples:
  - `servers-archived/brave-search/index.ts:84 Secret value (BRAVE_API_KEY) may reach a sink`
  - `servers-archived/gitlab/index.ts:62 Secret value (GITLAB_PERSONAL_ACCESS_TOKEN) may reach a sink`
  - `servers-archived/google-maps/index.ts:139 Secret value (GOOGLE_MAPS_API_KEY) may reach a sink`

## Mutation corpus (recall + negative precision)
- **tune** recall: 0.6019 (65/108)
- **holdout** recall: 0.5185 (28/54)
- negative precision (hard-negatives not flagged): **0.9029** (10 of 36 FP)

| class | split | recall |
|---|---|---|
| aliased-log | tune | 0.5556 (10/18) |
| cross-function-hop | holdout | 0.0 (0/18) |
| direct-env-log | tune | 0.8333 (15/18) |
| hardcoded-token | holdout | 1.0 (18/18) |
| secret-in-body | tune | 0.5556 (10/18) |
| secret-in-header | tune | 0.5556 (10/18) |
| secret-in-url | tune | 0.5556 (10/18) |
| secret-to-file | holdout | 0.5556 (10/18) |
| template-log | tune | 0.5556 (10/18) |

## Overall
- false-positive rate: **0.1226**
- _~78% flagged-findings-false is a single 33-server study — directional only, NOT our denominator (see README methodology)._
