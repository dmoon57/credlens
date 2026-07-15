# credlens eval — detector `credential`

## Real-server credential lens (precision)
- credential findings emitted: **0** (ground truth: 0 real leaks → all false positives)
- precision: **1.0**

## Mutation corpus (recall + negative precision)
- **intra-file holdout recall (gated): 0.9167** (33/36)
- exfil_v2 recall: 0.0 (0/54) — documented v1 known-miss, not gated
- interprocedural recall: 0.0 (0/18) — documented v1 known-miss, not gated
- intra_file recall: 0.8667 (78/90)
- tune split recall (all scopes): 0.4167 (45/108)
- holdout split recall (all scopes): 0.6111 (33/54)
- negative precision (hard-negatives not flagged): **1.0** (0 of 36 FP)

| class | split | scope | recall |
|---|---|---|---|
| aliased-log | tune | intra_file | 0.8333 (15/18) |
| cross-function-hop | holdout | interprocedural | 0.0 (0/18) |
| direct-env-log | tune | intra_file | 0.8333 (15/18) |
| hardcoded-token | holdout | intra_file | 1.0 (18/18) |
| secret-in-body | tune | exfil_v2 | 0.0 (0/18) |
| secret-in-header | tune | exfil_v2 | 0.0 (0/18) |
| secret-in-url | tune | exfil_v2 | 0.0 (0/18) |
| secret-to-file | holdout | intra_file | 0.8333 (15/18) |
| template-log | tune | intra_file | 0.8333 (15/18) |

## Least-privilege inventory (real servers — never scored TP/FP)
- asserted findings leaked into inventory pass: **0** (must be 0)

| category | occurrences | servers |
|---|---|---|
| Secret value sent in an outbound request | 14 | 2 |
| Writes to the filesystem | 8 | 3 |
| Deletes filesystem entries | 7 | 2 |
| Makes outbound network requests | 6 | 6 |
| HTTP server | 4 | 1 |
| Network-exposed transport | 2 | 1 |
| Executes subprocesses | 1 | 1 |
| OAuth scopes declared | 1 | 1 |

## Overall
- false-positive rate: **0.0**
- _~78% flagged-findings-false is a single 33-server study — directional only, NOT our denominator (see README methodology)._
