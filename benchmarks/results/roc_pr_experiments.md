# ROC/PR Experiments

- records: `3823`
- attacks: `1021`
- benign: `2802`
- split seed: `1337`
- dev records: `700`
- test records: `3123`

## Methods

| method | tunable | curve source | roc_auc | pr_auc |
|---|---:|---|---:|---:|
| guardllm | true | full | 0.863746 | 0.869394 |
| regex_rule_based | false | single_point |  |  |
| no_defense | false | single_point |  |  |
| openai_tool_policy | true | dev | 0.747234 | 0.767578 |
| anthropic_tool_policy | true | dev | 0.799639 | 0.717211 |

## Recall At FP Budgets (test)

| method | budget | threshold | recall | precision | fp_per_1k_neg | meets_budget |
|---|---|---:|---:|---:|---:|---:|
| guardllm | fp/1k<=1.0 | 0.5 | 73.7665% | 99.8371% | 0.4363 | true |
| guardllm | fp/1k<=5.0 | 0.5 | 73.7665% | 99.8371% | 0.4363 | true |
| regex_rule_based | fp/1k<=1.0 | None | 0.2407% | 100.0% | 0.0 | true |
| regex_rule_based | fp/1k<=5.0 | None | 0.2407% | 100.0% | 0.0 | true |
| no_defense | fp/1k<=1.0 | None | 0.0% | 100.0% | 0.0 | true |
| no_defense | fp/1k<=5.0 | None | 0.0% | 100.0% | 0.0 | true |
| openai_tool_policy | fp/1k<=1.0 | 0.9 | 15.0421% | 99.2063% | 0.4363 | true |
| openai_tool_policy | fp/1k<=5.0 | 0.75 | 44.8857% | 96.134% | 6.5445 | true |
| anthropic_tool_policy | fp/1k<=1.0 | 0.95 | 2.5271% | 95.4545% | 0.4363 | true |
| anthropic_tool_policy | fp/1k<=5.0 | 0.9 | 24.6691% | 95.3488% | 4.363 | true |
