# Mitigation Comparison

| suite | guardllm | isolation_only | source_gate_only | no_defense | delta_vs_no_defense |
|---|---:|---:|---:|---:|---:|
| agentdojo_style | 14/14 (100.0%) | 4/14 (28.57%) | 5/14 (35.71%) | 4/14 (28.57%) | 71.43% |
| bipia_style | 14/14 (100.0%) | 2/14 (14.29%) | 3/14 (21.43%) | 2/14 (14.29%) | 85.71% |
| garak_style | 5/5 (100.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 100.0% |
| mcp_protocol_abuse_style | 5/5 (100.0%) | 1/5 (20.0%) | 1/5 (20.0%) | 1/5 (20.0%) | 80.0% |
| multistep_agent_attack_style | 5/5 (100.0%) | 2/5 (40.0%) | 2/5 (40.0%) | 2/5 (40.0%) | 60.0% |
| owasp_llm_top10_style | 5/5 (100.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 100.0% |
| pint_style | 14/14 (100.0%) | 1/14 (7.14%) | 3/14 (21.43%) | 1/14 (7.14%) | 92.86% |
| promptfoo_redteam_style | 5/5 (100.0%) | 0/5 (0.0%) | 1/5 (20.0%) | 0/5 (0.0%) | 100.0% |
| rag_poisoning_style | 5/5 (100.0%) | 1/5 (20.0%) | 3/5 (60.0%) | 1/5 (20.0%) | 80.0% |
| secrets_exfil_style | 5/5 (100.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 100.0% |
| unicode_evasion_style | 5/5 (100.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 0/5 (0.0%) | 100.0% |
| upstream_agentdojo | 26/26 (100.0%) | 13/26 (50.0%) | 13/26 (50.0%) | 0/26 (0.0%) | 100.0% |
| upstream_bipia | 124/124 (100.0%) | 74/124 (59.68%) | 74/124 (59.68%) | 24/124 (19.35%) | 80.65% |
| upstream_harmbench | 640/640 (100.0%) | 320/640 (50.0%) | 320/640 (50.0%) | 0/640 (0.0%) | 100.0% |
| upstream_injecagent | 240/240 (100.0%) | 60/240 (25.0%) | 60/240 (25.0%) | 30/240 (12.5%) | 87.5% |
| upstream_jailbreakbench | 199/200 (99.5%) | 99/200 (49.5%) | 100/200 (50.0%) | 0/200 (0.0%) | 99.5% |
| upstream_mcp_bench | 320/320 (100.0%) | 80/320 (25.0%) | 80/320 (25.0%) | 40/320 (12.5%) | 87.5% |
| upstream_mcpbench | 4794/4800 (99.88%) | 1194/4800 (24.88%) | 1200/4800 (25.0%) | 600/4800 (12.5%) | 87.38% |
| upstream_pint | 16/16 (100.0%) | 8/16 (50.0%) | 8/16 (50.0%) | 0/16 (0.0%) | 100.0% |
| upstream_wainjectbench | 3486/3698 (94.27%) | 3490/3698 (94.38%) | 0/3698 (0.0%) | 0/3698 (0.0%) | 94.27% |

## Overall

- `guardllm`: 9927/10146 (97.84%)
- `isolation_only`: 5349/10146 (52.72%)
- `source_gate_only`: 1873/10146 (18.46%)
- `no_defense`: 705/10146 (6.95%)

## Full-Suite Breakdown

| strategy | attack-mitigation success | benign/allow correctness |
|---|---:|---:|
| guardllm | 6657/6665 (99.88%) | 3270/3481 (93.94%) |
| isolation_only | 2075/6665 (31.13%) | 3274/3481 (94.05%) |
| source_gate_only | 1168/6665 (17.52%) | 705/3481 (20.25%) |
| no_defense | 0/6665 (0.0%) | 705/3481 (20.25%) |

Note: full-suite benign correctness includes non-text and out-of-scope cases; it is not directly comparable to text-only precision.

## Text-Only Comparison

- Text scope: `injection`
- Included suites in text scope: `bipia_style, garak_style, owasp_llm_top10_style, pint_style, promptfoo_redteam_style, rag_poisoning_style, secrets_exfil_style, unicode_evasion_style, upstream_agentdojo, upstream_bipia, upstream_pint, upstream_wainjectbench`
- Record count: `3823`
- GuardLLM text reused: `False`
- Bedrock detection signal: `assessment contentPolicy PROMPT_ATTACK detected==true (inputStrength=HIGH)`

| strategy | accuracy | precision | recall | f1 | tp | tn | fp | fn |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| guardllm | 93.17% | 99.1% | 75.12% | 85.46 | 767 | 2795 | 7 | 254 |
| open_source_deberta | 81.45% | 80.47% | 40.35% | 53.75 | 412 | 2702 | 100 | 609 |
| openai_policy_adapter | 84.99% | 96.47% | 45.45% | 61.79 | 464 | 2785 | 17 | 557 |
| anthropic_policy_adapter | 81.27% | 89.0% | 34.08% | 49.29 | 348 | 2759 | 43 | 673 |
| no_defense | 73.29% | 0.0% | 0.0% | 0.0 | 0 | 2802 | 0 | 1021 |
| regex_rule_based | 73.37% | 100.0% | 0.29% | 0.58 | 3 | 2802 | 0 | 1018 |
| bedrock_guardrails (HIGH) | 78.5% | 100.0% | 19.49% | 32.62 | 199 | 2802 | 0 | 822 |

| strategy | avg latency (ms) | p95 latency (ms) | max latency (ms) |
|---|---:|---:|---:|
| guardllm | 0.07 | 0.2 | 2.46 |
| open_source_deberta | 27.1 | 45.97 | 692.0 |
| openai_policy_adapter | 615.68 | 1159.07 | 2480.23 |
| anthropic_policy_adapter | 662.14 | 1024.03 | 3893.35 |
| no_defense | 0.0 | 0.0 | 0.01 |
| regex_rule_based | 0.01 | 0.02 | 0.19 |
| bedrock_guardrails (HIGH) | 748.27 | 850.79 | 1644.63 |

Top GuardLLM false-negative patterns:
- `very`: `438`
- `image`: `64`
- `white`: `36`
- `background`: `36`
- `important`: `33`
- `patterned`: `32`
- `against`: `29`
- `like`: `28`
- `blue`: `28`
- `comment`: `27`
- `click`: `26`
- `possibly`: `26`
- `must`: `25`
- `attention`: `24`
- `functionality`: `24`
- `moved`: `24`
- `order`: `24`
- `page`: `24`
- `parked`: `22`
- `animated`: `20`

Cost proxy:
- Azure Prompt Shields calls: `0`
- Bedrock ApplyGuardrail calls: `3823`
- Bedrock wordPolicyUnits: `3836`
- Bedrock contentPolicyUnits: `3836`
- Bedrock calls with contentPolicyUnits>0: `3823`
- Bedrock calls with contentPolicyUnits==0: `0`
- Bedrock intervened responses: `2`
- Bedrock prompt-attack detected responses: `199`
- Bedrock prompt-attack filter present responses: `199`
- Bedrock prompt-attack filter present but not detected responses: `0`

## Non-Text Comparison

- Record count: `5230`
- Casbin available: `True`
- Pydantic available: `True`
| strategy | passed | total | micro pass rate | macro-by-kind |
|---|---:|---:|---:|---:|
| guardllm_non_text | 5230 | 5230 | 100.0% | 100.0% |
| no_defense_non_text | 679 | 5230 | 12.98% | 12.49% |
| schema_jsonschema | 681 | 5230 | 13.02% | 16.66% |
| policy_opa | 2527 | 5230 | 48.32% | 41.65% |
| casbin_rbac | 4549 | 5230 | 86.98% | 79.11% |
| strict_schema_stack | 5228 | 5230 | 99.96% | 99.96% |
| redis_rate_limit | 1353 | 5230 | 25.87% | 29.12% |
| non_text_stack | 3199 | 5230 | 61.17% | 54.11% |

Excluding `source_gate`:

| strategy | passed | total | micro pass rate | macro-by-kind |
|---|---:|---:|---:|---:|
| guardllm_non_text | 4061 | 4061 | 100.0% | 100.0% |
| no_defense_non_text | 678 | 4061 | 16.7% | 14.27% |
| schema_jsonschema | 680 | 4061 | 16.74% | 19.03% |
| policy_opa | 1358 | 4061 | 33.44% | 33.31% |
| casbin_rbac | 3380 | 4061 | 83.23% | 76.13% |
| strict_schema_stack | 4059 | 4061 | 99.95% | 99.96% |
| redis_rate_limit | 1352 | 4061 | 33.29% | 33.27% |
| non_text_stack | 2030 | 4061 | 49.99% | 47.56% |

| non-text kind | strategy | passed | total | pass rate |
|---|---|---:|---:|---:|
| action_gate | guardllm_non_text | 678 | 678 | 100.0% |
| action_gate | no_defense_non_text | 3 | 678 | 0.44% |
| action_gate | schema_jsonschema | 3 | 678 | 0.44% |
| action_gate | policy_opa | 676 | 678 | 99.71% |
| action_gate | casbin_rbac | 676 | 678 | 99.71% |
| action_gate | strict_schema_stack | 678 | 678 | 100.0% |
| action_gate | redis_rate_limit | 3 | 678 | 0.44% |
| action_gate | non_text_stack | 676 | 678 | 99.71% |
| binding_replay | guardllm_non_text | 676 | 676 | 100.0% |
| binding_replay | no_defense_non_text | 2 | 676 | 0.3% |
| binding_replay | schema_jsonschema | 2 | 676 | 0.3% |
| binding_replay | policy_opa | 2 | 676 | 0.3% |
| binding_replay | casbin_rbac | 676 | 676 | 100.0% |
| binding_replay | strict_schema_stack | 676 | 676 | 100.0% |
| binding_replay | redis_rate_limit | 2 | 676 | 0.3% |
| binding_replay | non_text_stack | 2 | 676 | 0.3% |
| error_sanitize | guardllm_non_text | 6 | 6 | 100.0% |
| error_sanitize | no_defense_non_text | 0 | 6 | 0.0% |
| error_sanitize | schema_jsonschema | 2 | 6 | 33.33% |
| error_sanitize | policy_opa | 2 | 6 | 33.33% |
| error_sanitize | casbin_rbac | 2 | 6 | 33.33% |
| error_sanitize | strict_schema_stack | 6 | 6 | 100.0% |
| error_sanitize | redis_rate_limit | 2 | 6 | 33.33% |
| error_sanitize | non_text_stack | 2 | 6 | 33.33% |
| rate_limit | guardllm_non_text | 674 | 674 | 100.0% |
| rate_limit | no_defense_non_text | 0 | 674 | 0.0% |
| rate_limit | schema_jsonschema | 0 | 674 | 0.0% |
| rate_limit | policy_opa | 0 | 674 | 0.0% |
| rate_limit | casbin_rbac | 0 | 674 | 0.0% |
| rate_limit | strict_schema_stack | 673 | 674 | 99.85% |
| rate_limit | redis_rate_limit | 672 | 674 | 99.7% |
| rate_limit | non_text_stack | 672 | 674 | 99.7% |
| source_gate | guardllm_non_text | 1169 | 1169 | 100.0% |
| source_gate | no_defense_non_text | 1 | 1169 | 0.09% |
| source_gate | schema_jsonschema | 1 | 1169 | 0.09% |
| source_gate | policy_opa | 1169 | 1169 | 100.0% |
| source_gate | casbin_rbac | 1169 | 1169 | 100.0% |
| source_gate | strict_schema_stack | 1169 | 1169 | 100.0% |
| source_gate | redis_rate_limit | 1 | 1169 | 0.09% |
| source_gate | non_text_stack | 1169 | 1169 | 100.0% |
| tool_gate | guardllm_non_text | 679 | 679 | 100.0% |
| tool_gate | no_defense_non_text | 673 | 679 | 99.12% |
| tool_gate | schema_jsonschema | 673 | 679 | 99.12% |
| tool_gate | policy_opa | 678 | 679 | 99.85% |
| tool_gate | casbin_rbac | 678 | 679 | 99.85% |
| tool_gate | strict_schema_stack | 678 | 679 | 99.85% |
| tool_gate | redis_rate_limit | 673 | 679 | 99.12% |
| tool_gate | non_text_stack | 678 | 679 | 99.85% |
| tool_gate_auth | guardllm_non_text | 674 | 674 | 100.0% |
| tool_gate_auth | no_defense_non_text | 0 | 674 | 0.0% |
| tool_gate_auth | schema_jsonschema | 0 | 674 | 0.0% |
| tool_gate_auth | policy_opa | 0 | 674 | 0.0% |
| tool_gate_auth | casbin_rbac | 674 | 674 | 100.0% |
| tool_gate_auth | strict_schema_stack | 674 | 674 | 100.0% |
| tool_gate_auth | redis_rate_limit | 0 | 674 | 0.0% |
| tool_gate_auth | non_text_stack | 0 | 674 | 0.0% |
| validation | guardllm_non_text | 674 | 674 | 100.0% |
| validation | no_defense_non_text | 0 | 674 | 0.0% |
| validation | schema_jsonschema | 0 | 674 | 0.0% |
| validation | policy_opa | 0 | 674 | 0.0% |
| validation | casbin_rbac | 674 | 674 | 100.0% |
| validation | strict_schema_stack | 674 | 674 | 100.0% |
| validation | redis_rate_limit | 0 | 674 | 0.0% |
| validation | non_text_stack | 0 | 674 | 0.0% |

## Holdout Generalization (Legacy Upstream Snapshots)

- No legacy holdout snapshots found.

## Official Reference (Pinned Sources)

- These stats are derived from pinned official exports in `benchmarks/upstream/manifest.json`.
- `pint` @ `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8`: {"negative_labels": 6, "positive_labels": 2, "rows": 8}
- `bipia` @ `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`: {"known_ideal": 24, "rows": 50, "unknown_ideal": 26}
- `agentdojo` @ `462c88ddf596cb745882702f9999c8aeb5fe467f`: {"channels": {"calendar": 7, "drive": 4, "email": 5, "other": 0}, "rows": 16}
- `jailbreakbench` @ `886acc352a31533ffbcf4ef22c744658688086fc`: {"rows": 100}
- `harmbench` @ `8e1604d1171fe8a48d8febecd22f600e462bdcdd`: {"rows": 320}
- `injecagent` @ `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`: {"rows": 30}
- `mcpbench` @ `5f397445370e6cb44dfdfc5680a48f128a75d349`: {"rows": 600}
- `mcp_bench` @ `7a8eaeae83a842a2949080acc5473f65e1569daf`: {"rows": 40}
- `wainjectbench` @ `4a5b7a5d4e393983d7105aed3485014b7206d205`: {"rows": 3698}
