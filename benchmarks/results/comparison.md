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
| upstream_injecagent | 60/60 (100.0%) | 30/60 (50.0%) | 30/60 (50.0%) | 0/60 (0.0%) | 100.0% |
| upstream_jailbreakbench | 199/200 (99.5%) | 99/200 (49.5%) | 100/200 (50.0%) | 0/200 (0.0%) | 99.5% |
| upstream_mcp_bench | 80/80 (100.0%) | 40/80 (50.0%) | 40/80 (50.0%) | 0/80 (0.0%) | 100.0% |
| upstream_mcpbench | 1194/1200 (99.5%) | 594/1200 (49.5%) | 600/1200 (50.0%) | 0/1200 (0.0%) | 99.5% |
| upstream_pint | 16/16 (100.0%) | 8/16 (50.0%) | 8/16 (50.0%) | 0/16 (0.0%) | 100.0% |

## Overall

- `guardllm`: 2421/2428 (99.71%)
- `isolation_only`: 1189/2428 (48.97%)
- `source_gate_only`: 1203/2428 (49.55%)
- `no_defense`: 35/2428 (1.44%)

## Full-Suite Breakdown

| strategy | attack-mitigation success | benign/allow correctness |
|---|---:|---:|
| guardllm | 2317/2324 (99.7%) | 104/104 (100.0%) |
| isolation_only | 1085/2324 (46.69%) | 104/104 (100.0%) |
| source_gate_only | 1168/2324 (50.26%) | 35/104 (33.65%) |
| no_defense | 0/2324 (0.0%) | 35/104 (33.65%) |

## Text-Only Comparison

- Record count: `1215`
- Azure Prompt Shields enabled: `True`
- Bedrock Guardrails enabled: `False`
- Open-source classifier enabled: `True`
- Open-source model: `protectai/deberta-v3-base-prompt-injection-v2`
- OpenAI policy adapter enabled: `True`
- OpenAI model: `gpt-4.1-mini`
- Anthropic policy adapter enabled: `True`
- Anthropic model: `claude-3-5-haiku-latest`

| strategy | accuracy | precision | recall | f1 | tp | tn | fp | fn |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| guardllm | 9.79% | 92.86% | 2.32% | 4.53 | 26 | 93 | 2 | 1094 |
| no_defense | 7.82% | 0.0% | 0.0% | 0.0 | 0 | 95 | 0 | 1120 |
| regex_rule_based | 8.15% | 100.0% | 0.36% | 0.72 | 4 | 95 | 0 | 1116 |
| open_source_deberta | 11.85% | 71.3% | 7.32% | 13.28 | 82 | 62 | 33 | 1038 |
| azure_prompt_shields | 9.63% | 100.0% | 1.96% | 3.84 | 22 | 95 | 0 | 1098 |
| openai_policy_adapter | 38.27% | 99.47% | 33.21% | 49.79 | 372 | 93 | 2 | 748 |
| anthropic_policy_adapter | 28.97% | 97.07% | 23.66% | 38.05 | 265 | 87 | 8 | 855 |
| azure_plus_guardllm | 11.52% | 95.92% | 4.2% | 8.05 | 47 | 93 | 2 | 1073 |

| strategy | avg latency (ms) | p95 latency (ms) | max latency (ms) |
|---|---:|---:|---:|
| guardllm | 0.03 | 0.08 | 0.98 |
| no_defense | 0.0 | 0.0 | 0.0 |
| regex_rule_based | 0.0 | 0.01 | 0.18 |
| open_source_deberta | 23.48 | 45.97 | 692.0 |
| azure_prompt_shields | 286.95 | 550.68 | 4978.92 |
| openai_policy_adapter | 687.92 | 1159.07 | 2480.23 |
| anthropic_policy_adapter | 686.36 | 1024.03 | 3893.35 |
| azure_plus_guardllm | 286.98 | 550.76 | 4979.9 |

Cost proxy:
- Azure Prompt Shields calls: `1215`
- Bedrock ApplyGuardrail calls: `0`
- Bedrock wordPolicyUnits: `0`

## Non-Text Comparison

- Record count: `1210`
- Casbin available: `True`
- Pydantic available: `True`
| strategy | passed | total | micro pass rate | macro-by-kind |
|---|---:|---:|---:|
| guardllm_non_text | 1210 | 1210 | 100.0% | 100.0% |
| no_defense_non_text | 9 | 1210 | 0.74% | 13.03% |
| schema_jsonschema | 11 | 1210 | 0.91% | 17.2% |
| policy_opa | 1187 | 1210 | 98.1% | 41.32% |
| casbin_rbac | 1199 | 1210 | 99.09% | 74.65% |
| strict_schema_stack | 1209 | 1210 | 99.92% | 98.61% |
| redis_rate_limit | 15 | 1210 | 1.24% | 29.7% |
| non_text_stack | 1191 | 1210 | 98.43% | 53.82% |

Excluding `source_gate`:

| strategy | passed | total | micro pass rate | macro-by-kind |
|---|---:|---:|---:|---:|
| guardllm_non_text | 41 | 41 | 100.0% | 100.0% |
| no_defense_non_text | 8 | 41 | 19.51% | 14.88% |
| schema_jsonschema | 10 | 41 | 24.39% | 19.64% |
| policy_opa | 18 | 41 | 43.9% | 32.94% |
| casbin_rbac | 30 | 41 | 73.17% | 71.03% |
| strict_schema_stack | 40 | 41 | 97.56% | 98.41% |
| redis_rate_limit | 14 | 41 | 34.15% | 33.93% |
| non_text_stack | 22 | 41 | 53.66% | 47.22% |

| non-text kind | strategy | passed | total | pass rate |
|---|---|---:|---:|---:|
| action_gate | guardllm_non_text | 8 | 8 | 100.0% |
| action_gate | no_defense_non_text | 3 | 8 | 37.5% |
| action_gate | schema_jsonschema | 3 | 8 | 37.5% |
| action_gate | policy_opa | 6 | 8 | 75.0% |
| action_gate | casbin_rbac | 6 | 8 | 75.0% |
| action_gate | strict_schema_stack | 8 | 8 | 100.0% |
| action_gate | redis_rate_limit | 3 | 8 | 37.5% |
| action_gate | non_text_stack | 6 | 8 | 75.0% |
| binding_replay | guardllm_non_text | 6 | 6 | 100.0% |
| binding_replay | no_defense_non_text | 2 | 6 | 33.33% |
| binding_replay | schema_jsonschema | 2 | 6 | 33.33% |
| binding_replay | policy_opa | 2 | 6 | 33.33% |
| binding_replay | casbin_rbac | 6 | 6 | 100.0% |
| binding_replay | strict_schema_stack | 6 | 6 | 100.0% |
| binding_replay | redis_rate_limit | 2 | 6 | 33.33% |
| binding_replay | non_text_stack | 2 | 6 | 33.33% |
| error_sanitize | guardllm_non_text | 6 | 6 | 100.0% |
| error_sanitize | no_defense_non_text | 0 | 6 | 0.0% |
| error_sanitize | schema_jsonschema | 2 | 6 | 33.33% |
| error_sanitize | policy_opa | 2 | 6 | 33.33% |
| error_sanitize | casbin_rbac | 2 | 6 | 33.33% |
| error_sanitize | strict_schema_stack | 6 | 6 | 100.0% |
| error_sanitize | redis_rate_limit | 2 | 6 | 33.33% |
| error_sanitize | non_text_stack | 2 | 6 | 33.33% |
| rate_limit | guardllm_non_text | 4 | 4 | 100.0% |
| rate_limit | no_defense_non_text | 0 | 4 | 0.0% |
| rate_limit | schema_jsonschema | 0 | 4 | 0.0% |
| rate_limit | policy_opa | 0 | 4 | 0.0% |
| rate_limit | casbin_rbac | 0 | 4 | 0.0% |
| rate_limit | strict_schema_stack | 4 | 4 | 100.0% |
| rate_limit | redis_rate_limit | 4 | 4 | 100.0% |
| rate_limit | non_text_stack | 4 | 4 | 100.0% |
| source_gate | guardllm_non_text | 1169 | 1169 | 100.0% |
| source_gate | no_defense_non_text | 1 | 1169 | 0.09% |
| source_gate | schema_jsonschema | 1 | 1169 | 0.09% |
| source_gate | policy_opa | 1169 | 1169 | 100.0% |
| source_gate | casbin_rbac | 1169 | 1169 | 100.0% |
| source_gate | strict_schema_stack | 1169 | 1169 | 100.0% |
| source_gate | redis_rate_limit | 1 | 1169 | 0.09% |
| source_gate | non_text_stack | 1169 | 1169 | 100.0% |
| tool_gate | guardllm_non_text | 9 | 9 | 100.0% |
| tool_gate | no_defense_non_text | 3 | 9 | 33.33% |
| tool_gate | schema_jsonschema | 3 | 9 | 33.33% |
| tool_gate | policy_opa | 8 | 9 | 88.89% |
| tool_gate | casbin_rbac | 8 | 9 | 88.89% |
| tool_gate | strict_schema_stack | 8 | 9 | 88.89% |
| tool_gate | redis_rate_limit | 3 | 9 | 33.33% |
| tool_gate | non_text_stack | 8 | 9 | 88.89% |
| tool_gate_auth | guardllm_non_text | 4 | 4 | 100.0% |
| tool_gate_auth | no_defense_non_text | 0 | 4 | 0.0% |
| tool_gate_auth | schema_jsonschema | 0 | 4 | 0.0% |
| tool_gate_auth | policy_opa | 0 | 4 | 0.0% |
| tool_gate_auth | casbin_rbac | 4 | 4 | 100.0% |
| tool_gate_auth | strict_schema_stack | 4 | 4 | 100.0% |
| tool_gate_auth | redis_rate_limit | 0 | 4 | 0.0% |
| tool_gate_auth | non_text_stack | 0 | 4 | 0.0% |
| validation | guardllm_non_text | 4 | 4 | 100.0% |
| validation | no_defense_non_text | 0 | 4 | 0.0% |
| validation | schema_jsonschema | 0 | 4 | 0.0% |
| validation | policy_opa | 0 | 4 | 0.0% |
| validation | casbin_rbac | 4 | 4 | 100.0% |
| validation | strict_schema_stack | 4 | 4 | 100.0% |
| validation | redis_rate_limit | 0 | 4 | 0.0% |
| validation | non_text_stack | 0 | 4 | 0.0% |

## Holdout Generalization (Legacy Upstream Snapshots)

- Record count: `6`
| strategy | accuracy | precision | recall | f1 | tp | tn | fp | fn |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| guardllm | 100.0% | 100.0% | 100.0% | 100.0 | 1 | 5 | 0 | 0 |
| no_defense | 83.33% | 0.0% | 0.0% | 0.0 | 0 | 5 | 0 | 1 |
| regex_rule_based | 66.67% | 0.0% | 0.0% | 0.0 | 0 | 4 | 1 | 1 |
| open_source_deberta | 50.0% | 0.0% | 0.0% | 0.0 | 0 | 3 | 2 | 1 |
| azure_prompt_shields | 66.67% | 0.0% | 0.0% | 0.0 | 0 | 4 | 1 | 1 |
| openai_policy_adapter | 33.33% | 0.0% | 0.0% | 0.0 | 0 | 2 | 3 | 1 |
| anthropic_policy_adapter | 66.67% | 33.33% | 100.0% | 50.0 | 1 | 3 | 2 | 0 |
| azure_plus_guardllm | 83.33% | 50.0% | 100.0% | 66.67 | 1 | 4 | 1 | 0 |

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
