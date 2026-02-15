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
| upstream_pint | 16/16 (100.0%) | 8/16 (50.0%) | 8/16 (50.0%) | 0/16 (0.0%) | 100.0% |

## Overall

- `guardllm`: 248/248 (100.0%)
- `isolation_only`: 106/248 (42.74%)
- `source_gate_only`: 113/248 (45.56%)
- `no_defense`: 35/248 (14.11%)

## Full-Suite Breakdown

| strategy | attack-mitigation success | benign/allow correctness |
|---|---:|---:|
| guardllm | 144/144 (100.0%) | 104/104 (100.0%) |
| isolation_only | 2/144 (1.39%) | 104/104 (100.0%) |
| source_gate_only | 78/144 (54.17%) | 35/104 (33.65%) |
| no_defense | 0/144 (0.0%) | 35/104 (33.65%) |

## Text-Only Comparison

- Record count: `125`
- Azure Prompt Shields enabled: `True`
- Azure Prompt Shields error: `<urlopen error [Errno 8] nodename nor servname provided, or not known>`
- Bedrock Guardrails enabled: `False`
- Open-source classifier enabled: `True`
- Open-source model: `protectai/deberta-v3-base-prompt-injection-v2`
- Open-source error: `
 requires the protobuf library but it was not found in your environment. Check out the instructions on the
installation page of its repo: https://github.com/protocolbuffers/protobuf/tree/master/python#installation and follow the ones
that match your environment. Please note that you may need to restart your runtime after installation.
`
- OpenAI policy adapter enabled: `True`
- OpenAI model: `gpt-4.1-mini`
- OpenAI error: `<urlopen error [Errno 8] nodename nor servname provided, or not known>`
- Anthropic policy adapter enabled: `True`
- Anthropic model: `claude-3-5-haiku-latest`
- Anthropic error: `<urlopen error [Errno 8] nodename nor servname provided, or not known>`

| strategy | accuracy | precision | recall | f1 | tp | tn | fp | fn |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| guardllm | 95.2% | 92.86% | 86.67% | 89.66 | 26 | 93 | 2 | 4 |
| no_defense | 76.0% | 0.0% | 0.0% | 0.0 | 0 | 95 | 0 | 30 |
| regex_rule_based | 78.4% | 100.0% | 10.0% | 18.18 | 3 | 95 | 0 | 27 |

| strategy | avg latency (ms) | p95 latency (ms) | max latency (ms) |
|---|---:|---:|---:|
| guardllm | 0.16 | 0.7 | 1.0 |
| no_defense | 0.0 | 0.0 | 0.0 |
| regex_rule_based | 0.01 | 0.03 | 0.19 |

Cost proxy:
- Azure Prompt Shields calls: `0`
- Bedrock ApplyGuardrail calls: `0`
- Bedrock wordPolicyUnits: `0`

## Non-Text Comparison

- Record count: `120`
| strategy | passed | total | pass rate |
|---|---:|---:|---:|
| guardllm_non_text | 120 | 120 | 100.0% |
| no_defense_non_text | 9 | 120 | 7.5% |
| schema_jsonschema | 11 | 120 | 9.17% |
| policy_opa | 97 | 120 | 80.83% |
| redis_rate_limit | 15 | 120 | 12.5% |
| non_text_stack | 101 | 120 | 84.17% |

| non-text kind | strategy | passed | total | pass rate |
|---|---|---:|---:|---:|
| action_gate | guardllm_non_text | 8 | 8 | 100.0% |
| action_gate | no_defense_non_text | 3 | 8 | 37.5% |
| action_gate | schema_jsonschema | 3 | 8 | 37.5% |
| action_gate | policy_opa | 6 | 8 | 75.0% |
| action_gate | redis_rate_limit | 3 | 8 | 37.5% |
| action_gate | non_text_stack | 6 | 8 | 75.0% |
| binding_replay | guardllm_non_text | 6 | 6 | 100.0% |
| binding_replay | no_defense_non_text | 2 | 6 | 33.33% |
| binding_replay | schema_jsonschema | 2 | 6 | 33.33% |
| binding_replay | policy_opa | 2 | 6 | 33.33% |
| binding_replay | redis_rate_limit | 2 | 6 | 33.33% |
| binding_replay | non_text_stack | 2 | 6 | 33.33% |
| error_sanitize | guardllm_non_text | 6 | 6 | 100.0% |
| error_sanitize | no_defense_non_text | 0 | 6 | 0.0% |
| error_sanitize | schema_jsonschema | 2 | 6 | 33.33% |
| error_sanitize | policy_opa | 2 | 6 | 33.33% |
| error_sanitize | redis_rate_limit | 2 | 6 | 33.33% |
| error_sanitize | non_text_stack | 2 | 6 | 33.33% |
| rate_limit | guardllm_non_text | 4 | 4 | 100.0% |
| rate_limit | no_defense_non_text | 0 | 4 | 0.0% |
| rate_limit | schema_jsonschema | 0 | 4 | 0.0% |
| rate_limit | policy_opa | 0 | 4 | 0.0% |
| rate_limit | redis_rate_limit | 4 | 4 | 100.0% |
| rate_limit | non_text_stack | 4 | 4 | 100.0% |
| source_gate | guardllm_non_text | 79 | 79 | 100.0% |
| source_gate | no_defense_non_text | 1 | 79 | 1.27% |
| source_gate | schema_jsonschema | 1 | 79 | 1.27% |
| source_gate | policy_opa | 79 | 79 | 100.0% |
| source_gate | redis_rate_limit | 1 | 79 | 1.27% |
| source_gate | non_text_stack | 79 | 79 | 100.0% |
| tool_gate | guardllm_non_text | 9 | 9 | 100.0% |
| tool_gate | no_defense_non_text | 3 | 9 | 33.33% |
| tool_gate | schema_jsonschema | 3 | 9 | 33.33% |
| tool_gate | policy_opa | 8 | 9 | 88.89% |
| tool_gate | redis_rate_limit | 3 | 9 | 33.33% |
| tool_gate | non_text_stack | 8 | 9 | 88.89% |
| tool_gate_auth | guardllm_non_text | 4 | 4 | 100.0% |
| tool_gate_auth | no_defense_non_text | 0 | 4 | 0.0% |
| tool_gate_auth | schema_jsonschema | 0 | 4 | 0.0% |
| tool_gate_auth | policy_opa | 0 | 4 | 0.0% |
| tool_gate_auth | redis_rate_limit | 0 | 4 | 0.0% |
| tool_gate_auth | non_text_stack | 0 | 4 | 0.0% |
| validation | guardllm_non_text | 4 | 4 | 100.0% |
| validation | no_defense_non_text | 0 | 4 | 0.0% |
| validation | schema_jsonschema | 0 | 4 | 0.0% |
| validation | policy_opa | 0 | 4 | 0.0% |
| validation | redis_rate_limit | 0 | 4 | 0.0% |
| validation | non_text_stack | 0 | 4 | 0.0% |

## Holdout Generalization (Legacy Upstream Snapshots)

- Record count: `6`
| strategy | accuracy | precision | recall | f1 | tp | tn | fp | fn |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| guardllm | 100.0% | 100.0% | 100.0% | 100.0 | 1 | 5 | 0 | 0 |
| no_defense | 83.33% | 0.0% | 0.0% | 0.0 | 0 | 5 | 0 | 1 |
| regex_rule_based | 66.67% | 0.0% | 0.0% | 0.0 | 0 | 4 | 1 | 1 |

## Official Reference (Pinned Sources)

- These stats are derived from pinned official exports in `benchmarks/upstream/manifest.json`.
- `pint` @ `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8`: {"negative_labels": 6, "positive_labels": 2, "rows": 8}
- `bipia` @ `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`: {"known_ideal": 24, "rows": 50, "unknown_ideal": 26}
- `agentdojo` @ `462c88ddf596cb745882702f9999c8aeb5fe467f`: {"channels": {"calendar": 7, "drive": 4, "email": 5, "other": 0}, "rows": 16}
