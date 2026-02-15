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
- Bedrock Guardrails enabled: `True`
- Open-source classifier enabled: `True`
- Open-source model: `protectai/deberta-v3-base-prompt-injection-v2`
- OpenAI policy adapter enabled: `True`
- OpenAI model: `gpt-4.1-mini`
- Anthropic policy adapter enabled: `True`
- Anthropic model: `claude-3-5-haiku-latest`

| strategy | accuracy | precision | recall | f1 | tp | tn | fp | fn |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| guardllm | 95.2% | 92.86% | 86.67% | 89.66 | 26 | 93 | 2 | 4 |
| no_defense | 76.0% | 0.0% | 0.0% | 0.0 | 0 | 95 | 0 | 30 |
| regex_rule_based | 78.4% | 100.0% | 10.0% | 18.18 | 3 | 95 | 0 | 27 |
| open_source_deberta | 60.8% | 29.79% | 46.67% | 36.37 | 14 | 62 | 33 | 16 |
| azure_prompt_shields | 78.4% | 100.0% | 10.0% | 18.18 | 3 | 95 | 0 | 27 |
| openai_policy_adapter | 89.6% | 90.48% | 63.33% | 74.51 | 19 | 93 | 2 | 11 |
| anthropic_policy_adapter | 84.8% | 70.37% | 63.33% | 66.66 | 19 | 87 | 8 | 11 |
| bedrock_guardrails | 77.6% | 100.0% | 6.67% | 12.51 | 2 | 95 | 0 | 28 |
| azure_plus_guardllm | 96.8% | 93.33% | 93.33% | 93.33 | 28 | 93 | 2 | 2 |
| bedrock_plus_guardllm | 96.0% | 93.1% | 90.0% | 91.52 | 27 | 93 | 2 | 3 |

| strategy | avg latency (ms) | p95 latency (ms) | max latency (ms) |
|---|---:|---:|---:|
| guardllm | 0.16 | 0.68 | 1.0 |
| no_defense | 0.0 | 0.0 | 0.0 |
| regex_rule_based | 0.01 | 0.03 | 0.19 |
| open_source_deberta | 35.62 | 52.43 | 181.94 |
| azure_prompt_shields | 215.7 | 253.9 | 616.4 |
| openai_policy_adapter | 626.6 | 990.34 | 2641.52 |
| anthropic_policy_adapter | 645.48 | 892.07 | 1787.38 |
| bedrock_guardrails | 658.22 | 728.12 | 823.73 |
| azure_plus_guardllm | 215.86 | 254.58 | 617.4 |
| bedrock_plus_guardllm | 658.38 | 728.8 | 824.73 |

Cost proxy:
- Azure Prompt Shields calls: `125`
- Bedrock ApplyGuardrail calls: `125`
- Bedrock wordPolicyUnits: `130`

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
| anthropic_policy_adapter | 50.0% | 25.0% | 100.0% | 40.0 | 1 | 2 | 3 | 0 |
| bedrock_guardrails | 66.67% | 0.0% | 0.0% | 0.0 | 0 | 4 | 1 | 1 |
| azure_plus_guardllm | 83.33% | 50.0% | 100.0% | 66.67 | 1 | 4 | 1 | 0 |
| bedrock_plus_guardllm | 83.33% | 50.0% | 100.0% | 66.67 | 1 | 4 | 1 | 0 |

## Official Reference (Pinned Sources)

- These stats are derived from pinned official exports in `benchmarks/upstream/manifest.json`.
- `pint` @ `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8`: {"negative_labels": 6, "positive_labels": 2, "rows": 8}
- `bipia` @ `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`: {"known_ideal": 24, "rows": 50, "unknown_ideal": 26}
- `agentdojo` @ `462c88ddf596cb745882702f9999c8aeb5fe467f`: {"channels": {"calendar": 7, "drive": 4, "email": 5, "other": 0}, "rows": 16}
