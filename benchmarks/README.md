# Benchmarks

This directory provides an offline benchmark harness for evaluating guardllm against known threat patterns inspired by:
- PINT-style prompt-injection cases
- BIPIA-style indirect prompt-injection cases
- AgentDojo-style agent/tool security cases
- OWASP LLM Top 10-style threat profiles
- garak-style probe cases
- promptfoo red-team style cases
- MCP protocol abuse scenarios
- RAG poisoning scenarios
- secrets exfiltration scenarios
- multistep agent attack chains
- Unicode evasion attacks

## What this is

- A reproducible local regression suite for guardllm controls.
- A starter threat library in JSONL format under `benchmarks/cases/`.
- Versioned upstream-derived fixture snapshots under `benchmarks/upstream/`.
- Import tooling for official benchmark exports.
- Checkpoint files for regression gating in CI.
- A report generator writing to `benchmarks/results/latest.json`.

## Latest Snapshot

Core regression harness (`benchmarks/results/latest.json`):
- Overall: `6441/6448` (`99.89%`)
- Local suites: `82/82` (`100%`)
- Upstream suites: `6359/6366` (`99.89%`)

Expanded comparison corpus (`benchmarks/results/comparison.json`):
- Full suite: `9927/10146` (`97.84%`)
- Text scope (injection-only): `3823` records
- Non-text scope: `5230` records

Current text comparison (`benchmarks/results/comparison.json`, injection scope):
- Accuracy definition (text scope): `(TP + TN) / total_records` where labels are prompt-injection attack vs benign.
- Why accuracy is not enough: this dataset is benign-heavy, so accuracy can look acceptable even with poor attack recall. Use F1 and recall as primary attack-detection quality signals.

| Strategy | Accuracy | F1 | Precision | Recall | Avg Latency |
|---|---:|---:|---:|---:|---:|
| GuardLLM | 93.17% | 85.46 | 99.10% | 75.12% | 0.07ms |
| OpenAI (`gpt-4.1-mini`) | 84.99% | 61.79 | 96.47% | 45.45% | 615.68ms |
| Anthropic (`claude-3-5-haiku-latest`) | 81.27% | 49.29 | 89.00% | 34.08% | 662.14ms |
| Bedrock Guardrails (`HIGH`) | 78.50% | 32.62 | 100.0% | 19.49% | 748.27ms |
| Azure Prompt Shields | 76.80% | 23.60 | 97.86% | 13.42% | 209.34ms |
| Regex Rule Baseline | 73.37% | 0.58 | 100.0% | 0.29% | 0.01ms |
| No Defense | 73.29% | 0.00 | 0.0% | 0.0% | 0.00ms |

All rows in this table are evaluated on the same `3823`-record corpus (`1021` attacks, `2802` benign).
`comparison.json` / `comparison.md` are single-snapshot artifacts: re-running with different flags overwrites strategy rows for the latest run; they are not cumulative across runs.
`No Defense` is an allow-all baseline that effectively predicts benign for every input. Because the set is imbalanced, accuracy alone can look deceptively high; use recall/F1 as primary attack-detection metrics.

Current non-text comparison (`benchmarks/results/comparison.json`):
- Non-text total: `5230`
- Non-text excluding `source_gate`: `4061`

| Strategy | Passed | Total | Pass Rate |
|---|---:|---:|---:|
| guardllm_non_text | 5230 | 5230 | 100.0% |
| strict_schema_stack | 5228 | 5230 | 99.96% |
| casbin_rbac | 4549 | 5230 | 86.98% |
| non_text_stack | 3199 | 5230 | 61.17% |
| policy_opa | 2527 | 5230 | 48.32% |
| redis_rate_limit | 1353 | 5230 | 25.87% |
| schema_jsonschema | 681 | 5230 | 13.02% |
| no_defense_non_text | 679 | 5230 | 12.98% |

Non-text (excluding `source_gate`) pass rates:
- `guardllm_non_text`: `100.0%`
- `strict_schema_stack`: `99.95%`
- `casbin_rbac`: `83.23%`
- `non_text_stack`: `49.99%`
- `policy_opa`: `33.44%`

Reproducibility note:
- A few rate-limit and timing-sensitive checks can vary slightly across runs, which can shift pass counts by small margins.

## Run

```bash
python benchmarks/run_benchmarks.py
```

Run a single suite:

```bash
python benchmarks/run_benchmarks.py --suite pint_style
```

Run with checkpoint validation:

```bash
python benchmarks/run_benchmarks.py --checkpoint benchmarks/checkpoints/official-baseline.json
```

Write/update a checkpoint from current results:

```bash
python benchmarks/run_benchmarks.py --write-checkpoint benchmarks/checkpoints/official-baseline.json
```

Generate mitigation comparison tables:

```bash
python benchmarks/compare_mitigations.py
```

Include Azure Prompt Shields and Bedrock Guardrails:

```bash
python benchmarks/compare_mitigations.py \
  --azure-endpoint "https://<name>.cognitiveservices.azure.com" \
  --azure-key "<azure_key>" \
  --bedrock-guardrail-id "<guardrail_id>" \
  --bedrock-guardrail-version "<version>" \
  --bedrock-profile "bedrockbench" \
  --bedrock-region "us-east-1"
```

Outputs:
- `benchmarks/results/comparison.json`
- `benchmarks/results/comparison.md`

Current comparison strategies:
- `guardllm`: full GuardLLM controls
- `isolation_only`: inbound isolation-only baseline
- `source_gate_only`: source-gate-only baseline
- `no_defense`: allow-all baseline

## Import official exports

Import an official export and create a versioned upstream snapshot:

```bash
python benchmarks/import_official_exports.py \
  --suite bipia \
  --input /path/to/official/export.jsonl \
  --ref <upstream_commit_or_tag>
```

Other supported suites:

```bash
python benchmarks/import_official_exports.py --suite pint --input /path/to/pint_export.yaml --ref <upstream_ref>
python benchmarks/import_official_exports.py --suite agentdojo --input /path/to/agentdojo_export.yaml --ref <upstream_ref>
python benchmarks/import_official_exports.py --suite jailbreakbench --input /path/to/jbb_export.jsonl --ref <upstream_ref>
python benchmarks/import_official_exports.py --suite harmbench --input /path/to/harmbench_export.jsonl --ref <upstream_ref>
python benchmarks/import_official_exports.py --suite injecagent --input /path/to/injecagent_export.jsonl --ref <upstream_ref>
python benchmarks/import_official_exports.py --suite mcpbench --input /path/to/mcpbench_export.jsonl --ref <upstream_ref>
python benchmarks/import_official_exports.py --suite mcp_bench --input /path/to/accenture_mcp_bench_export.jsonl --ref <upstream_ref>
```

This writes:
- `benchmarks/upstream/<suite>/v<ref8>/raw_samples.jsonl`
- `benchmarks/upstream/<suite>/v<ref8>/mapped_cases.jsonl`
- `benchmarks/upstream/<suite>/v<ref8>/README.md`

and updates `benchmarks/upstream/manifest.json` provenance metadata.

Supported values for `--suite`:
- `pint`
- `bipia`
- `agentdojo`
- `jailbreakbench`
- `harmbench`
- `injecagent`
- `mcpbench`
- `mcp_bench`

## Case format

Each line in `benchmarks/cases/*.jsonl` is one JSON object with:
- `id`: stable case identifier
- `suite`: suite name (`pint_style`, `bipia_style`, `agentdojo_style`)
- `kind`: evaluator type (`inbound_sanitize`, `tool_gate`, `tool_gate_auth`, `outbound_check`, `validation`, `error_sanitize`, `binding_replay`, `action_gate`, `source_gate`, `canary_check`, `rate_limit`)
- additional fields required by that `kind`

## Current Suites

- `pint_style`
- `bipia_style`
- `agentdojo_style`
- `owasp_llm_top10_style`
- `garak_style`
- `promptfoo_redteam_style`
- `mcp_protocol_abuse_style`
- `rag_poisoning_style`
- `secrets_exfil_style`
- `multistep_agent_attack_style`
- `unicode_evasion_style`
- `upstream_pint`
- `upstream_bipia`
- `upstream_agentdojo`
- `upstream_jailbreakbench`
- `upstream_harmbench`
- `upstream_injecagent`
- `upstream_mcpbench`
- `upstream_mcp_bench`

## Pinned Upstream Sources

From `benchmarks/upstream/manifest.json`:
- `pint` @ `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8` (`mapped_cases=16`)
- `bipia` @ `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` (`mapped_cases=124`)
- `agentdojo` @ `462c88ddf596cb745882702f9999c8aeb5fe467f` (`mapped_cases=26`)
- `jailbreakbench` @ `886acc352a31533ffbcf4ef22c744658688086fc` (`mapped_cases=200`)
- `harmbench` @ `8e1604d1171fe8a48d8febecd22f600e462bdcdd` (`mapped_cases=640`)
- `injecagent` @ `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` (`mapped_cases=240`)
- `mcpbench` @ `5f397445370e6cb44dfdfc5680a48f128a75d349` (`mapped_cases=4800`)
- `mcp_bench` @ `7a8eaeae83a842a2949080acc5473f65e1569daf` (`mapped_cases=320`)

## Dataset Licensing and Redistribution

Status below is based on upstream metadata observed on `2026-02-15` (repo license files / dataset cards). Treat this as an engineering compliance checklist, not legal advice.

| source | upstream | observed license signal | redistribution posture |
|---|---|---|---|
| `pint` | `lakeraai/pint-benchmark` | MIT | generally redistributable with copyright + license notice |
| `bipia` | `microsoft/BIPIA` | MIT repo license, with explicit dataset component exceptions in upstream `LICENSE` | conditionally redistributable; verify component-level terms before republishing raw examples |
| `agentdojo` | `ethz-spylab/agentdojo` | MIT | generally redistributable with notice |
| `jailbreakbench` | `JailbreakBench/JBB-Behaviors` (Hugging Face) | MIT (dataset card) | generally redistributable with notice |
| `harmbench` | `centerforaisafety/HarmBench` | MIT | generally redistributable with notice |
| `injecagent` | `uiuc-kang-lab/InjecAgent` | MIT | generally redistributable with notice |
| `mcpbench` | `modelscope/MCPBench` | Apache-2.0 | redistributable under Apache-2.0 conditions |
| `mcp_bench` | `Accenture/mcp-bench` | no top-level license file/metadata detected (README badge claims Apache-2.0) | treat as restricted until upstream publishes explicit license text |
| `wainjectbench` | `Norrrrrrr-lyn/WAInjectBench` | no top-level license file/metadata detected | treat as restricted until upstream publishes explicit license text |

Recommended policy for this repo:
- Keep provenance (`benchmarks/upstream/manifest.json`) and import scripts for every source.
- Redistribute raw upstream-derived fixtures only when an explicit permissive license is present and satisfied.
- For sources with unclear/no license, distribute loaders/importers plus pinned refs, and require users to fetch data from upstream themselves.
- Restricted sources are intentionally not vendored in git (`benchmarks/upstream/mcp_bench/`, `benchmarks/upstream/wainjectbench/`).

## Notes

- These are local benchmark profiles and not a full mirror of upstream benchmark repos.
- Upstream snapshots are expected to come from official exports/checkpoints pinned by commit/tag in provenance metadata.
- Upstream fixture provenance metadata is tracked in `benchmarks/upstream/manifest.json`.
- `compare_mitigations.py` compares `guardllm` against a `no_defense` baseline on identical cases and includes pinned export reference stats.
- Azure category moderation is intentionally excluded from the injection benchmark; Prompt Shields integration is tracked separately.
- Bedrock Guardrails can be compared on the text-only subset by providing a guardrail ID/version and AWS profile/region.
- The comparison report's "Official Reference" section summarizes pinned export dataset stats; it is not a direct upstream leaderboard scrape.
