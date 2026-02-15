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

## Notes

- These are local benchmark profiles and not a full mirror of upstream benchmark repos.
- Upstream snapshots are expected to come from official exports/checkpoints pinned by commit/tag in provenance metadata.
- Upstream fixture provenance metadata is tracked in `benchmarks/upstream/manifest.json`.
- `compare_mitigations.py` compares `guardllm` against a `no_defense` baseline on identical cases and includes pinned export reference stats.
- Azure category moderation is intentionally excluded from the injection benchmark; Prompt Shields integration is tracked separately.
- Bedrock Guardrails can be compared on the text-only subset by providing a guardrail ID/version and AWS profile/region.
- The comparison report's "Official Reference" section summarizes pinned export dataset stats; it is not a direct upstream leaderboard scrape.
