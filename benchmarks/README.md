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
- Run-scoped outputs written under `benchmarks/runs/<run_id>/`.

## Publication Artifacts

- Protocol and metric definitions: `benchmarks/methodology.md`
- Dataset rebuild and provenance flow: `benchmarks/DATASET_REPRO.md`
- Auditor checklist: `benchmarks/VERIFICATION.md`
- Canonical summary tables/figures: `benchmarks/results.md`

## Reproducing Paper Results

The benchmark harness uses two scripts with distinct roles:

- **`run_benchmarks.py`**: Runs GuardLLM-only evaluation (per-case pass/fail against expected outcomes).
- **`compare_mitigations.py`**: Produces the baseline vs GuardLLM comparison table matching **paper Table 1** (CSE-8000). This is the script a reviewer needs for paper reproduction.

To reproduce the paper's Table 1 (CSE comparison across 8 security kinds):

```bash
python benchmarks/compare_mitigations.py --run-id paper-repro
```

This outputs `benchmarks/runs/<run_id>/comparison.md` (Table 1 format) and `benchmarks/runs/<run_id>/comparison.json` with per-strategy, per-kind, and partition-level (call-local / cross-stage) metrics.

## Run

```bash
python benchmarks/run_benchmarks.py --run-id core-local
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

Run outputs are written to `benchmarks/runs/<run_id>/latest.json` and `benchmarks/runs/LATEST.txt` is updated.

Build canonical dataset package:

```bash
python benchmarks/build_dataset.py --dataset-id canonical-v1
```

Generate mitigation comparison tables:

```bash
python benchmarks/compare_mitigations.py --run-id comparison-local
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
- `benchmarks/runs/<run_id>/comparison.json`
- `benchmarks/runs/<run_id>/comparison.md`

Run ROC/PR and operating-point experiments (dev/test split, threshold selection on dev, frozen test eval):

```bash
python benchmarks/roc_pr_experiments.py --run-id rocpr-local
```

Optional vendor runs with tool-based structured outputs:

```bash
python benchmarks/roc_pr_experiments.py \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-4.1-mini" \
  --anthropic-api-key "$ANTHROPIC_API_KEY" \
  --anthropic-model "claude-3-5-haiku-latest"
```

ROC/PR outputs:
- `benchmarks/runs/<run_id>/roc_pr_experiments.json`
- `benchmarks/runs/<run_id>/roc_pr_experiments.md`
- optional figures: `benchmarks/runs/<run_id>/roc_curve.svg`, `benchmarks/runs/<run_id>/pr_curve.svg`

Runtime behavior for `roc_pr_experiments.py`:
- Per-record scoring is cache-backed and resumable across reruns via `benchmarks/cache/roc_score_cache.jsonl`.
- Long-running scorers print status/progress every 2 minutes.
- `benchmarks/runs/LATEST.txt` is updated to the latest run id.

Current comparison strategies:
- `guardllm`: full GuardLLM controls
- `surface_stack`: point-tool stack baseline (Casbin + JSON Schema + Redis + OPA). This is the paper Table 1 baseline.
- `isolation_only`: inbound isolation-only baseline
- `source_gate_only`: source-gate-only baseline
- `no_defense`: allow-all lower-bound control

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
- `kind`: evaluator type (`inbound_sanitize`, `tool_gate`, `tool_gate_auth`, `tool_gate_contamination`, `outbound_check`, `validation`, `error_sanitize`, `binding_replay`, `action_gate`, `source_gate`, `canary_check`, `rate_limit`)
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
- `tool_gate_contamination_style`
- `upstream_pint`
- `upstream_bipia`
- `upstream_agentdojo`
- `upstream_jailbreakbench`
- `upstream_harmbench`
- `upstream_injecagent`
- `upstream_mcpbench`
- `upstream_mcp_bench`

## Paper-Cited Evaluation Datasets

Three datasets are cited in the CACM paper. All are deterministically generated
from pinned seeds and upstream sources.

### CBX-1000

1000 contaminated-context exfiltration cases. Attacker text sampled verbatim
from four MIT-licensed repos.

- Dataset: `artifacts/cbx1000/cbx_1000_v1_seed20260222.jsonl`
- Manifest: `artifacts/cbx1000/cbx_1000_v1_manifest_seed20260222.json`
- Generator: `scripts/gen_cbx1000.py`
- Distribution: 500 expected BLOCK, 350 expected ALLOW, 150 REPORT_LIMITATION
- Seed: `20260222`

Attacker text sources (cloned automatically by the generator):

| repo | commit | license |
|---|---|---|
| `uiuc-kang-lab/InjecAgent` | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT |
| `ethz-spylab/agentdojo` | `462c88ddf596cb745882702f9999c8aeb5fe467f` | MIT |
| `lakeraai/pint-benchmark` | `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8` | MIT |
| `Giskard-AI/prompt-injections` | `ce50a549dadc46b48c931250d2dd71d5f003c0c2` | MIT |

Rebuild:

```bash
python scripts/gen_cbx1000.py
```

Evaluate:

```bash
python benchmarks/eval_cbx1000.py
```

### CBX-1200

1200 contaminated-context exfiltration cases with expanded secret types.
Extends CBX-1000 with pii, internal_id, and contract_text secret kinds
(composite strings of 40-80 chars) alongside the original api_key,
bearer_token, and webhook_url kinds.

Evaluation runs each case through two independent pipeline configurations:

- Variant A (VA): No sensitive buffer. Only secret-pattern regex, entropy
  scanning, and hex decode-then-scan can fire. No overlap comparison.
- Variant B (VB): Full contaminated-context mechanism. Sensitive buffer
  populated via `process_inbound`, overlap comparison active.

- Dataset: `artifacts/cbx1200/cbx_1200_v1_seed20260224.jsonl`
- Manifest: `artifacts/cbx1200/cbx_1200_v1_manifest_seed20260224.json`
- Generator: `scripts/gen_cbx1200.py`
- Evaluator: `benchmarks/eval_cbx1200.py`
- Distribution: 780 ATTACK (600 within-scope, 180 out-of-scope encoding),
  300 BASELINE, 120 NEAR_MISS
- Seed: `20260224`

Within-scope transform operators: `verbatim_copy`, `prefix_fragment`,
`middle_fragment`, `suffix_fragment`, `insert_separators`,
`markdown_link_wrap`, `json_reformat`.

Out-of-scope encoding operators: `hex_encode`, `rot13`, `leetspeak`,
`homoglyph_substitution`.

Attacker text sources (same repos as CBX-1000):

| repo | commit | license |
|---|---|---|
| `uiuc-kang-lab/InjecAgent` | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT |
| `ethz-spylab/agentdojo` | `462c88ddf596cb745882702f9999c8aeb5fe467f` | MIT |
| `lakeraai/pint-benchmark` | `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8` | MIT |
| `Giskard-AI/prompt-injections` | `ce50a549dadc46b48c931250d2dd71d5f003c0c2` | MIT |

Rebuild:

```bash
python scripts/gen_cbx1200.py
```

Evaluate:

```bash
python benchmarks/eval_cbx1200.py
```

### Invariance Suites (A/B/C)

Three 1000-case suites with identical transform programs but different untrusted
text sources. Proves detection is mechanism-driven, not corpus-tuned.

- Suite A (LLM injections): `artifacts/suites/suiteA_llm_N1000_seed20260222.jsonl`
- Suite B (OWASP payloads): `artifacts/suites/suiteB_owasp_N1000_seed20260222.jsonl`
- Suite C (benign noise): `artifacts/suites/suiteC_benign_N1000_seed20260222.jsonl`
- Manifests: `artifacts/suites/suite{A,B,C}_*_manifest_seed20260222.json`
- Generator: `scripts/gen_suites/gen_attack_suites.py`
- Distribution per suite: 500 expected BLOCK, 350 expected ALLOW, 150 REPORT_LIMITATION
- Seed: `20260222`

Pool files (in `artifacts/suites/cache/`):

| pool file | lines | source |
|---|---|---|
| `llm_injection.txt` | 219 | Extracted from InjecAgent, AgentDojo, PINT, Giskard (same repos as CBX-1000) |
| `owasp_payload.txt` | 7,191 | Real payloads from OWASP CRS regression tests + PayloadsAllTheThings |
| `benign_noise.txt` | 15,371 | Real email bodies from EnronSent Corpus v1.0 |

Pool provenance for OWASP payloads is recorded in
`artifacts/suites/cache/owasp_payload_provenance.json`:

| repo | commit | license |
|---|---|---|
| `coreruleset/coreruleset` | `5486e697bd336cedca4a0d4cece16722a6088235` | Apache-2.0 |
| `swisskyrepo/PayloadsAllTheThings` | `10d41d2e7de0de20c424c90ceb118a5993110081` | MIT |

Pool build scripts: `scripts/gen_suites/sources_llm.py`,
`scripts/gen_suites/sources_owasp.py`.

Rebuild pools and suites:

```bash
# Rebuild pool files (requires cloning upstream repos)
python scripts/gen_suites/sources_llm.py --cache_dir artifacts/suites/cache
python scripts/gen_suites/sources_owasp.py --cache_dir artifacts/suites/cache

# Generate suites
python scripts/gen_suites/gen_attack_suites.py \
  --outdir artifacts/suites --seed 20260222 \
  --cache_dir artifacts/suites/cache
```

Evaluate:

```bash
python benchmarks/eval_invariance_suites.py
```

### Benign Library (False-Positive Measurement)

2000 all-benign cases for measuring false positive rates. Every case is
expected ALLOW; any block is a false positive.

- Dataset: `artifacts/suites/benign_library_N2000_seed20260222.jsonl`
- Manifest: `artifacts/suites/benign_library_manifest_seed20260222.json`
- Generator: `scripts/gen_suites/gen_benign_library.py`
- Strata: 666 uncontaminated/sensitive, 666 contaminated/sensitive, 668 contaminated/no-sensitive
- Seed: `20260222`
- Benign pool: `artifacts/suites/cache/benign_noise.txt` (15,371 real Enron emails)

Rebuild:

```bash
python scripts/gen_suites/gen_benign_library.py \
  --outdir artifacts/suites --seed 20260222 \
  --benign_pool artifacts/suites/cache/benign_noise.txt --N 2000
```

Evaluate:

```bash
python benchmarks/eval_benign_library.py
```

### External Data: EnronSent Corpus

The benign pool (`benign_noise.txt`) is built from real email text. The pool
file is included in the repository, but to rebuild it from scratch:

1. Download the EnronSent Corpus v1.0:
   ```
   http://wstyler.ucsd.edu/files/enronsentv1.tar.gz
   ```
   Size: ~25 MB. License: public domain (William Styler, UC Colorado preparation
   of the Enron Sent Corpus).

2. Extract and process:
   ```bash
   mkdir -p /tmp/enron && cd /tmp/enron
   curl -LO http://wstyler.ucsd.edu/files/enronsentv1.tar.gz
   tar xzf enronsentv1.tar.gz
   ```

3. The extraction script reads all `.txt` files under the extracted directory,
   deduplicates email bodies, filters to lines with 40+ characters and 40%+
   alphabetic content, and truncates each to 2000 characters. The result is
   written one email per line to `artifacts/suites/cache/benign_noise.txt`.

Pool integrity:
- Expected line count: 15,371
- SHA-256: `5f393c58297a6fb84bfa4d6b5d64540ac0f8098dec8663f95d14f190ea64d717`

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
- `compare_mitigations.py` compares `guardllm` against baseline strategies (point-tool stack `surface_stack` for Table 1, `no_defense` as lower-bound control) and includes pinned export reference stats.
- Azure category moderation is intentionally excluded from the injection benchmark; Prompt Shields integration is tracked separately.
- Bedrock Guardrails can be compared on the injection-detection subset by providing a guardrail ID/version and AWS profile/region.
- The comparison report's "Official Reference" section summarizes pinned export dataset stats; it is not a direct upstream leaderboard scrape.
