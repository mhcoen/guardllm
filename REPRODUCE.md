# Reproducing Paper Results

This guide provides step-by-step instructions for reproducing every claim in the paper. Commands are organized into tiers by resource requirements.

## Prerequisites

```bash
git clone https://github.com/mhcoen/GuardLLM.git
cd GuardLLM
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

- Python 3.10 or later (tested on 3.10, 3.11, 3.12)
- Reference platform: Mac M3 Max with 128 GB unified memory (all timings below are from this machine)
- Core dependency: `beautifulsoup4>=4.12` (installed automatically)
- No external API keys or GPU required for Tier 1 and Tier 2

## Tier 1: Unit Tests and Regression Suite (no API keys, no GPU)

### Run the full test suite

```bash
pytest -q
```

Expected: 429 tests pass.

### Run benchmark regression with checkpoint validation

```bash
python benchmarks/run_benchmarks.py \
  --checkpoint benchmarks/checkpoints/official-baseline.json
```

This evaluates all 12 control surface kinds across native and upstream-derived cases. The checkpoint enforces that pass/fail counts match the baseline exactly (modulo known-failed cases listed in the checkpoint file).

Expected output: checkpoint comparison passes with 6,919 cases, 6,912 passed, 7 known failures.

### Run the eval suite (non-injection controls)

```bash
pytest tests/ -k eval_suite --tb=short
```

This parametrizes each non-`inbound_sanitize` benchmark case as an individual pytest test, covering tool gating, authorization, validation, error sanitization, binding replay, action gating, source gating, rate limiting, canary detection, outbound checks, and contaminated-context exfiltration.

## How Benchmark Data Is Organized

Benchmark cases come from two sources, both committed in the repository:

1. **Native fixtures** in `benchmarks/cases/*.jsonl` (553 cases across 13 files): hand-authored threat patterns covering prompt injection, tool abuse, secrets exfiltration, unicode evasion, cross-boundary exfiltration, and more.

2. **Upstream-derived snapshots** in `benchmarks/upstream/<suite>/<version>/mapped_cases.jsonl` (up to 10,064 cases across 9 suites): imported from pinned commits of external benchmark repositories (PINT, BIPIA, AgentDojo, JailbreakBench, HarmBench, InjecAgent, MCPBench, mcp-bench, WAInjectBench).

All upstream snapshots are committed and available after `git clone`. No separate download or build step is needed to run Tier 1 or Tier 3 benchmarks.

The scripts `run_benchmarks.py` and `compare_mitigations.py` load cases directly from these two locations. The `build_dataset.py` script (Tier 2) assembles them into a single canonical dataset package for the ROC/PR experiments, which require a unified `cases.jsonl` with provenance metadata.

### Upstream provenance

Each upstream suite is pinned to a specific commit SHA in `benchmarks/upstream/manifest.json`. To verify provenance or re-import from upstream:

```bash
# View pinned refs and case counts
python -c "
import json; m = json.loads(open('benchmarks/upstream/manifest.json').read_text())
for s in m['sources']:
    print(f\"{s['suite']:20s} ref={s['ref'][:12]} mapped={s['mapped_cases']}\")
"
```

Two suites (`mcp_bench`, `wainjectbench`) have unclear upstream licensing. Their snapshots are included for research reproducibility but should not be redistributed without verifying upstream license terms. See `benchmarks/DATASET_REPRO.md` for the full acquisition and re-import protocol.

## Tier 2: Deterministic Dataset Rebuild and ROC/PR Curves (no API keys)

### Rebuild the canonical dataset

```bash
SOURCE_DATE_EPOCH=0 python benchmarks/build_dataset.py --dataset-id canonical-v1
```

Output: `benchmarks/datasets/canonical-v1/` containing `cases.jsonl`, `case_manifest.json`, and `METADATA.json`.

Verify determinism by running the command twice and comparing SHA-256 hashes:

```bash
shasum -a 256 benchmarks/datasets/canonical-v1/cases.jsonl
```

The hash should match `METADATA.json`'s `dataset_hash_sha256` field.

### Run ROC/PR experiments (GuardLLM-only, local)

```bash
python benchmarks/roc_pr_experiments.py \
  --run-id rocpr-canonical-local \
  --dataset-id canonical-v1
```

This produces dev/test split analysis with threshold selection on dev and frozen evaluation on test. All curves are dev-sourced. 95% Wilson confidence intervals are computed for recall, precision, and FPR.

Output: `benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.json` and `.md`

### Generate ROC and PR figures

```bash
python benchmarks/plot_roc_pr.py --run-id rocpr-canonical-local
```

Output: `benchmarks/runs/rocpr-canonical-local/roc_curve.svg` and `pr_curve.svg`

## Tier 3: Local Competitor Comparison (no API keys)

### Run GuardLLM vs. baselines on all cases

This loads cases directly from the committed fixture files (see "How Benchmark Data Is Organized" above). No dataset build step is required.

```bash
python benchmarks/compare_mitigations.py --run-id comparison-local
```

This evaluates `guardllm`, `isolation_only`, `source_gate_only`, `regex_rule_based`, and `no_defense` strategies on all benchmark cases. No external API calls are made.

Output: `benchmarks/runs/comparison-local/comparison.json` and `comparison.md`

### Non-text control results (Table 5 claims)

The comparison report includes a non-text controls section. Key claims to verify:
- GuardLLM: 100% on non-text controls
- `non_text_stack` (OPA + Redis + Casbin + JSON Schema composed): ~61% on non-text controls
- `no_defense`: ~13% on non-text controls

Optional non-text-stack dependencies (soft-imported, not required):

```bash
pip install casbin pydantic jsonschema
# OPA: download from https://www.openpolicyagent.org/docs/latest/#running-opa
# Redis: install via package manager (brew install redis, apt install redis-server)
```

## Tier 4: Vendor API Comparisons (requires API keys)

### OpenAI and Anthropic

```bash
python benchmarks/compare_mitigations.py \
  --run-id comparison-vendors \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-4.1-mini" \
  --anthropic-api-key "$ANTHROPIC_API_KEY" \
  --anthropic-model "claude-3-5-haiku-latest"
```

### Azure Prompt Shields

```bash
python benchmarks/compare_mitigations.py \
  --run-id comparison-azure \
  --azure-endpoint "https://<name>.cognitiveservices.azure.com" \
  --azure-key "$AZURE_KEY"
```

### AWS Bedrock Guardrails

```bash
python benchmarks/compare_mitigations.py \
  --run-id comparison-bedrock \
  --bedrock-guardrail-id "$BEDROCK_GUARDRAIL_ID" \
  --bedrock-guardrail-version "$BEDROCK_GUARDRAIL_VERSION" \
  --bedrock-profile "bedrockbench" \
  --bedrock-region "us-east-1"
```

### Full comparison with all vendors

```bash
python benchmarks/compare_mitigations.py \
  --run-id comparison-full \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-4.1-mini" \
  --anthropic-api-key "$ANTHROPIC_API_KEY" \
  --anthropic-model "claude-3-5-haiku-latest" \
  --azure-endpoint "https://<name>.cognitiveservices.azure.com" \
  --azure-key "$AZURE_KEY" \
  --bedrock-guardrail-id "$BEDROCK_GUARDRAIL_ID" \
  --bedrock-guardrail-version "$BEDROCK_GUARDRAIL_VERSION" \
  --bedrock-profile "bedrockbench" \
  --bedrock-region "us-east-1"
```

## Tier 5: GPU Competitors

### ProtectAI DeBERTa

```bash
pip install transformers torch
python benchmarks/compare_mitigations.py \
  --run-id comparison-deberta \
  --open-source-model-id "protectai/deberta-v3-base-prompt-injection-v2"
```

Runs on CPU (slower) or GPU (automatic detection via PyTorch). Paper numbers (27ms avg latency) were collected on Mac M3 Max using MPS (Metal Performance Shaders) acceleration. On CUDA GPUs, latency will be similar or faster. On CPU, expect ~100-200ms per inference.

### Meta Llama Guard 4 (12B)

Requires a GPU with sufficient VRAM (A100 80GB recommended). Paper results were generated on an A100.

```bash
pip install torch transformers huggingface_hub
python benchmarks/eval_llama_guard4.py --run-id llama-guard4-v1
```

Merge Llama Guard 4 results into the comparison table:

```bash
python benchmarks/compare_mitigations.py \
  --llama-guard-results benchmarks/runs/llama-guard4-v1/llama_guard4_eval/results.json \
  --run-id comparison-with-lg4
```

### DataFilter + GPT-4o (contaminated-context exfiltration)

```bash
python benchmarks/eval_datafilter_gpt4o_contaminated_context.py \
  --run-id datafilter-gpt4o-cc \
  --openai-api-key "$OPENAI_API_KEY"
```

## Verifying Specific Paper Claims

### Claim: GuardLLM processes inbound content in under 0.1ms

This is measured by the benchmark harness latency column. Run Tier 3 and check the `avg_latency_ms` field for `guardllm` in `comparison.json`.

### Claim: F1 = 85.46 on text-scope injection detection (3,823 records)

Run Tier 3 or Tier 4. The text-scope comparison section of `comparison.md` shows F1, precision, recall, and latency for all strategies. Record count (3,823) is the `injection`-scope text projection from the canonical dataset (1,021 attacks, 2,802 benign).

### Claim: 100% on non-text controls

Run Tier 3. The non-text comparison section shows GuardLLM at 100% across all non-text control kinds.

### Claim: ~10,000x faster than neural-based alternatives

Compare GuardLLM's avg latency (0.07ms) against vendor latencies in the comparison table. The ratio against typical neural classifiers (27ms for DeBERTa, 178ms for Llama Guard 4, 600-750ms for API-based) ranges from ~400x to ~10,000x.

### Claim: ROC/PR curves with dev/test split

Run Tier 2. The methodology uses deterministic stratified dev/test split (seed=1337, dev_fraction=0.30, dev_max_records=700). Threshold selection on dev only; frozen thresholds evaluated once on test with 95% Wilson intervals.

## Dataset Provenance

The canonical dataset (`canonical-v1`) is built from:
- 13 native fixture files in `benchmarks/cases/` (553 cases)
- 9 upstream-derived snapshots in `benchmarks/upstream/` (up to 10,064 cases)

All upstream sources are pinned by commit SHA in `benchmarks/upstream/manifest.json`. Two suites (`mcp_bench`, `wainjectbench`) have unclear upstream licensing and must be fetched directly from their source repositories.

Full dataset provenance protocol: `benchmarks/DATASET_REPRO.md`
Upstream acquisition matrix: `benchmarks/upstream/manifest.json`

## Git Tags

For pinning specific paper versions, tag the submission commit:

```bash
git tag -a cacm-submission -m "CACM paper submission"
git push origin cacm-submission
```

## Output Directory Structure

All benchmark outputs are written to `benchmarks/runs/<run_id>/`:
- `latest.json`: core benchmark results
- `comparison.json` / `comparison.md`: competitor comparison
- `roc_pr_experiments.json` / `.md`: ROC/PR analysis
- `roc_curve.svg` / `pr_curve.svg`: figures
- `METADATA.json`: dataset provenance (when built with `--run-id`)

## Further Documentation

- Benchmark methodology and metric definitions: `benchmarks/methodology.md`
- Dataset rebuild protocol: `benchmarks/DATASET_REPRO.md`
- Auditor verification checklist: `benchmarks/VERIFICATION.md`
- Canonical result pointers: `benchmarks/results.md`
- Security architecture: `docs/security.md`
