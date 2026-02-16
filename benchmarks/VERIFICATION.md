# Verification Checklist

Note on prior discrepancy:

- The previous packet omitted some untracked/new files from the diff export path, so dataset/doc additions were incomplete in the shared patch.
- This packet fixes that by producing one unified diff (`benchmarks/verification_packet_full.diff`) that explicitly includes dataset pipeline files and publication docs, plus regenerated run artifacts from the updated code.

## 1) Environment

```bash
cd <repo-root>
.venv312/bin/python -m py_compile \
  benchmarks/build_dataset.py \
  benchmarks/output_layout.py \
  benchmarks/run_benchmarks.py \
  benchmarks/compare_mitigations.py \
  benchmarks/roc_pr_experiments.py \
  benchmarks/plot_roc_pr.py
```

No paid vendor APIs are required for this checklist.

## 2) Path Hygiene Check

```bash
cd <repo-root>
rg -n "(/Users/|/home/|[A-Za-z]:\\\\)" \
  benchmarks/*.py \
  benchmarks/DATASET_REPRO.md \
  benchmarks/methodology.md \
  benchmarks/results.md \
  docs/*.md \
  README.md \
  .gitignore
```

Expected: no matches.

## 3) Deterministic Dataset Rebuild (Twice)

Use fixed timestamp seed:

```bash
cd <repo-root>
SOURCE_DATE_EPOCH=0 .venv312/bin/python benchmarks/build_dataset.py \
  --dataset-id canonical-v1 \
  --run-id verify-canonical-local
cp benchmarks/datasets/canonical-v1/cases.jsonl /tmp/cases_a.jsonl
cp benchmarks/datasets/canonical-v1/case_manifest.json /tmp/manifest_a.json
cp benchmarks/datasets/canonical-v1/METADATA.json /tmp/meta_a.json

SOURCE_DATE_EPOCH=0 .venv312/bin/python benchmarks/build_dataset.py \
  --dataset-id canonical-v1 \
  --run-id verify-canonical-local
cp benchmarks/datasets/canonical-v1/cases.jsonl /tmp/cases_b.jsonl
cp benchmarks/datasets/canonical-v1/case_manifest.json /tmp/manifest_b.json
cp benchmarks/datasets/canonical-v1/METADATA.json /tmp/meta_b.json

shasum -a 256 /tmp/cases_a.jsonl /tmp/cases_b.jsonl /tmp/manifest_a.json /tmp/manifest_b.json /tmp/meta_a.json /tmp/meta_b.json
```

Expected:

- A/B checksums are identical for all three files.
- run-scoped metadata file exists: `benchmarks/runs/verify-canonical-local/METADATA.json`

## 4) Upstream Snapshot Verification (Including Restricted/Manual)

```bash
cd <repo-root>
jq -r '.sources[] | [.suite, .repo, .ref, .snapshot_dir, .source_export, .imported_raw_records, .mapped_cases] | @tsv' benchmarks/upstream/manifest.json
```

Per-suite local snapshot checks:

```bash
cd <repo-root>
for d in $(jq -r '.sources[].snapshot_dir' benchmarks/upstream/manifest.json); do
  test -f "$d/raw_samples.jsonl"
  test -f "$d/mapped_cases.jsonl"
  test -f "$d/README.md"
  wc -l "$d/raw_samples.jsonl" "$d/mapped_cases.jsonl"
  shasum -a 256 "$d/raw_samples.jsonl" "$d/mapped_cases.jsonl"
done
```

Restricted suites (`mcp_bench`, `wainjectbench`) must follow manual acquisition and local verification flow from `benchmarks/DATASET_REPRO.md`. Do not redistribute upstream raw exports unless licensing explicitly permits it.

## 5) ROC/PR Run Using Built Dataset (Local-Only)

```bash
cd <repo-root>
.venv312/bin/python benchmarks/roc_pr_experiments.py \
  --run-id rocpr-canonical-local \
  --dataset-id canonical-v1 \
  --openai-api-key '' \
  --anthropic-api-key '' \
  --azure-key '' \
  --azure-endpoint '' \
  --progress-seconds 120
```

Expected artifacts:

- `benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.json`
- `benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.md`
- `benchmarks/runs/rocpr-canonical-local/results.md`

Semantics checks:

```bash
cd <repo-root>
jq -r '.methods[] | .name + " curve_source=" + .curve_source' benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.json
jq -r '.methods[] | .name as $m | (.selected_operating_points // [])[]? | [$m, (has("meets_budget_dev")|tostring), (has("meets_budget_test")|tostring), (.test_intervals|type)] | @tsv' benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.json
rg -n "Default operating point semantics|meets_budget_dev|meets_budget_test|recall_ci95|precision_ci95|fpr_ci95" benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.md
```

Expected:

- all methods report `curve_source=dev`
- operating points include `meets_budget_dev` and `meets_budget_test`
- markdown includes default operating point semantics and CI columns

## 6) Plot Regeneration

```bash
cd <repo-root>
.venv312/bin/python benchmarks/plot_roc_pr.py --run-id rocpr-canonical-local
shasum -a 256 \
  benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.json \
  benchmarks/runs/rocpr-canonical-local/roc_curve.svg \
  benchmarks/runs/rocpr-canonical-local/pr_curve.svg
```

If you publish pinned figure hashes, update them only from this command.

## 7) Canonical Docs Cross-Check

- Protocol: `benchmarks/methodology.md`
- Dataset rebuild: `benchmarks/DATASET_REPRO.md`
- Canonical summary: `benchmarks/results.md`

All three should reference run-scoped or dataset-scoped artifacts under repo-relative paths.

## 8) UNVERIFIED Items

- Paid provider rows are `UNVERIFIED` in this checklist because no vendor APIs are invoked.
- External license grants for restricted suites are `UNVERIFIED` from repository files alone and require manual legal/license verification upstream.
