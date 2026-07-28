# Dataset Rebuild Protocol

<!-- nav:start -->
[Home](../README.md) / [Benchmarks](README.md)
<!-- nav:end -->

This protocol documents how to rebuild benchmark datasets with pinned provenance while handling non-redistributable upstream suites.

## Scope

- Dataset builder code: `benchmarks/build_dataset.py`.
- Upstream importer code: `benchmarks/import_official_exports.py`.
- Upstream source pins: `benchmarks/upstream/manifest.json`.
- Harness loader behavior: `benchmarks/run_benchmarks.py`.

## What The Builder Emits

Command:

```bash
cd <repo-root>
.venv312/bin/python benchmarks/build_dataset.py --dataset-id canonical-v1
```

Output directory:

- `benchmarks/datasets/canonical-v1/cases.jsonl`
- `benchmarks/datasets/canonical-v1/case_manifest.json`
- `benchmarks/datasets/canonical-v1/METADATA.json`

Implemented by:

- case loading + provenance: `benchmarks/build_dataset.py` (`_load_cases_with_provenance`)
- per-case hash + manifest: `benchmarks/build_dataset.py` (`case_sha256`, `source_file`, `source_class`)
- dataset hash + text hash: `benchmarks/build_dataset.py` (`_dataset_hash`, `_text_dataset_hash`)
- upstream snapshot audit hashes: `benchmarks/build_dataset.py` (`_manifest_source_audit`)

## Deterministic Canonicalization

Determinism is implemented by:

- stable source ordering (`benchmarks/build_dataset.py`, `_sorted_sources`, `_local_case_paths`)
- stable row ordering (`benchmarks/build_dataset.py`, `_load_cases_with_provenance`)
- canonical JSON serialization with sorted keys (`benchmarks/build_dataset.py`, `_sha256_json`, writes for `cases.jsonl` / manifest / metadata)
- reproducible timestamp mode via `SOURCE_DATE_EPOCH` (`benchmarks/build_dataset.py`, `source_date_epoch`)

When `SOURCE_DATE_EPOCH` is set, `METADATA.json` build timestamp fields are deterministic.

## Upstream Suite Acquisition Matrix

All pinned refs and snapshot targets come from `benchmarks/upstream/manifest.json`.

| suite | repo | pinned ref | expected snapshot dir | expected files |
|---|---|---|---|---|
| `pint` | `https://github.com/lakeraai/pint-benchmark` | `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8` | `benchmarks/upstream/pint/v0aa0d641` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |
| `bipia` | `https://github.com/microsoft/BIPIA` | `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` | `benchmarks/upstream/bipia/va004b69e` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |
| `agentdojo` | `https://github.com/ethz-spylab/agentdojo` | `462c88ddf596cb745882702f9999c8aeb5fe467f` | `benchmarks/upstream/agentdojo/v462c88dd` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |
| `jailbreakbench` | `https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors` | `886acc352a31533ffbcf4ef22c744658688086fc` | `benchmarks/upstream/jailbreakbench/v886acc35` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |
| `harmbench` | `https://github.com/centerforaisafety/HarmBench` | `8e1604d1171fe8a48d8febecd22f600e462bdcdd` | `benchmarks/upstream/harmbench/v8e1604d1` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |
| `injecagent` | `https://github.com/uiuc-kang-lab/InjecAgent` | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | `benchmarks/upstream/injecagent/vf19c9f2c` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |
| `mcpbench` | `https://github.com/modelscope/MCPBench` | `5f397445370e6cb44dfdfc5680a48f128a75d349` | `benchmarks/upstream/mcpbench/v5f397445` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |
| `mcp_bench` | `https://github.com/Accenture/mcp-bench` | `7a8eaeae83a842a2949080acc5473f65e1569daf` | `benchmarks/upstream/mcp_bench/v7a8eaeae` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |
| `wainjectbench` | `https://github.com/Norrrrrrr-lyn/WAInjectBench` | `4a5b7a5d4e393983d7105aed3485014b7206d205` | `benchmarks/upstream/wainjectbench/v4a5b7a5d` | `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md` |

## Automatic Import Path (When Redistribution Is Allowed)

Importer command shape (implemented in `benchmarks/import_official_exports.py`, `main`):

```bash
.venv312/bin/python benchmarks/import_official_exports.py \
  --suite <suite> \
  --input /path/to/upstream_export \
  --ref <pinned_ref> \
  --source-export <upstream_export_path>
```

Importer behavior:

- snapshot dir naming: `v<ref8>` unless overridden (`--snapshot-tag`)
- emits `raw_samples.jsonl`, `mapped_cases.jsonl`, `README.md`
- updates `benchmarks/upstream/manifest.json` with repo/ref/snapshot/path/counts

## Verification Checks Per Suite

For each suite in the manifest:

```bash
cd <repo-root>
jq -r '.sources[] | [.suite, .ref, .snapshot_dir, .imported_raw_records, .mapped_cases] | @tsv' benchmarks/upstream/manifest.json
```

Verify expected files exist and counts match manifest:

```bash
cd <repo-root>
for d in $(jq -r '.sources[].snapshot_dir' benchmarks/upstream/manifest.json); do
  test -f "$d/raw_samples.jsonl"
  test -f "$d/mapped_cases.jsonl"
  test -f "$d/README.md"
  echo "$d"
  wc -l "$d/raw_samples.jsonl" "$d/mapped_cases.jsonl"
  shasum -a 256 "$d/raw_samples.jsonl" "$d/mapped_cases.jsonl"
done
```

Cross-check manifest counts against actual line counts:

```bash
cd <repo-root>
python3 - <<'PY'
import json
from pathlib import Path
manifest = json.loads(Path("benchmarks/upstream/manifest.json").read_text())
for src in manifest["sources"]:
    d = Path(src["snapshot_dir"])
    raw = sum(1 for ln in (d/"raw_samples.jsonl").open() if ln.strip())
    mapped = sum(1 for ln in (d/"mapped_cases.jsonl").open() if ln.strip())
    print(src["suite"], src["imported_raw_records"], raw, src["mapped_cases"], mapped)
PY
```

## Restricted / Manual Acquisition

Suites currently marked restricted by repo policy:

- `mcp_bench`
- `wainjectbench`

Policy evidence is in `benchmarks/README.md` (licensing table + restricted note).

If redistribution is disallowed:

1. Do not commit upstream raw exports into this repository.
2. Acquire exports manually from pinned refs listed in `benchmarks/upstream/manifest.json`.
3. Run `import_official_exports.py` locally to produce snapshot files.
4. Verify local snapshots with the per-suite checks above (file presence, sha256, line counts, manifest counts).
5. Build final dataset with `benchmarks/build_dataset.py`.

`UNVERIFIED`: this repository does not itself prove external license grants for those restricted suites; auditors must validate licensing terms from upstream sources before redistribution.

## Dataset Build Metadata For Auditors

`METADATA.json` includes:

- `dataset_hash_sha256`
- `text_injection_dataset_hash_sha256`
- suite/kind/label counts
- `built_at_unix`, `built_at_iso_utc`
- `source_date_epoch` (if set)
- `git_sha`, `git_sha_short`
- upstream suite audit rows with file presence, sha256, and line counts (`upstream_sources`)

## Run-Scoped Metadata Copy

To write dataset metadata into a run directory:

```bash
cd <repo-root>
SOURCE_DATE_EPOCH=0 .venv312/bin/python benchmarks/build_dataset.py \
  --dataset-id canonical-v1 \
  --run-id verify-canonical-local
```

This writes:

- `benchmarks/datasets/canonical-v1/METADATA.json`
- `benchmarks/runs/verify-canonical-local/METADATA.json`
