# Canonical Results (Local-Only, No Vendor APIs)

Surface-control figures on this page and the homepage are generated from the [published surface evidence](published/surface_controls.md), which is tracked and carries its run id, commit, and dataset hash. The prompt-injection vendor comparison is not yet published this way; see the scope note in that file.

This page points to the canonical run artifacts that are reproducible without paid providers.

## Canonical IDs

- dataset id: `canonical-v1`
- dataset build run id: `verify-canonical-local`
- roc/pr run id: `rocpr-canonical-local`

## Canonical Artifacts

- dataset metadata: `benchmarks/datasets/canonical-v1/METADATA.json`
- run-scoped dataset metadata copy: `benchmarks/runs/verify-canonical-local/METADATA.json`
- roc/pr json: `benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.json`
- roc/pr markdown: `benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.md`
- roc/pr summary: `benchmarks/runs/rocpr-canonical-local/results.md`
- roc figure: `benchmarks/runs/rocpr-canonical-local/roc_curve.svg`
- pr figure: `benchmarks/runs/rocpr-canonical-local/pr_curve.svg`

## Semantics Snapshot

From `benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.md`:

- all curves are dev-sourced (`curve_source=dev`)
- budget reporting uses split-specific flags:
  - `meets_budget_dev`
  - `meets_budget_test`
- default point semantics are explicitly documented
- frozen test operating points include CI columns:
  - `recall_ci95`
  - `precision_ci95`
  - `fpr_ci95`

## Verification Pointer

Use `benchmarks/VERIFICATION.md` for exact commands and expected checksums.
