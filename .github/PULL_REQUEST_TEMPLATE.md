<!--
Thanks for sending a PR. Please fill in the sections below so reviewers can
understand the change quickly. For security-sensitive changes, see
CONTRIBUTING.md for what reviewers will look for.
-->

## Summary

<!-- One or two sentences: what changed and why. -->

## Threat-model relevance

<!--
If this touches sanitizer / detector / policy engine / request binding /
outbound DLP, describe how the change affects the in-scope threats in
docs/threat_model.md. If it does not, write "None".
-->

## Test and benchmark impact

<!--
- New or changed tests:
- Benchmark deltas (if any) from `python benchmarks/run_benchmarks.py`:
- Performance impact:
-->

## Backwards compatibility

<!-- Public API moves, deprecation notes, config format changes. If none, write "None". -->

## Checklist

- [ ] Tests added or updated (`tests/security/` for primitives, `tests/integration/` for documented flows)
- [ ] `ruff check .` passes
- [ ] `pytest` passes locally
- [ ] CHANGELOG.md updated under `[Unreleased]` if user-visible
- [ ] No changes to benchmark datasets (`CSE-8000`, `CBX-1200`, etc.) — those go through `benchmarks/methodology.md`
- [ ] No edits to `paper/`
