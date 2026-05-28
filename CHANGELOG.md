# Changelog

All notable changes to GuardLLM are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Regenerated `benchmarks/checkpoints/official-baseline.json` against the CI-visible corpus (the non-redistributable `upstream_wainjectbench` suite remains gitignored and is excluded from the checkpoint, matching how `fc842dc` was built). The prior checkpoint (captured Feb 22 2026) predated several legitimate additions and intentional behavior changes: the `error_sanitize_suite` and `tool_gate_contamination_style` suites were added; `mcp_protocol_abuse_style` grew from 5 to 8 cases (all pass); the Feb-24 TR39 confusable normalization (`8ced9ae`) and the auth-scope fix in this release shifted ~30 `upstream_mcpbench` results. The remaining 37 failed-case IDs reflect known upstream data quirks (whitespace mismatches between `input` and `expect_contains` in the upstream mcpbench JSONL) plus the intentional FP cost of homoglyph hardening on Polish, French, em-dash, and CJK text. Local runs with the wainjectbench fixtures present continue to use `--allow-extra-suites` to compare only the checkpoint-covered subset. New baseline: 7108 cases / 7071 pass / 37 fail (99.48%).

### Added
- `SECURITY.md` vulnerability reporting policy with disclosure timeline and scope.
- `CONTRIBUTING.md` developer guide covering setup, tests, benchmarks, and security-sensitive review expectations.
- `CHANGELOG.md` (this file), reconstructed from git history for 1.0.x.
- `docs/threat_model.md` explicit threat model: trust boundaries, adversary capabilities, in-scope vs out-of-scope threats.
- `py.typed` marker (PEP 561) so downstream type checkers honor GuardLLM's annotations.
- Expanded top-level `__all__` so the public API is explicit on `from guardllm import ...`.
- GitHub Actions: CodeQL security scan workflow.
- GitHub Actions: lint and supply-chain job (ruff, pip-audit, bandit) running in parallel with the test matrix.
- Python 3.13 in the CI matrix alongside 3.10-3.12.
- Dependabot configuration for pip and GitHub Actions updates.
- Issue templates (bug report, feature request, security-report stub) and PR template.
- Ruff configuration in `pyproject.toml`.
- README badges: CI status, Python versions, license.

## [1.0.3] - 2026-02-26

### Fixed
- Audit findings #6, #7, #9, #10 across code/paper alignment.
- Empty allowlist now deny-by-default (operator-friendly safe default).
- `compare_mitigations` surface-kinds handling and outbound-check evaluation.
- F1 metric reporting on benchmark suites.

### Changed
- `surface_stack` is now reported as the Table 1 baseline.
- CSE-8000 generator uses a single shared RNG seed for reproducibility.

### Added
- Compound inbound processing path (`process_inbound_compound`).
- CSE-8000 generator rewritten with diverse case patterns.

## [1.0.2] - 2026-02-22

### Added
- Two-axis trust model: `source_trust` + `principal_trust`.
- CBX-1200 benchmark suite.
- TR39 confusable normalization.
- Hex decode-then-scan path in the sanitizer.

### Fixed
- Close 10 CSE-8000 false negatives (F1 0.999 → 1.000).
- Correct parameter name in `roc_pr_experiments.py`.
- Audit findings 3-12 (code/paper alignment).

### Changed
- `SURFACE_KINDS` aligned to paper terminology.
- Markdown docs updated for two-axis trust model.

## [1.0.1] - 2026-02-18

### Changed
- Benchmark suite loads from canonical-v1 dataset; runtime rebalancing removed.
- Renamed `non_text` / `text_only` benchmark axes to `surface` / `injection_only`.
- Rebalanced compositional suite; expanded `error_sanitize` coverage.

### Added
- Optional dependency groups: `benchmarks`, `gpu`, `examples`.
- BIPIA license verification note.

### Fixed
- CI checkpoint handling for non-redistributable suites.

## [1.0.0] - 2026-02-13

### Added
- Initial public release.
- Inbound pipeline: sanitization (HTML/CSS stripping, hidden-element removal), source/trust labeling, `<untrusted_content>` isolation, heuristic prompt-injection detection, canary token detection.
- Authorization and policy: tool authorization gate, action gate with confirmation path, source gate for KG extraction and quarantine, OAuth/OIDC integration patterns.
- Integrity and replay: request binding for tool calls, anti-replay checks, rate limiting, argument schema validation.
- Outbound and audit: outbound DLP and provenance copy controls, provenance tracking, error sanitization, structured audit logging hooks.
- Documentation: quick start, security architecture, API reference, configuration, integration patterns, production checklist, troubleshooting.
- Tutorials and examples covering MCP client/server hardening, web/email/document/calendar untrusted input, action gating, audit logging, validation, and a full end-to-end flow.
- Benchmark methodology and canonical results comparing against OpenAI, Anthropic, AWS Bedrock Guardrails, Azure Prompt Shields, Llama Guard 4, and ProtectAI DeBERTa.

[Unreleased]: https://github.com/mhcoen/guardllm/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/mhcoen/guardllm/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/mhcoen/guardllm/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/mhcoen/guardllm/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mhcoen/guardllm/releases/tag/v1.0.0
