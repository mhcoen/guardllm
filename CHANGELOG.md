# Changelog

All notable changes to GuardLLM are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-07-10

This release completes the session-risk feedback mechanism designed in the "metadata circulation in the LLM systems loop" work: egress DLP verdicts now persist as session state and gate subsequent tool execution. The `escalated_tool_policy` default of `require_auth` is a behavior-changing default for any deployment that hits the DLP-block-then-tool-call sequence, so this is a major version bump.

### Added
- Egress feedback escalation: the backward-propagating complement of `_context_contaminated`. A DLP hard block at egress (`check_outbound`) now sets a monotonic, session-scoped escalation flag, and subsequent tool calls are gated by the new `PolicyConfig.escalated_tool_policy` (`"allow"` | `"require_auth"` | `"deny"`, default `"require_auth"`). Contamination and escalation are independent signals; when both fire the strictest policy wins, and the denial reason names each contributing trigger with its policy (e.g. `session contaminated=deny; egress escalated=require_auth`). Exposed via a read-only `SecurityPipeline.session_escalated` property. Cleared only by `reset()`, which hosts must call only at genuine session boundaries. See "Session Risk Signals" in `docs/security.md`.
- Benchmark kind `egress_feedback_escalation` covering the mechanism (require_auth default, deny/allow options, strictest-wins vs contamination, monotonicity, and reset clearing).

## [1.2.0] - 2026-07-09

### Security
- Injection detection now strips zero-width, bidi, and tag characters before scanning, so a trigger word split by an invisible character (e.g. U+200B) no longer evades detection.
- Outbound secret scanning now inspects invisible-stripped and whitespace-removed forms, so a key split by a space or zero-width character is still caught. The high-entropy scan gained a length-aware threshold that closes a dead zone for 20-22 character tokens, and covers the whitespace-removed form (gated to digit-bearing tokens to avoid flagging natural language).
- Canary detection is now case- and separator-insensitive, so an exfiltrated token cannot be hidden by re-casing or inserting spaces/zero-width characters.
- `wrap_untrusted` neutralizes any `</untrusted_content>` sentinel embedded in untrusted content and XML-escapes attribute values, preventing untrusted content from breaking out of or spoofing the isolation boundary.
- `validate_arguments` now applies path-traversal and null-byte checks to every argument (not just six named ones), recurses into lists/dicts including dict keys, and is depth-bounded to reject deeply nested or cyclic input instead of raising `RecursionError`.
- `guard_tool_call` now enforces the escalation gate: web-derived context (INV-MUSE-7) and `confirm_all_below` force confirmation, failing closed when no handler is configured.
- The policy engine now binds client-mode authorizations to the current user message: a mismatching message hash is denied as replay.

### Added
- `PolicyConfig.require_message_binding` (`"off"` | `"destructive"` | `"all"`): anti-replay message binding; fail-closed opt-in for a missing current message hash.
- `PolicyConfig.server_default_deny`: server-mode fail-closed when `capability_scopes` is unset.
- `recipient` parameter on `Guard.check_tool_call`, `Guard.check_outbound`, and `Guard.guard_tool_call`, feeding novel-recipient rate-limit anomaly detection.
- `GateResult.anomalies` and `OutboundResult.anomalies`: non-blocking rate-limit signals (burst, novel recipient), also recorded in the audit trail.

### Fixed
- The rate limiter now records permitted actions on the success path, so per-session limits actually accumulate and eventually trip.

### Changed
- `confusables` (>=1.2) is now a declared runtime dependency; when it is absent, TR39 homoglyph normalization emits a `RuntimeWarning` instead of silently degrading to a no-op.
- `normalize_confusables` now maps homoglyphs only within mixed-script letter runs (the attack signature) instead of flattening every confusable to ASCII. Legitimate single-script international text (accented Latin, Cyrillic, en-dashes) is preserved. This also makes the benchmark deterministic across platforms and regardless of whether `confusables` is installed, resolving the cross-platform `upstream_mcpbench` discrepancy noted in the 1.1.0 checkpoint entry.
- Pinned `soupsieve>=2.8.4` (transitive via `beautifulsoup4`) to pick up the fix for GHSA-2wc2-fm75-p42x (memory exhaustion via large comma-separated selector lists).

## [1.1.0] - 2026-05-28

### Added
- `SECURITY.md` vulnerability reporting policy with disclosure timeline and scope.
- `CONTRIBUTING.md` developer guide covering setup, tests, benchmarks, and security-sensitive review expectations.
- `CHANGELOG.md` (this file), reconstructed from git history for 1.0.x.
- `docs/threat_model.md` explicit threat model: trust boundaries, adversary capabilities, in-scope vs out-of-scope threats.
- `py.typed` marker (PEP 561) so downstream type checkers honor GuardLLM's annotations.
- Expanded top-level `__all__` so the public API is explicit on `from guardllm import ...` (`AuditEvent`, `AuthorizationEvent`, `Binding`, `ContentType`, `GateResult`, `OutboundResult`, `PolicyConfig`, `ProcessedContent`, `SecurityContext`, `SensitivityLevel`, `TrustLevel`, `ValidationResult`).
- GitHub Actions: CodeQL security scan workflow.
- GitHub Actions: lint and supply-chain job (ruff, pip-audit, bandit) running in parallel with the test matrix.
- Python 3.13 in the CI matrix alongside 3.10-3.12.
- Dependabot configuration for pip and GitHub Actions updates.
- Issue templates (bug report, feature request, security-report stub) and PR template.
- Ruff configuration in `pyproject.toml`.
- README badges: CI status, Python versions, license.

### Changed
- Empty `auth_scope` on a non-destructive tool is now treated as "no per-arg restriction" rather than denying every arg key. Destructive tools continue to require explicit per-arg scope coverage; non-empty scopes continue to enforce subset coverage to prevent parameter-expansion attacks (authorize `to=alice`, LLM tacks on `bcc=eve`). Fixes the `contaminated_tool_policy=require_auth` flow for read/search tools that don't enumerate every argument in scope.
- Modernized typing across the security package: PEP 585 builtin generics, PEP 604 unions, dropped legacy `typing.Dict`/`List`/`Optional` aliases. Source-level change only; the package already used `from __future__ import annotations`.
- Applied ruff format across the tree for consistent style.
- Regenerated `benchmarks/checkpoints/official-baseline.json` against CI's actual run output (Ubuntu, Python 3.10 through 3.13). The prior checkpoint (captured Feb 22 2026) predated the `error_sanitize_suite` and `tool_gate_contamination_style` suites, the growth of `mcp_protocol_abuse_style` from 5 to 8 cases, and the auth-scope fix in this release. The non-redistributable `upstream_wainjectbench` suite remains gitignored and is excluded from the checkpoint. The 7 expected failures are upstream data bugs (6 in mcpbench, 1 in jailbreakbench) where `expect_contains` is literally not present in `input` due to whitespace differences. Local macOS runs see ~30 additional `upstream_mcpbench` failures on cases containing Polish, French, em-dash, and CJK characters due to platform unicodedata differences with TR39 normalization; those are not regressions and the gate uses CI as the source of truth. New baseline: 7108 cases / 7101 pass / 7 fail (99.9%).

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

[Unreleased]: https://github.com/mhcoen/guardllm/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/mhcoen/guardllm/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/mhcoen/guardllm/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/mhcoen/guardllm/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/mhcoen/guardllm/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mhcoen/guardllm/releases/tag/v1.0.0
