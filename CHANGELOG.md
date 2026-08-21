# Changelog

All notable changes to GuardLLM are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Privacy vault: pseudonymization at the model boundary, with restoration scoped by tool field and by destination. Personal data detected on the way in is replaced with an opaque token before the prompt reaches the provider, and the real value is put back only where policy says it may go. Entirely opt-in: `Guard(..., privacy=PrivacyConfig(...))` or `SecurityPipeline(..., privacy=...)` constructs a vault, and without it nothing in this feature runs and no existing verdict changes. `seed_private_values`, `deidentify`, and `reidentify` raise `ValueError` when no vault was configured, rather than returning something that looks like a result; `prepare_tool_call` instead passes the arguments through with `reason="privacy disabled"`, so a host can call it unconditionally in its dispatch path. Surface: `Guard.seed_private_values`, `.deidentify`, `.reidentify`, `.prepare_tool_call`; `PrivacyConfig`, `PIIClass`, `ClassPolicy`, `Destination`, `PIIFinding`, `Detector`, `DeidentifyResult`, `PreparedCall`; and `SecurityPipeline.vault` for direct access. `ProcessedContent` gains `pii_findings`, `blocked`, `detection_incomplete`, and `inference_used`, all defaulted so existing readers are unaffected.
  - Detection ships two tiers and neither infers. **Declared values** are seeded by the host from a session it has already authenticated, so precision is exact. **Pattern detection** covers structured identifiers deterministically: email, phone, SSN, credit card by Luhn, IBAN, routing number, passport, driver's licence, national identity number, medical record number, and date of birth. A third tier is available through the `Detector` protocol for hosts that want to plug in their own recognizer; registration order cannot remove a finding another detector produced. `PrivacyConfig.classes` defaults to thirteen classes, two of which, `PERSON` and `ADDRESS`, no pattern can find: they are reachable only through seeded declared values or a registered detector, and are in the default set so that a host which does seed them gets them tokenized without extra configuration.
  - Restoration is deny-by-default in both directions. `restore_policy` maps a tool and a field path to the classes restorable there, `destination_policy` maps a destination to the classes it may receive, and a field or destination with no rule restores nothing. `prepare_tool_call` resolves tokens before the host builds its authorization event and binding, because both bind exact bytes and a scope authorized over a token fails against the restored value.
  - Fails closed throughout. A token that cannot be resolved, a token whose framing the model damaged, an unresolvable count past `max_unresolvable`, a vault at `vault_max_entries`, or an argument tree past `max_arg_depth` or `max_arg_nodes` all refuse the call rather than dispatching a partially resolved one. Tokens carry a Reed-Solomon check (`token_codec`) that corrects a single mangled symbol and refuses two, so an off-by-one transcription by the model is recovered rather than silently misresolved.

### Changed
- A missing confirmation handler is now reported as a configuration failure rather than as a user decision. `guard_tool_call(..., require_confirmation=True)` against a `SecurityContext` with no `confirmation_handler` previously denied with `reason="User denied confirmation"` and audited `user_confirmed=False`, although no user was consulted: the reason read like a working confirmation flow that an operator declined, so a missing handler failed quietly rather than obviously, and the audit trail asserted a decision nobody made. The call still denies. It now returns `reason="Confirmation unavailable: no confirmation handler configured"` and emits an `action_gate_unavailable` audit event with `user_confirmed=None`. `reason="User denied confirmation"` and `user_confirmed=False` are preserved for the case a handler actually returned False. **Callers matching on the reason string for the missing-handler case need to update.**

### Security
- G6 action-gate commitment now binds the exact argument bytes. `canonicalize_args` previously normalized whitespace, so a confirmed `{"cmd": "a\nb"}` and an executed `{"cmd": "a b"}` verified against the same commitment; whitespace-sensitive payloads (shell commands, prompts, regexes, file bodies) could be mutated after confirmation without tripping G6. Verification now compares exact canonical JSON.
- `SecurityContext.mode` is validated in `__post_init__`. It was documented as `"client"` or `"server"` but never checked, and the policy engine treats only exact `"server"` as server mode. A typo such as `mode="sever"` with `server_default_deny=True` silently fell through to the client implicit-allow path and admitted a non-destructive tool. Any mode outside `{"client", "server"}` now raises `ValueError`.
- `PrivacyVault.reidentify(..., allowed_classes=...)` now intersects with `destination_policy` instead of replacing it. It read as a per-call restriction and behaved as a per-call bypass: a destination entitled to `EMAIL` alone restored a full SSN when the caller passed `allowed_classes={PIIClass.SSN}`, so any caller who could choose the destination could choose the classes too, which is the whole of `destination_policy` undone by a keyword argument. Narrowing still narrows; a class the destination does not permit is now withheld however the argument is written.
- `class_policy` can no longer weaken a mandatory-deny class. It was consulted before `DEFAULT_DENY_CLASSES`, so `class_policy={PIIClass.CREDENTIAL: ClassPolicy.ALLOW}` won outright and a recognized OpenAI key crossed to the model provider unchanged. `PrivacyConfig` now raises `ValueError` on such a config rather than ignoring the entry silently, and `policy_for` checks the mandatory-deny set first so a mapping mutated after construction cannot reach the boundary either. **A config that set this raises at construction; it never did what it appeared to do.**
- An alphabet run reports as its own finding, `Alphabet run (ambiguous: a character table or a secret)`, rather than as a generic high-entropy token, and callers that rewrite content must skip it. `is_ambiguous_finding` is the predicate; the vault's residue sweep uses it. Without the distinction the sweep acted on a chart exactly as on a located credential, so `alphabet = abcdefghijklmnopqrstuvwxyz` came back from sensitive ingest as `[redacted:credential]` with nothing in `findings` to say a line had been destroyed. Reporting an ambiguous run is safe in both directions; rewriting on one is not.
- A credential that is also an alphabet chart is no longer erased by the monotonic-run suppression. `_monotonic` was consulted by both the span pass and the label pass, which made it the one rule in the module able to remove a credential entirely rather than move it from a span to a label. `234567ABCDEFGHIJKLMNOPQRSTUVWXYZ` is the RFC 4648 Base32 alphabet and also an ordinary TOTP shared secret, and all 32 characters left `check_outbound` with `reason="clean"`. The label pass no longer asks. The span pass still does, so a document holding a character table is never rewritten: over 153 standard library files the spans and the characters they cover are unchanged at 37 and 3,157, and the entire cost is three more files drawing a `High-entropy token` label.
- Outbound credential scanning is restructured into two passes that answer different questions, and this changes verdicts for every deployment, not only those using the privacy vault. Attribution asks which characters can be replaced faithfully and is bounded everywhere, because a span that reaches too far corrupts the document it was protecting. Recognition asks whether a credential is present at all and is bounded nowhere. Every bound in the first pass is a number an attacker can exceed on purpose, and each of them was: 65 separators, 33 shell line continuations, and adjacent empty shell quotes each made a whole credential family disappear while `/bin/sh` still reconstructed the key. A value pushed past a bound now moves from an exact span to a label with no span, so the caller refuses the content rather than releasing it. **Content that previously passed `check_outbound` may now be blocked.**
- A credential split across whitespace, punctuation, quotes, or line continuations is reassembled and replaced exactly, rather than being missed or causing the whole document to be withheld. Compatibility and confusable forms are folded first, so a key rewritten in full-width or mathematical characters is read as the key it is, and invisible characters inside a value no longer end it.
- Credential grammars added for formats that previously registered only as a generic high-entropy token, or not at all: GitHub fine-grained (`github_pat_`) and user-to-server (`ghu_`) tokens, GitLab personal access tokens (`glpat-`), Hugging Face tokens (`hf_`), Stripe secret, restricted, and webhook keys (`sk_live_`, `rk_live_`, `whsec_`), and npm access tokens (`npm_`). A leaked Stripe key was previously reported as an OpenAI API key, because `sk_live_` compacts to a string the `sk` anchor claims; the specific grammar now names it first. npm's legacy registry token is 32 to 40 hex characters with no prefix and was invisible to both passes, since 32 hex characters decode to 16 bytes whose Shannon entropy is capped at 4.0 bits per byte against a 4.5 threshold; it is now found by its `_authToken` config key instead, with the span covering the value only so the line still parses.

### Fixed
- A confirmation the user denies no longer consumes L6 rate-limit quota. The guard flow previously recorded the tool action against the rate limiter before the confirmation ran, so a denied confirmation still burned a per-session slot. The record is now deferred until the call has cleared confirmation and G6 commitment verification.
- Confirmed tool calls can no longer exceed the rate limit under concurrency. The deferral above left the rate-limit check before the confirmation `await` and the record after it, so two concurrent confirmed calls could both pass a near-full limit before either recorded. The finalize step now re-checks and records under the rate limiter's lock (`RateLimiter.check_and_record`), so at most `limit` confirmed calls are admitted under both asyncio concurrency and multiple OS threads.

### Changed
- The L6 rapid-burst anomaly now counts the action being checked, not only the actions already completed in the window. `burst_threshold=3` previously required three completed actions before flagging anything, so the signal first appeared on the *fourth* proposal and a burst of exactly three actions inside `burst_window_seconds` produced no anomaly at all. The third action in the window is now flagged, and the reported count names that action's own position (`Rapid burst: 3 actions in 10s` on the third send rather than the fourth). The burst signal is advisory and never blocks, so this changes which calls carry an anomaly, not which calls are permitted. The hourly cap is unchanged and still counts only completed actions, because it governs quota and must reflect what actually happened. Hosts that treat `anomalies` as an alerting trigger will see burst alerts one action earlier. Documented in `docs/policy_tuning.md`.
- Threat model (`docs/threat_model.md`) rescoped to match the implementation: request binding is described as an intra-process consistency check (recomputed argument hash, message-hash match, TTL) rather than a cryptographic binding, and authorization-event origin authenticity is stated as a host obligation (the library validates event contents, not origin). `PolicyConfig.directive_patterns` is documented as reserved and not yet wired.

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

[Unreleased]: https://github.com/mhcoen/guardllm/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/mhcoen/guardllm/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/mhcoen/guardllm/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mhcoen/guardllm/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/mhcoen/guardllm/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/mhcoen/guardllm/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/mhcoen/guardllm/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mhcoen/guardllm/releases/tag/v1.0.0
