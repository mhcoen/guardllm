# Policy Tuning Guide

This guide explains how to tune guardllm safety controls without disabling core protections.

## Start from secure defaults

- Keep `enable_destructive=False` unless needed.
- Keep unknown-provenance sources at `UNTRUSTED`.
- Keep L12 confirmation enabled for high-impact actions.

## Tuning dimensions

## 1) Tool policy

Use `PolicyConfig` to control capabilities:
- `capability_scopes` (server mode): allowed tools per client.
- `enable_destructive` (client/server): whether destructive tools are even eligible.

Recommended:
- allowlist read-only tools by default
- enable destructive tools per workflow, not globally

## 2) Confirmation strictness (L12)

- For high-risk flows, use `guard_tool_call(..., require_confirmation=True)`.
- Use `context_has_web_derived=True` when web-derived content influences the action.
- Keep `escalation_gate_enabled=True`.

## 3) Validation strictness

- Always run `validate_tool_args(...)` pre-dispatch.
- Extend field-level validation in your adapter layer for domain-specific params.

## 4) Outbound strictness

- Default DLP/provenance thresholds are conservative.
- Prefer prompt/design changes over threshold weakening.
- Allow quotation only when policy permits and user intent is explicit.

## 5) Rate limiting

- Tune by action criticality and user volume.
- Keep anomaly detection enabled (novel recipient / burst patterns). Pass `recipient=` to `check_tool_call`/`check_outbound` to drive novel-recipient detection; anomalies surface non-blocking on `GateResult.anomalies` / `OutboundResult.anomalies` and in the audit trail.

## 6) Fail-closed options

- `server_default_deny=True` (server mode): deny all tools when `capability_scopes` is unset.
- `require_message_binding="destructive"` (or `"all"`): reject write-tool authorizations that are not bound to the current user message. Pass the current `user_message`/`message_hash` at the call site.
- `contaminated_tool_policy` / `escalated_tool_policy` (`"require_auth"` or `"deny"`): tighten tool calls after session risk. Contamination fires when untrusted content is ingested; escalation fires on a high-confidence DLP hard block or remembered-canary match (default `"require_auth"`). When both fire the strictest wins. `reset()` clears both signals; pass a new canary session ID when it also starts a new logical session.

## Tuning workflow

1. Benchmark baseline: `python benchmarks/run_benchmarks.py`
2. Apply one policy change.
3. Re-run benchmarks and compare `benchmarks/runs/<run_id>/latest.json` (or resolve latest from `benchmarks/runs/LATEST.txt`).
4. Add/adjust suite cases for your domain.
5. Deploy with audit logging enabled.

## Anti-patterns

- Enabling destructive tools globally without scoped checks.
- Skipping binding on write-capable operations.
- Disabling confirmation while ingesting untrusted web/email content.
- Suppressing blocked events instead of handling root cause.
