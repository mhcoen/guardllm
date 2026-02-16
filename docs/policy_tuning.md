# Policy Tuning Guide

This guide explains how to tune guardllm safety controls without disabling core protections.

## Start from secure defaults

- Keep `enable_destructive=False` unless needed.
- Keep unknown-provenance sources at `UNTRUSTED`.
- Keep L2 confirmation enabled for high-impact actions.

## Tuning dimensions

## 1) Tool policy

Use `PolicyConfig` to control capabilities:
- `capability_scopes` (server mode): allowed tools per client.
- `enable_destructive` (client/server): whether destructive tools are even eligible.

Recommended:
- allowlist read-only tools by default
- enable destructive tools per workflow, not globally

## 2) Confirmation strictness (L2)

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
- Keep anomaly detection enabled (novel recipient / burst patterns).

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
