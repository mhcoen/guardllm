# Production Checklist

Use this checklist before deploying guardllm-backed flows.

## 1. Dependency and Environment

- Use a dedicated project environment.
- Install package and dev deps from project metadata.
- Pin dependency versions in your deployment system.

## 2. Trust Boundary Setup

- Treat all external feeds as `UNTRUSTED` by default.
- Define source-specific `SecurityContext` values (`web_content`, `email_content`, `calendar_content`, `rag_content`, `tool_output`).
- Ensure all unknown-provenance text passes through `process_inbound(...)` before model/tool use.

## 3. Tool Execution Controls

- Enable destructive tools only where required (`PolicyConfig(enable_destructive=True)`).
- Enforce scope-limited server policies (`capability_scopes`).
- Require explicit authorization and request binding for write-capable tools.
- Require L2 confirmation for high-impact actions (`guard_tool_call(..., require_confirmation=True)`).

## 4. Outbound Safety

- Run `check_outbound(...)` before external calls and user-visible responses.
- Fail closed when DLP/provenance/canary checks block output.
- Log blocked events with enough context for follow-up.

## 5. Validation and Error Hygiene

- Validate tool args before dispatch (`validate_tool_args(...)`).
- Return sanitized error payloads only (`sanitize_exception(...)`).
- Avoid returning raw internal exceptions or stack traces.

## 6. Audit and Monitoring

- Always provide `audit_logger` in production.
- Track event classes: inbound_processed, tool_call_checked, outbound_checked, action_gate_confirmed, error_sanitized.
- Alert on repeated blocks, rate-limit anomalies, and canary detection.

## 7. Benchmark and Regression Gates

- Run benchmark suite in CI: `python benchmarks/run_benchmarks.py`.
- Block releases on benchmark regressions.
- Keep `benchmarks/results/latest.json` current for release notes.

## 8. Operational Runbooks

- Document how to handle false positives and emergency overrides.
- Define incident response playbooks for suspected exfiltration or prompt-injection events.
- Review policy settings and benchmark coverage regularly.
