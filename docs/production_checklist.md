# Production Checklist

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

Use this checklist before deploying guardllm-backed flows.

## 1. Dependency and Environment

- Use a dedicated project environment.
- Install package and dev deps from project metadata. Runtime dependencies are `beautifulsoup4` and `confusables` (TR39 homoglyph normalization); if `confusables` is missing, homoglyph normalization is disabled and a `RuntimeWarning` is emitted.
- Pin dependency versions in your deployment system.

## 2. Trust Boundary Setup

- Treat all external feeds as `UNTRUSTED` by default.
- Define source-specific `SecurityContext` values (`web_content`, `email_content`, `calendar_content`, `rag_content`, `tool_output`).
- Ensure all unknown-provenance text passes through `process_inbound(...)` before model/tool use.

## 3. Tool Execution Controls

- Enable destructive tools only where required (`PolicyConfig(enable_destructive=True)`).
- Enforce scope-limited server policies (`capability_scopes`), and set `server_default_deny=True` so a missing scope config fails closed.
- Require explicit authorization and request binding for write-capable tools; set `require_message_binding="destructive"` (or `"all"`) and pass the current `user_message`/`message_hash` to prevent authorization replay.
- Treat `Binding` objects as intra-process only. Request binding is an intra-process consistency check (recomputed args hash, message hash, TTL), not a cryptographic token, so a `Binding` must never be passed across a process or trust boundary. See the Integrity boundary in `docs/threat_model.md` Illustrated in [03 The Call That Came Back Changed](mechanisms/03-request-binding.html), whose closing section states the same limit.
- Require L12 confirmation for high-impact actions (`guard_tool_call(..., require_confirmation=True)`).
- Keep session-risk tool gating tight: `contaminated_tool_policy` and `escalated_tool_policy` (default `"require_auth"` for escalation) tighten tool calls after untrusted ingest or a high-confidence DLP/canary block. Never reset reactively. A no-argument reset retains the current canary; pass a new canary session ID to rotate it at a genuine logical-session boundary.

## 4. Outbound Safety

- Declare your own destructive tools with `destructive_tools`. The built-in set names gmail, calendar, slack, file and shell tools, so a deployment whose dangerous action is `wire_funds` or `ledger_write` gets none of the destructive-tool handling until it says so. Note the scope: this gates `enable_destructive`, the authorization requirement and `require_message_binding: destructive`, and does not affect the session-risk gate, which refuses declared and undeclared tools alike under `contaminated_tool_policy: deny`.
- Run `check_outbound(...)` before external calls and user-visible responses.
- Treat content carried in tool-call arguments as an outbound channel. `check_tool_call(...)` gates the action (policy, rate limit, binding) and does not inspect argument content, so an email send that passes the tool gate still needs `check_outbound(...)` on its body (see A-AS9 in `docs/threat_model.md`). `prepare_tool_call(...)` already does this over every string leaf when the privacy vault is enabled. **In gateway mode this is not yours to remember:** the proxy runs outbound DLP and provenance over every string in a tool call's arguments before allowing it. Illustrated in [06 One Call, Two Questions](mechanisms/06-two-questions.html), which measures the case this bullet exists for: a credential that the tool gate allows through and egress refuses.
- Fail closed when DLP/provenance/canary checks block output.
- When canaries are enabled, place `guard.canary_token` in private model context from trusted host code and never log or expose the token itself.
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
- Keep canonical run summaries current in `benchmarks/results.md` with source artifacts under `benchmarks/runs/<run_id>/`.

## 8. Operational Runbooks

- Document how to handle false positives and emergency overrides.
- Define incident response playbooks for suspected exfiltration or prompt-injection events.
- Review policy settings and benchmark coverage regularly.
