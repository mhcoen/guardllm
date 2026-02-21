# API Reference

guardllm exposes a stable facade: `guardllm.Guard`.

## Core Class

```python
from guardllm import Guard
```

Constructor:
- `Guard(canary_session_id: str | None = None, audit_logger: object | None = None)`

## Context Builders

Use these to declare trust boundaries explicitly:
- `Guard.context_mcp_server(server_id, trust_level=..., content_type=..., policy=...)`
- `Guard.context_mcp_client(client_id, trust_level=..., content_type=..., policy=...)`
- `Guard.context_document(document_id, content_type=..., policy=...)`
- `Guard.context_web(source_id="web", content_type=..., policy=...)`

For additional source types (for example `email_content`, `calendar_content`), construct `SecurityContext` directly.

## Authorization and Binding

- `Guard.hash_message(message) -> str`
- `Guard.authorize(action, scope, source="api", user_message=..., message_hash=..., session_id=..., timestamp=...) -> AuthorizationEvent`
- `Guard.bind_request(tool, args, authorization=..., user_message=..., message_hash=..., ttl=120.0) -> Binding`

Recommended pattern for write-capable tools:
1. Create authorization event from explicit user intent.
2. Create binding from tool + args + message hash.
3. Check tool call with authorization + binding.

## Runtime Checks

- `guard.process_inbound(content, context) -> ProcessedContent`
- `guard.check_tool_call(tool, args, context, authorization=..., binding=..., user_message=..., message_hash=...) -> GateResult`
- `guard.check_outbound(content, context, has_quoting_directive=False) -> OutboundResult`
- `guard.validate_tool_args(tool, args) -> ValidationResult`
- `await guard.confirm_action(tool, args, context, summary=..., ...) -> bool`
- `await guard.guard_tool_call(tool, args, context, ...) -> GateResult`
- `guard.sanitize_exception(exception, retry_after=None) -> dict`

### Manual Gating (L12) Behavior

- `confirm_action(...)` and `guard_tool_call(..., require_confirmation=True)` rely on `context.confirmation_handler`.
- If no handler is configured, confirmation fails closed (`False`) and the action is blocked.
- For heightened scrutiny, pass `context_has_web_derived=True` to include the hardcoded warning context in the confirmation payload.

## Return Objects

- `ProcessedContent`: sanitized content, warnings, source metadata.
- `GateResult`: allow/deny decision and reason for tool execution.
- `OutboundResult`: allow/deny decision and exfiltration/provenance indicators.
- `ValidationResult`: argument validation pass/fail with field-level details.

## Minimal End-to-End Example

```python
from guardllm import Guard
from guardllm.security.types import PolicyConfig

guard = Guard(canary_session_id="session-1")
ctx = Guard.context_mcp_server(
    server_id="mcp-mail",
    policy=PolicyConfig(
        enable_destructive=True,
        dlp_verbatim_lcs_min=100,
        dlp_ngram_overlap_min=0.40,
        provenance_verbatim_lcs_min=50,
        provenance_ngram_overlap_min=0.30,
    ),
)

tool = "gmail_send_email"
args = {"to": "alice@example.com"}
msg = "send email to alice@example.com"

auth = Guard.authorize(action=tool, scope={"to": "alice@example.com"}, user_message=msg)
binding = Guard.bind_request(tool=tool, args=args, authorization=auth)

gate = guard.check_tool_call(
    tool=tool,
    args=args,
    context=ctx,
    authorization=auth,
    binding=binding,
    user_message=msg,
)

if gate.allowed:
    # execute tool here
    pass
```
