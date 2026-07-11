# API Specification (Exhaustive)

This document is the complete public API contract for GuardLLM (`guardllm`) as implemented in:
- `src/guardllm/__init__.py`
- `src/guardllm/api.py`
- `src/guardllm/security/types.py`

## Scope and Stability

- Public package export surface: `guardllm.Guard`
- Stability target: `Guard` methods and the data types referenced below.
- Internal modules under `guardllm.security.*` are implementation details unless explicitly referenced in this spec.

## Public Export

```python
from guardllm import Guard
```

`src/guardllm/__init__.py` exports:
- `Guard`

## Guard Class

### Constructor

```python
Guard(*, canary_session_id: str | None = None, audit_logger: object | None = None, principal_trust: TrustLevel = TrustLevel.UNTRUSTED)
```

Parameters:
- `canary_session_id`: optional session identifier used to generate a canary token for exfiltration detection checks.
- `audit_logger`: optional logger object. If it has `.log(event)` it receives `AuditEvent` records emitted by Guard methods.
- `principal_trust`: session-level caller trust (default `UNTRUSTED`). Accepts `TRUSTED`, `SEMI_TRUSTED`, or `UNTRUSTED`.

Behavior:
- Initializes security pipeline and action gate.
- Does not raise under normal construction.

### Static Method: `hash_message`

```python
Guard.hash_message(message: str) -> str
```

Behavior:
- Returns SHA-256 hex digest of `message`.

### Static Method: `authorize`

```python
Guard.authorize(
    action: str,
    scope: dict,
    *,
    source: str = "api",
    user_message: str | None = None,
    message_hash: str | None = None,
    session_id: str | None = None,
    timestamp: float | None = None,
) -> AuthorizationEvent
```

Required input rule:
- Must provide either `user_message` or `message_hash`.

Error behavior:
- Raises `ValueError("Provide either user_message or message_hash")` if neither yields a usable hash.

Behavior:
- If `message_hash` not provided and `user_message` provided, hashes message via `Guard.hash_message`.
- Uses `time.time()` when `timestamp` is not supplied.

### Static Method: `bind_request`

```python
Guard.bind_request(
    tool: str,
    args: dict,
    *,
    authorization: AuthorizationEvent | None = None,
    user_message: str | None = None,
    message_hash: str | None = None,
    ttl: float = 120.0,
) -> Binding
```

Behavior:
- Creates anti-replay binding for `(tool, args, message_hash)`.
- Message hash precedence:
1. `authorization.message_hash` (if authorization provided)
2. explicit `message_hash`
3. hash of `user_message` (if provided)
4. empty string if none provided

Notes:
- Method itself does not raise for missing hash.
- Verification stage can reject if hash context mismatches later.

### Static Method: `context_mcp_server`

```python
Guard.context_mcp_server(
    server_id: str,
    *,
    source_trust: TrustLevel = TrustLevel.UNTRUSTED,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
) -> SecurityContext
```

Returns `SecurityContext` with:
- `mode="client"`
- `source_type="mcp_server"`
- `source_id=server_id`
- `source_trust`, `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`

### Static Method: `context_mcp_client`

```python
Guard.context_mcp_client(
    client_id: str,
    *,
    source_trust: TrustLevel = TrustLevel.UNTRUSTED,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
) -> SecurityContext
```

Returns `SecurityContext` with:
- `mode="server"`
- `source_type="mcp_client"`
- `source_id=client_id`
- `source_trust`, `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`

### Static Method: `context_document`

```python
Guard.context_document(
    document_id: str,
    *,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
) -> SecurityContext
```

Returns `SecurityContext` with:
- `mode="client"`
- `source_type="rag_content"`
- `source_id=document_id`
- `source_trust=TrustLevel.UNTRUSTED`
- `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`

### Static Method: `context_web`

```python
Guard.context_web(
    *,
    source_id: str = "web",
    content_type: ContentType = ContentType.HTML,
    policy: PolicyConfig | None = None,
) -> SecurityContext
```

Returns `SecurityContext` with:
- `mode="client"`
- `source_type="web_content"`
- `source_id=source_id`
- `source_trust=TrustLevel.UNTRUSTED`
- `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`

### Method: `process_inbound`

```python
guard.process_inbound(content: str, context: SecurityContext) -> ProcessedContent
```

Pipeline behavior:
- Sanitizes inbound content.
- Wraps untrusted content in `<untrusted_content ...>` tags.
- Tracks provenance and warnings.
- Emits audit event `inbound_processed` if audit logger is configured.

### Method: `process_inbound_compound`

```python
guard.process_inbound_compound(
    spans: list[tuple[str, SecurityContext]],
    compound_id: str | None = None,
) -> list[ProcessedContent]
```

Pipeline behavior:
- Processes each span independently through the existing `process_inbound` path.
- Session state (contamination, DLP buffers, provenance) accumulates across all spans.
- If any span has `source_trust == UNTRUSTED`, the session contamination flag is set, widening downstream egress checks for the entire session.
- Source gate evaluates extraction policy per span independently; a trusted envelope does not upgrade an untrusted forwarded payload.
- `compound_id` links spans for provenance and audit. If `None`, generated from a hash of all span contents (16-char hex prefix).
- Emits per-span `inbound_processed` audit events plus one `compound_inbound_processed` summary event with the `compound_id` as `request_id`.

### Method: `check_tool_call`

```python
guard.check_tool_call(
    tool: str,
    args: dict,
    context: SecurityContext,
    *,
    authorization: AuthorizationEvent | None = None,
    binding: Binding | None = None,
    user_message: str | None = None,
    message_hash: str | None = None,
    recipient: str | None = None,
    validate: bool = True,
    record_rate_limit: bool = True,
) -> GateResult
```

Behavior:
- Runs policy check, rate-limit check, and optional binding verification.
- If `message_hash` absent and `user_message` provided, computes hash from `user_message`.
- Anti-replay message binding: when an `authorization` is present and a current message hash is available (from `message_hash`/`user_message`), a mismatch against `authorization.message_hash` is denied as a possible replay. `PolicyConfig.require_message_binding` additionally fails closed on a missing current hash.
- `recipient` (optional) feeds novel-recipient rate-limit anomaly detection; surfaced non-blocking on `GateResult.anomalies` and recorded in the audit event.
- `validate` (default `True`): validate arguments before the authorization decision; pass `False` only when the caller already validated (as `guard_tool_call` does).
- `record_rate_limit` (default `True`): a permitted call is the terminal decision and is recorded against the rate limiter. The rate-limit *check* always runs; only the *record* is gated. `guard_tool_call` passes `False` when a confirmation still follows, so a denied confirmation does not consume quota (see `guard_tool_call` below).
- Emits audit event `tool_call_checked` if audit logger is configured.

### Method: `check_outbound`

```python
guard.check_outbound(
    content: str,
    context: SecurityContext,
    *,
    has_quoting_directive: bool = False,
    recipient: str | None = None,
) -> OutboundResult
```

Behavior:
- Runs outbound DLP, provenance checks, rate checks, canary check.
- `recipient` (optional) feeds novel-recipient rate-limit anomaly detection; surfaced non-blocking on `OutboundResult.anomalies` and recorded in the audit event.
- Emits audit event `outbound_checked` if audit logger is configured.

### Method: `validate_tool_args`

```python
guard.validate_tool_args(tool: str, args: dict) -> ValidationResult
```

Behavior:
- Validates known argument names against built-in size/pattern limits.
- Applies universal safety checks (path traversal, null byte) to every argument including unknown ones and strings nested in containers; unknown fields get no size/pattern limits but are not exempt from these safety checks.
- Emits audit event `tool_args_validated` if audit logger is configured.

### Method: `sanitize_exception`

```python
guard.sanitize_exception(exception: Exception, retry_after: int | None = None) -> dict
```

Behavior:
- Maps internal exception to outward-safe error payload.
- Emits audit event `error_sanitized` if audit logger is configured.

Return payload shape:

```python
{"error": {"code": str, "message": str}}
```

### Async Method: `confirm_action`

```python
await guard.confirm_action(
    tool: str,
    args: dict,
    context: SecurityContext,
    *,
    summary: str,
    proposal_context: dict | None = None,
    heightened_scrutiny: bool = False,
    context_has_web_derived: bool = False,
) -> bool
```

Behavior:
- Delegates to `context.confirmation_handler.confirm(...)` when handler exists.
- If no confirmation handler is configured, fails closed (`False`).
- Emits audit event `action_gate_confirmed` if audit logger is configured.

### Async Method: `guard_tool_call`

```python
await guard.guard_tool_call(
    tool: str,
    args: dict,
    context: SecurityContext,
    *,
    summary: str | None = None,
    proposal_context: dict | None = None,
    authorization: AuthorizationEvent | None = None,
    binding: Binding | None = None,
    user_message: str | None = None,
    message_hash: str | None = None,
    context_has_web_derived: bool = False,
    require_confirmation: bool = False,
    heightened_scrutiny: bool = False,
    validate: bool = True,
    recipient: str | None = None,
) -> GateResult
```

Execution order:
1. Confirmation escalation: `require_confirmation` is forced to `True` when policy demands it, even if the caller passed `False`. This fires for a destructive tool under `auto_confirm_destructive`, for web-derived context (`context_has_web_derived=True`) under `escalation_gate_enabled`, and for a principal at or below `confirm_all_below`. Escalation fails closed: if confirmation is required and no handler is configured, the call is denied.
2. Optional validation (`validate=True` by default)
3. Tool policy/rate/binding checks (`check_tool_call`). When a confirmation follows (`require_confirmation=True`), this call passes `record_rate_limit=False`: the rate-limit *check* runs but the slot is not consumed yet, so a call denied at confirmation leaves no rate-limit trace.
4. Optional/escalated confirmation (`require_confirmation=True`)
5. G6 commitment verification: after confirmation, verifies that tool args have not been mutated since the confirmation handler was called. If args changed, the call is rejected with `"Commitment verification failed"`. This prevents TOCTOU attacks where args are swapped between confirmation and execution.
6. Rate-limit finalize (confirmation path only): once the call has cleared confirmation and G6, the rate-limit slot is re-checked and recorded atomically. Re-checking here (not just recording) closes a race where two concurrent confirmations both pass the step-3 check before either records; the check and record run with no intervening `await`, so at most `limit` confirmed calls are admitted. If the limit is now reached, the call is denied with the rate-limit reason.

`recipient` (optional) is forwarded to `check_tool_call` for novel-recipient anomaly detection.

Return behavior:
- Validation failure: `GateResult(allowed=False, reason="Validation failed: ...", confidence="none")`
- Gate failure: returns gate denial from `check_tool_call`
- Confirmation denied: `GateResult(allowed=False, reason="User denied confirmation", confidence="none")`
- G6 commitment mismatch: `GateResult(allowed=False, reason="Commitment verification failed: ...", confidence="none")`
- Rate-limit reached at finalize (concurrent confirmed calls): `GateResult(allowed=False, reason="Hourly limit exceeded ...", confidence="none")`
- Success: returns gate result from `check_tool_call`

## Type Specification

All types below are from `guardllm.security.types`.

### Enum: `TrustLevel`

- `TrustLevel.TRUSTED` -> `"trusted"`
- `TrustLevel.SEMI_TRUSTED` -> `"semi_trusted"` (valid only for `principal_trust`, not `source_trust`)
- `TrustLevel.UNTRUSTED` -> `"untrusted"`

Note: `SEMI_TRUSTED` is only valid on the `principal_trust` axis. Setting `source_trust=TrustLevel.SEMI_TRUSTED` on a `SecurityContext` raises `ValueError`.

### Enum: `ContentType`

- `ContentType.HTML` -> `"html"`
- `ContentType.PLAINTEXT` -> `"plaintext"`
- `ContentType.STRUCTURED` -> `"structured"`

### Dataclass: `AuthorizationEvent` (frozen)

Fields:
- `action: str`
- `scope: dict`
- `message_hash: str`
- `timestamp: float`
- `source: str`
- `session_id: str | None = None`

Method:
- `binding_hash() -> str`

### Dataclass: `PolicyConfig`

Fields:
- `tool_allowlist: dict[tuple, Any] | None = None` (`None` = no allowlist, fall through; `{}` = deny all tools)
- `directive_patterns: dict[str, Any] = {}` (reserved / not yet wired; not consulted by the policy engine today, retained for forward compatibility)
- `enable_destructive: bool = False`
- `capability_scopes: dict[str, Any] | None = None` (`None` = no allowlist; `{}` = deny all tools)
- `client_id: str | None = None`
- `server_default_deny: bool = False` (server mode: when `True`, a missing `capability_scopes` denies all tools instead of allowing by default)
- `rate_limits: dict[str, Any] = {}`
- `argument_limits: dict[str, Any] = {}`
- `escalation_gate_enabled: bool = True`
- `contaminated_action: str = "block"`
- `dlp_verbatim_lcs_min: int = 14`
- `dlp_ngram_overlap_min: float = 0.40`
- `dlp_sensitive_lcs_min: int = 12`
- `provenance_verbatim_lcs_min: int = 50`
- `provenance_ngram_overlap_min: float = 0.30`
- `source_gate_overrides: dict[tuple[str, TrustLevel], ExtractionPolicy] = {}`
- `untrusted_deny_tools: frozenset[str] = frozenset()`
- `untrusted_require_auth: bool = False`
- `confirm_all_below: TrustLevel | None = None`
- `rate_limit_overrides: dict[TrustLevel, dict[str, int]] = {}`
- `contaminated_tool_policy: str = "allow"` (`"allow"` | `"require_auth"` | `"deny"`; tool gating when untrusted content has entered the session)
- `escalated_tool_policy: str = "require_auth"` (`"allow"` | `"require_auth"` | `"deny"`; tool gating once an egress DLP block has fired this session)
- `auto_confirm_destructive: bool = False`
- `require_source_id_for: frozenset[str] = frozenset()`
- `require_message_binding: str = "off"` (`"off"` | `"destructive"` | `"all"`; anti-replay message binding)

### Protocol Class: `ConfirmationHandler`

Required async method:

```python
async def confirm(self, tool: str, args: dict, context: dict) -> bool
```

### Dataclass: `SecurityContext`

Fields:
- `mode: str` (`"client"` or `"server"` by convention)
- `source_type: str`
- `source_id: str`
- `source_trust: TrustLevel = TrustLevel.UNTRUSTED` (per-content trust; `TRUSTED` or `UNTRUSTED` only)
- `principal_trust: TrustLevel = TrustLevel.UNTRUSTED` (per-session caller trust; `TRUSTED`, `SEMI_TRUSTED`, or `UNTRUSTED`)
- `sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC`
- `content_type: ContentType = ContentType.PLAINTEXT`
- `policy: PolicyConfig = PolicyConfig()`
- `confirmation_handler: ConfirmationHandler | None = None`

### Dataclass: `SanitizationResult`

Fields:
- `cleaned_text: str`
- `warnings: list[str] = []`
- `sanitization_summary: str | None = None`
- `chars_stripped: int = 0`
- `class_hiding_possible: bool = False`
- `encoded_detected: bool = False`
- `mixed_script_words: list[str] = []`

### Dataclass: `ProcessedContent`

Fields:
- `content: str`
- `sanitization: SanitizationResult | None = None`
- `isolated: bool = False`
- `source_type: str = ""`
- `source_id: str = ""`
- `warnings: list[str] = []`

### Dataclass: `GateResult`

Fields:
- `allowed: bool`
- `reason: str`
- `matched_directive: str | None = None`
- `confidence: str = "none"` (`"explicit" | "implicit" | "none"` by convention)
- `anomalies: list[str] = []` (non-blocking rate-limit signals: burst, novel recipient)

### Dataclass: `OutboundResult`

Fields:
- `allowed: bool`
- `reason: str`
- `overlap_pct: float = 0.0`
- `secrets_found: list[str] = []`
- `provenance_blocked: bool = False`
- `contamination_triggered: bool = False`
- `echo_detected: bool = False`
- `echo_lcs: int = 0`
- `anomalies: list[str] = []` (non-blocking rate-limit signals: burst, novel recipient)

### Dataclass: `RateLimitResult`

Fields:
- `allowed: bool`
- `reason: str`
- `anomalies: list[str] = []`
- `remaining: int | None = None`
- `retry_after: int | None = None`

### Dataclass: `ValidationResult`

Fields:
- `valid: bool`
- `errors: list[str] = []`
- `field_name: str | None = None`

### Dataclass: `Binding`

Fields:
- `tool_name: str`
- `args_hash: str`
- `message_hash: str`
- `binding_hash: str`
- `created_at: float`
- `ttl: float = 120.0`

Computed property:
- `expired: bool`

### Dataclass: `AuditEvent`

Fields:
- `event_type: str`
- `tool_name: str | None = None`
- `action_summary: str | None = None`
- `content_hash: str | None = None`
- `user_confirmed: bool | None = None`
- `firewall_result: dict[str, Any] | None = None`
- `dlp_result: dict[str, Any] | None = None`
- `provenance_result: dict[str, Any] | None = None`
- `rate_limit_result: dict[str, Any] | None = None`
- `binding_result: dict[str, Any] | None = None`
- `warnings: list[str] | None = None`
- `session_id: str | None = None`
- `timestamp: float | None = None`
- `request_id: str | None = None`

## Validation Contract (`validate_tool_args`)

Known argument limits currently enforced:

- `message`: max chars `50_000`
- `content`: max chars `500_000`
- `query`: max chars `1_000`
- `source_name`: max chars `200`, regex `^[\w\-. /]+$`
- `thread_handle`: max chars `100`, regex `^[A-Za-z0-9_\-]+$`
- `provenance`: max fields `10`, max string value chars `500`

Universal safety checks (every argument, known or unknown):
- path traversal sequence `".."` is rejected
- null byte (`\x00`) is rejected
- these run on strings nested in lists/dicts (including dict keys); recursion is depth-bounded and over-deep or cyclic input is rejected

Unknown argument names:
- no size/pattern limits are applied, but the universal safety checks above still apply, so a traversal or null-byte payload in an unknown field is rejected

## Error Sanitization Contract (`sanitize_exception`)

Supported mappings:
- `RateLimitError` -> `{"code": "rate_limited", "message": "...retry after Xs"}`
- `InvalidParamsError` -> `{"code": "invalid_params", "message": "Invalid parameters: <field>"}`
- `UnauthorizedError` -> `{"code": "unauthorized", "message": "Invalid or expired token"}`
- `PermissionDeniedError` -> `{"code": "permission_denied", "message": "Tool not available"}`
- `InvalidHandleError` -> `{"code": "invalid_handle", "message": "Invalid or expired thread handle"}`
- `sqlite3.OperationalError` -> `{"code": "internal_error", "message": "Request could not be processed"}`
- `FileNotFoundError` -> `{"code": "internal_error", "message": "Request could not be processed"}`
- uncaught/other exceptions -> `{"code": "internal_error", "message": "Request could not be processed"}`

## Audit Logger Contract

If `Guard(..., audit_logger=logger)` is provided:
- logger must either be:
1. an instance of `guardllm.security.audit.AuditLogger`, or
2. any object with method `log(event)`

`event` is an `AuditEvent` instance.
