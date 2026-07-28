# Integration Patterns

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

This guide shows practical patterns for integrating guardllm into MCP server/client systems and unknown-provenance ingestion pipelines.

## Pattern 1: MCP Server Ingress Hardening

Scenario: your MCP server receives requests from external clients.

1. Create server-side context with `Guard.context_mcp_client(client_id=...)`.
2. Run `process_inbound` on every incoming textual field.
3. Before dispatching any internal tool, run `check_tool_call`.
4. Before returning model/tool output, run `check_outbound`.

Benefits:
- sanitization and normalization at ingress
- capability-scope enforcement
- replay and exfiltration resistance

## Pattern 2: MCP Client Tool-Use Hardening

Scenario: your app invokes external MCP tools.

1. Use `Guard.context_mcp_server(server_id=...)`.
2. For destructive tools, generate `AuthorizationEvent` from explicit user intent.
3. Bind request with `bind_request`.
4. Permit tool execution only when `check_tool_call(...).allowed` is `True`.
5. Optionally require runtime confirmation with `await guard.guard_tool_call(..., require_confirmation=True)`.

Implementation note:
- Configure `context.confirmation_handler` for manual gating callbacks.
- Without a confirmation handler, L12 confirmation is fail-closed and returns deny.
- Use `context_has_web_derived=True` when tool decisions are influenced by web-derived context.

Benefits:
- explicit-user-intent enforcement
- anti-replay binding
- safer delegation to external systems

## Pattern 3: Untrusted Content Ingestion

Scenario: content from web, email, documents, calendars, or third-party outputs.

- Web results: use `context_web(...)`.
- Documents: use `context_document(...)`.
- Email/calendar/custom feeds: construct `SecurityContext` with source types like `email_content`, `calendar_content`, `tool_output`.

Always:
1. sanitize/isolate on ingress (`process_inbound`)
2. enforce source gate for KG/indexing decisions (`check_extraction_allowed`)
3. run outbound checks before responses leave your boundary (`check_outbound`)

## Pattern 4: Retrieval + Generation Safety Boundary

If you attach retrieved content to prompts:
- treat retrieval as untrusted unless you can prove provenance
- run retrieval chunks through inbound pipeline first
- avoid direct copy of retrieved text into outbound channels without outbound checks

## Pattern 5: Audit and Observability

Use `guardllm.security.audit.AuditLogger` as a structured sink for:
- blocked tool calls
- outbound DLP blocks
- repeated rate-limit violations
- canary detections

Persist logs and correlate by session/request IDs in your telemetry stack.

When you pass `audit_logger` to `Guard(...)`, the API emits structured events for:
- inbound processing
- tool-call checks
- outbound checks
- argument validation
- action-gate confirmations
- sanitized error generation
