# Tutorial: Harden a GSuite MCP Client

This tutorial shows how to build an MCP client that safely handles unknown-provenance GSuite inputs (email and calendar) and safely executes outbound actions.

Runnable example:
- `examples/12_tutorial_gsuite_mcp_client.py`

## Goals

- Treat inbound email/calendar content as untrusted.
- Sanitize and isolate unknown input before use.
- Block unsafe extraction paths for untrusted sources.
- Require explicit authorization and request binding for destructive tools.
- Optionally require user confirmation before execution.
- Run outbound exfiltration checks before sending.
- Emit structured audit events.

## Flow

1. Create a `Guard` instance with an `AuditLogger`.
2. Build MCP client context (`Guard.context_mcp_server("mcp-gsuite", ...)`).
3. For each inbound source:
   - Build a source-specific `SecurityContext` (`email_content`/`calendar_content`).
   - Run `guard.process_inbound(...)`.
   - Run `check_extraction_allowed(...)` before KG/indexing.
4. For outbound actions (for example `gmail_send_email`):
   - Build `AuthorizationEvent` with `Guard.authorize(...)`.
   - Build `Binding` with `Guard.bind_request(...)`.
   - Run `await guard.guard_tool_call(..., require_confirmation=True)`.
   - If allowed, run `guard.check_outbound(...)` before transport.
5. Inspect `audit_logger.get_events(...)` for observability.

## Run

```bash
/Users/mhcoen/proj/episodic/.venv/bin/python examples/12_tutorial_gsuite_mcp_client.py
```

## Adapt to Production

- Replace `FakeGsuiteMCP` with your actual MCP transport.
- Replace demo `ConfirmationHandler` logic with your UI confirmation workflow.
- Enforce tool and scope policy from config/service policy.
- Persist audit events to durable storage.
