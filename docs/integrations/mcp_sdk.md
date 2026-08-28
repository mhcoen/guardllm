# Integration: MCP SDK Middleware Pattern

<!-- nav:start -->
[Docs index](../README.md) / [Integrations](README.md)
<!-- nav:end -->

Use Vörður as a middleware-style layer around MCP request/response handling.

## Server side

- Build context with `Guard.context_mcp_client(client_id=...)`
- Validate + sanitize inbound args
- Gate tool calls with `check_tool_call(...)`
- Check outbound response before returning

## Client side

- Build context with `Guard.context_mcp_server(server_id=...)`
- Sanitize unknown-provenance context before tool selection
- Use `guard_tool_call(..., require_confirmation=True)` for destructive tools
- Check outbound content before invoking transport

See copy-paste templates in `docs/integration_templates.md` and runnable tutorials in `tutorials/`.
