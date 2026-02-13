# Tutorial 04: MCP Server Hardening

Script:
- `tutorials/04_mcp_server_tutorial.py`

This tutorial shows a server-side request handler pattern:
1. Build server context with `Guard.context_mcp_client(...)`.
2. Validate arguments before processing.
3. Sanitize inbound text arguments from untrusted clients.
4. Enforce tool policy/rate checks (`check_tool_call`).
5. Execute tool only if allowed.
6. Run outbound checks before returning response.

Expected behavior:
- Sanitized inbound text returned by `process_inbound(...)` is wrapped in `<untrusted_content ...>` blocks to preserve trust boundaries through server-side processing.

Run:

```bash
python tutorials/04_mcp_server_tutorial.py
```
