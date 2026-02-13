# Tutorial 05: MCP Client Hardening

Script:
- `tutorials/05_mcp_client_tutorial.py`

This tutorial shows a client-side tool invocation pattern:
1. Build client context with `Guard.context_mcp_server(...)`.
2. Sanitize unknown-provenance inputs used in arguments/prompts.
3. Require explicit authorization + request binding.
4. Run `guard_tool_call(..., require_confirmation=True)`.
5. Run outbound checks before making external MCP calls.

Run:

```bash
/Users/mhcoen/proj/episodic/.venv/bin/python tutorials/05_mcp_client_tutorial.py
```
