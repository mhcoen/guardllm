# Tutorials

Step-by-step guides for larger end-to-end integrations.

## Available Tutorials

- [01_web_search_sanitization.md](01_web_search_sanitization.md) ([run the script](01_web_search_sanitization.py)): sanitize and isolate unknown-provenance web search content.
- [02_email_calendar_sanitization.md](02_email_calendar_sanitization.md) ([run the script](02_email_calendar_sanitization.py)): sanitize unknown email and calendar inputs before downstream use.
- [03_safe_tool_call_pipeline.md](03_safe_tool_call_pipeline.md) ([run the script](03_safe_tool_call_pipeline.py)): validate + authorize + bind + confirm + outbound-check a destructive tool call; anti-replay message binding; egress feedback escalation (a DLP block at egress tightens later tool calls).
- [04_mcp_server_tutorial.md](04_mcp_server_tutorial.md) ([run the script](04_mcp_server_tutorial.py)): MCP server-side hardening flow for untrusted MCP client requests.
- [05_mcp_client_tutorial.md](05_mcp_client_tutorial.md) ([run the script](05_mcp_client_tutorial.py)): MCP client-side hardening flow for external MCP tool invocations.
- [gsuite_mcp_client_tutorial.md](gsuite_mcp_client_tutorial.md) ([run the script](gsuite_mcp_client_tutorial.py)): full end-to-end GSuite-style MCP client hardening tutorial.

Run tutorial scripts from repo root:

```bash
python tutorials/01_web_search_sanitization.py
python tutorials/02_email_calendar_sanitization.py
python tutorials/03_safe_tool_call_pipeline.py
python tutorials/04_mcp_server_tutorial.py
python tutorials/05_mcp_client_tutorial.py
python tutorials/gsuite_mcp_client_tutorial.py
```
