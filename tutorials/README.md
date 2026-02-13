# Tutorials

Step-by-step guides for larger end-to-end integrations.

## Available Tutorials

- `01_web_search_sanitization.py` / `01_web_search_sanitization.md`: sanitize and isolate unknown-provenance web search content.
- `02_email_calendar_sanitization.py` / `02_email_calendar_sanitization.md`: sanitize unknown email and calendar inputs before downstream use.
- `03_safe_tool_call_pipeline.py` / `03_safe_tool_call_pipeline.md`: validate + authorize + bind + confirm + outbound-check a destructive tool call.
- `04_mcp_server_tutorial.py` / `04_mcp_server_tutorial.md`: MCP server-side hardening flow for untrusted MCP client requests.
- `05_mcp_client_tutorial.py` / `05_mcp_client_tutorial.md`: MCP client-side hardening flow for external MCP tool invocations.
- `gsuite_mcp_client_tutorial.py` / `gsuite_mcp_client_tutorial.md`: full end-to-end GSuite-style MCP client hardening tutorial.

Run tutorial scripts from repo root:

```bash
python tutorials/01_web_search_sanitization.py
python tutorials/02_email_calendar_sanitization.py
python tutorials/03_safe_tool_call_pipeline.py
python tutorials/04_mcp_server_tutorial.py
python tutorials/05_mcp_client_tutorial.py
python tutorials/gsuite_mcp_client_tutorial.py
```
