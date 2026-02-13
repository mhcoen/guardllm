# Tutorial 01: Sanitize Web Search Content

Use this when your MCP client ingests search results from unknown websites.

Script:
- `tutorials/01_web_search_sanitization.py`

What it demonstrates:
1. Build web context with `Guard.context_web(...)`.
2. Sanitize and isolate HTML via `guard.process_inbound(...)`.
3. Enforce source gate policy (`web_content` -> blocked for KG extraction by default).

Expected behavior:
- Processed output is wrapped in an untrusted isolation block, for example:
  - `<untrusted_content source="web_content:duckduckgo" trust="untrusted"> ... </untrusted_content>`

Run:

```bash
/Users/mhcoen/proj/episodic/.venv/bin/python tutorials/01_web_search_sanitization.py
```
