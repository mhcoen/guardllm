# Tutorial 05: MCP Client Hardening

<!-- nav:start -->
[Home](../README.md) / [Tutorials](README.md)
<!-- nav:end -->

Script:
- `tutorials/05_mcp_client_tutorial.py`

This tutorial shows a client-side tool invocation pattern:
1. Build client context with `Guard.context_mcp_server(...)`.
2. Sanitize unknown-provenance inputs used in arguments/prompts.
3. Require explicit authorization + request binding.
4. Run `guard_tool_call(..., require_confirmation=True)`.
5. Pass `recipient=` to drive novel-recipient anomaly detection, surfaced non-blocking on `gate.anomalies` / `OutboundResult.anomalies`.
6. Run outbound checks before making external MCP calls.

Expected behavior:
- Any unknown-provenance input passed through `guard.process_inbound(...)` is wrapped in `<untrusted_content ...>` blocks before being used in prompts or tool arguments.

Run:

```bash
python tutorials/05_mcp_client_tutorial.py
```
