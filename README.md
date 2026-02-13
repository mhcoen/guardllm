# guardllm

guardllm is a standalone Python library for hardening MCP servers and MCP clients against content from unknown provenance, including web search results, emails, documents, calendar data, and other untrusted inputs.

It provides:
- inbound sanitization and isolation for untrusted content
- tool-execution policy gates and request binding checks
- outbound DLP/provenance/rate-limit checks
- source-gate controls for KG extraction and quarantine
- error sanitization and structured audit support

## Install

```bash
pip install -e .
```

## Quick Start

```python
from guardllm import Guard
from guardllm.security.types import PolicyConfig

guard = Guard(canary_session_id="session-123")

# 1) Build context for untrusted input (web, document, MCP server/client)
ctx = Guard.context_web(source_id="duckduckgo")

# 2) Process inbound untrusted content
processed = guard.process_inbound("<html><body>hello</body></html>", ctx)

# 3) Gate tool execution with explicit authorization + binding
tool = "gmail_send_email"
args = {"to": "alice@example.com"}
msg = "send email to alice@example.com"
auth = Guard.authorize(
    action=tool,
    scope={"to": "alice@example.com"},
    user_message=msg,
)
binding = Guard.bind_request(tool=tool, args=args, authorization=auth)
tool_result = guard.check_tool_call(
    tool=tool,
    args=args,
    context=Guard.context_mcp_server(
        server_id="mail-server",
        policy=PolicyConfig(enable_destructive=True),
    ),
    authorization=auth,
    binding=binding,
    user_message=msg,
)

# 4) Check outbound response before it leaves your system
outbound = guard.check_outbound("Safe response", ctx)
```

## API Surface

Primary API:
- `Guard(...)`
- `Guard.context_mcp_server(...)`
- `Guard.context_mcp_client(...)`
- `Guard.context_document(...)`
- `Guard.context_web(...)`
- `Guard.authorize(...)`
- `Guard.bind_request(...)`
- `Guard.process_inbound(...)`
- `Guard.check_tool_call(...)`
- `Guard.check_outbound(...)`
- `Guard.validate_tool_args(...)`
- `Guard.confirm_action(...)` (async)
- `Guard.guard_tool_call(...)` (async orchestration)
- `Guard.sanitize_exception(...)`

## Documentation

- Architecture: `docs/security.md`
- API details: `docs/api.md`
- Integration patterns: `docs/integration.md`
- Configuration and policy: `docs/configuration.md`
- Benchmarking: `benchmarks/README.md`
- Tutorials: `tutorials/README.md`

## Development

```bash
pip install -e .[dev]
PYTHONPATH=src pytest -q
```
