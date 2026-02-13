# guardllm

guardllm is a standalone Python library for hardening LLM-based applications by securing how they process and act on unknown-provenance content, including web search results, emails, documents, calendar data, MCP tool traffic, and other untrusted inputs.

It provides:
- inbound sanitization and isolation for untrusted content
- tool-execution policy gates and request binding checks
- outbound DLP/provenance/rate-limit checks
- source-gate controls for KG extraction and quarantine
- error sanitization and structured audit support

Benchmark status: guardllm currently passes all benchmark cases in this repo (`82/82`) across [PINT-style](benchmarks/cases/pint_style.jsonl), [BIPIA-style](benchmarks/cases/bipia_style.jsonl), [AgentDojo-style](benchmarks/cases/agentdojo_style.jsonl), [OWASP LLM Top 10-style](benchmarks/cases/owasp_llm_top10_style.jsonl), [garak-style](benchmarks/cases/garak_style.jsonl), [promptfoo red-team style](benchmarks/cases/promptfoo_redteam_style.jsonl), [MCP protocol abuse](benchmarks/cases/mcp_protocol_abuse_style.jsonl), [RAG poisoning](benchmarks/cases/rag_poisoning_style.jsonl), [secrets exfiltration](benchmarks/cases/secrets_exfil_style.jsonl), [multistep agent attacks](benchmarks/cases/multistep_agent_attack_style.jsonl), and [Unicode evasion](benchmarks/cases/unicode_evasion_style.jsonl) suites (see [benchmark harness docs](benchmarks/README.md)).

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

## Current Benchmark Results

Latest local benchmark run:
- Total: `82`
- Passed: `82`
- Failed: `0`
- Pass rate: `100%`
- Suites: `pint_style (14/14)`, `bipia_style (14/14)`, `agentdojo_style (14/14)`, `owasp_llm_top10_style (5/5)`, `garak_style (5/5)`, `promptfoo_redteam_style (5/5)`, `mcp_protocol_abuse_style (5/5)`, `rag_poisoning_style (5/5)`, `secrets_exfil_style (5/5)`, `multistep_agent_attack_style (5/5)`, `unicode_evasion_style (5/5)`

Re-run:

```bash
/Users/mhcoen/proj/episodic/.venv/bin/python benchmarks/run_benchmarks.py
```

Detailed report is written to `benchmarks/results/latest.json`.

## Development

```bash
pip install -e .[dev]
PYTHONPATH=src pytest -q
```
