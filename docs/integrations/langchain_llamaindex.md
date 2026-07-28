# Integration: LangChain / LlamaIndex

<!-- nav:start -->
[Docs index](../README.md) / [Integrations](README.md)
<!-- nav:end -->

Treat external retrieval and tool execution as trust boundaries.

## Recommended placement

1. Before retrieval chunks are inserted into prompts:
   - run `process_inbound(...)` on chunk text
2. Before tool execution:
   - run `guard_tool_call(...)` with authorization/binding for write-capable tools
3. Before final answer output:
   - run `check_outbound(...)`

## Minimal sketch

```python
from guardllm import Guard

guard = Guard()
ctx = Guard.context_document(document_id="retrieved-doc")

safe_chunk = guard.process_inbound(raw_chunk_text, ctx).content
# include safe_chunk in prompt context

# ... generate answer ...
out = guard.check_outbound(answer_text, ctx)
if not out.allowed:
    answer_text = "Blocked unsafe output"
```

For tool-enabled chains/agents, combine this with the MCP client template in `docs/integration_templates.md`.
