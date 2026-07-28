# Framework Integrations

Patterns for wiring GuardLLM into a specific framework. Each page shows where
the ingress, egress, and tool-authorization calls belong in that framework's
request lifecycle.

- [fastapi.md](fastapi.md): guarding inbound and outbound flows in a FastAPI service.
- [mcp_sdk.md](mcp_sdk.md): hardening a server built on the MCP SDK.
- [langchain_llamaindex.md](langchain_llamaindex.md): guarding retrieval and tool
  calls in LangChain and LlamaIndex applications.

## The rule these all share

A `Guard` owns mutable session state: contamination, egress escalation,
provenance spans, DLP buffers, the remembered canary, and rate counters. The
pipeline does not synchronize internally, so the contract is **one Guard per
session**, with the host serializing that session's calls.

A single module-level Guard shared by every request leaks state between users
and lets concurrent requests mutate it unguarded. Every template on these pages
holds one per session and drops it when the session ends.

See [../security.md](../security.md) for the concurrency contract, and
[../integration_templates.md](../integration_templates.md) for the framework
independent versions.
