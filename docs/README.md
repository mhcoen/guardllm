# guardllm Documentation

This directory contains architecture and integration documentation for using guardllm to harden MCP servers, MCP clients, and unknown-provenance input sources (web search, email, documents, calendar data, and other untrusted content).

## Documents

- `quick_start.md`: simple, interaction-focused setup for first integration.
- `security.md`: Defense-in-depth architecture and layer-by-layer controls.
- `api.md`: Stable public API (`Guard`) and usage contract.
- `api_spec.md`: exhaustive API contract (full signatures, defaults, return types, and error semantics).
- `integration.md`: Practical integration patterns for MCP server/client systems.
- `oauth_integration.md`: mapping OAuth scopes to Guard policy and tool-gating decisions.
- `integration_templates.md`: copy-paste templates for MCP server/client and untrusted-input ingestion.
- `configuration.md`: Policy controls and deployment guidance.
- `policy_tuning.md`: guidance for safely tuning policy strictness.
- `troubleshooting.md`: common failure modes, fixes, and FAQ.
- `production_checklist.md`: deployment checklist for production hardening and operations.

Tutorials live in the top-level `tutorials/` directory.

## Framework Integrations

- `integrations/fastapi.md`
- `integrations/mcp_sdk.md`
- `integrations/langchain_llamaindex.md`
