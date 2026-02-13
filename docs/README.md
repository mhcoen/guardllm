# guardllm Documentation

This directory contains architecture and integration documentation for using guardllm to harden MCP servers, MCP clients, and unknown-provenance input sources (web search, email, documents, calendar data, and other untrusted content).

## Documents

- `security.md`: Defense-in-depth architecture and layer-by-layer controls.
- `api.md`: Stable public API (`Guard`) and usage contract.
- `integration.md`: Practical integration patterns for MCP server/client systems.
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
