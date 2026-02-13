# Configuration and Policy

guardllm is policy-driven via `PolicyConfig` and `SecurityContext`.

## PolicyConfig

`PolicyConfig` fields:
- `tool_allowlist`: client-mode allowlist map for tool authorization policy.
- `directive_patterns`: optional adapter-side directive rules.
- `enable_destructive`: enable destructive tools (default `False`).
- `capability_scopes`: server-mode allowed tool scope mapping.
- `client_id`: optional logical client identity.
- `rate_limits`: custom rate limits (overrides defaults where used).
- `argument_limits`: custom argument constraints.
- `escalation_gate_enabled`: enable heightened confirmation behavior in action gate.

## SecurityContext

`SecurityContext` controls evaluation for each data flow:
- `mode`: `"client"` or `"server"`
- `source_type`: provenance label (`mcp_server`, `mcp_client`, `web_content`, `email_content`, etc.)
- `source_id`: source identifier for traceability
- `trust_level`: trusted/semi-trusted/untrusted
- `content_type`: plaintext/html/structured
- `policy`: `PolicyConfig`

## Recommended Defaults

- Keep `enable_destructive=False` unless explicitly required.
- Use `UNTRUSTED` for any external or mixed-provenance source.
- Require both authorization and binding for all write-capable tools.
- Preserve and monitor warnings from `process_inbound`.

## Deployment Guidance

- Run inbound checks at every trust boundary (server ingress, retrieval ingress, webhook ingress).
- Run tool gating immediately before execution (not earlier in the request lifecycle).
- Run outbound checks on final generated/tool-return content.
- Version and review your policy configuration as code.
