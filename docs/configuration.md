# Configuration and Policy

guardllm is policy-driven via `PolicyConfig` and `SecurityContext`.

## PolicyConfig

`PolicyConfig` fields:
- `tool_allowlist`: client-mode allowlist map for tool authorization policy.
- `directive_patterns`: optional adapter-side directive rules.
- `enable_destructive`: enable destructive tools (default `False`).
- `capability_scopes`: server-mode allowed tool scope mapping (`None` = no allowlist; `{}` = deny all tools).
- `client_id`: optional logical client identity.
- `rate_limits`: custom rate limits (overrides defaults where used).
- `argument_limits`: custom argument constraints.
- `escalation_gate_enabled`: enable heightened confirmation behavior in action gate.
- `contaminated_action`: action when contaminated context detected (default `"block"`).
- `dlp_verbatim_lcs_min`: untrusted-echo LCS threshold (default `14` chars).
- `dlp_ngram_overlap_min`: outbound DLP n-gram overlap block threshold (default `0.40`).
- `dlp_sensitive_lcs_min`: sensitive-leak LCS threshold (default `12` chars).
- `provenance_verbatim_lcs_min`: provenance verbatim overlap block threshold (default `50` chars).
- `provenance_ngram_overlap_min`: provenance n-gram overlap block threshold (default `0.30`).
- `source_gate_overrides`: override source gate policy keyed by `(source_type, source_trust)`.
- `untrusted_deny_tools`: tools denied when `principal_trust == UNTRUSTED`.
- `untrusted_require_auth`: require auth event when `principal_trust == UNTRUSTED` (default `False`).
- `confirm_all_below`: require confirmation for all tools when `principal_trust` is at or below this level.
- `rate_limit_overrides`: per-`principal_trust` rate limit overrides, merged over defaults.
- `contaminated_tool_policy`: tool gating when context is contaminated (`"allow"`, `"require_auth"`, or `"deny"`; default `"allow"`).
- `auto_confirm_destructive`: auto-require confirmation for destructive tool calls (default `False`). Production deployments should set to `True`.
- `require_source_id_for`: source types that require non-empty `source_id` (default empty frozenset). Blocks KG extraction when violated.

## SecurityContext

`SecurityContext` controls evaluation for each data flow:
- `mode`: `"client"` or `"server"`
- `source_type`: provenance label (`mcp_server`, `mcp_client`, `web_content`, `email_content`, etc.)
- `source_id`: source identifier for traceability
- `source_trust`: per-content trust (`TRUSTED` or `UNTRUSTED` only; `SEMI_TRUSTED` is not valid on this axis)
- `principal_trust`: per-session caller identity (`TRUSTED`, `SEMI_TRUSTED`, or `UNTRUSTED`)
- `sensitivity`: data sensitivity level (`PUBLIC`, `INTERNAL`, or `SENSITIVE`)
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
