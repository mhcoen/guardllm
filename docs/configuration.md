# Configuration and Policy

guardllm is policy-driven via `PolicyConfig` and `SecurityContext`.

## PolicyConfig

`PolicyConfig` fields:
- `tool_allowlist`: client-mode allowlist map for tool authorization policy (`None` = no allowlist, fall through; `{}` = deny all tools; `{tool: ...}` = allow listed tools only).
- `directive_patterns`: **reserved / not yet wired.** Accepted for forward compatibility but not consulted by the policy engine today. The library validates an `AuthorizationEvent`'s contents, not its origin; ensuring only trusted adapters can construct events is a host obligation (see A-AS8 in `docs/threat_model.md`). Its disposition (deprecate vs. wire as a source-string consistency check) is undecided; retained as a constructor field to avoid a breaking change post-2.0.0.
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
- `contaminated_tool_policy`: tool gating when context is contaminated (untrusted content ingested this session) (`"allow"`, `"require_auth"`, or `"deny"`; default `"allow"`).
- `escalated_tool_policy`: tool gating once an egress DLP block has fired this session (the backward-propagating complement of contamination) (`"allow"`, `"require_auth"`, or `"deny"`; default `"require_auth"`). Contamination and escalation are independent; when both fire the strictest policy wins. See "Session Risk Signals" in `docs/security.md`.
- `auto_confirm_destructive`: auto-require confirmation for destructive tool calls (default `False`). Production deployments should set to `True`.
- `require_source_id_for`: source types that require non-empty `source_id` (default empty frozenset). Blocks KG extraction when violated.
- `server_default_deny`: server-mode fail-closed (default `False`). When `True`, a missing `capability_scopes` (`None`) denies all tools instead of allowing non-destructive tools by default. Set to `True` in production so a forgotten scope config does not silently allow tools.
- `require_message_binding`: anti-replay message binding for client-mode authorizations (`"off"`, `"destructive"`, or `"all"`; default `"off"`). A current message hash that mismatches the authorized message is always denied as replay; this flag additionally controls whether a *missing* current hash fails closed: `"destructive"` requires it for destructive tools, `"all"` for every authorized tool call.

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
- Set `server_default_deny=True` (server mode) so a missing `capability_scopes` fails closed.
- Set `require_message_binding="destructive"` (or `"all"`) and pass the current `user_message`/`message_hash` so authorizations cannot be replayed across messages.
- Preserve and monitor warnings from `process_inbound`.

## Deployment Guidance

- Run inbound checks at every trust boundary (server ingress, retrieval ingress, webhook ingress).
- Run tool gating immediately before execution (not earlier in the request lifecycle).
- Run outbound checks on final generated/tool-return content.
- Version and review your policy configuration as code.
