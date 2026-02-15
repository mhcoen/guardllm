# Security Architecture

guardllm uses a defense-in-depth security pipeline designed to harden MCP servers and MCP clients against prompt injection, data exfiltration, replay attacks, and trust-boundary violations from unknown-provenance content sources such as web search results, emails, documents, calendar data, and other untrusted inputs.

## Defense Layers

| Layer | Name | Purpose | Primary Module |
|---|---|---|---|
| L0 | Input Sanitization | Strip hidden HTML, dangerous attributes/comments, invisible Unicode, and normalize content before further processing | `guardllm.security.sanitizer` |
| L1 | Content Isolation | Wrap untrusted input in `<untrusted_content ...>` tags with source attribution | `guardllm.security.isolation` |
| L2 | Action Gate | Optional interactive confirmation gate for sensitive actions | `guardllm.security.action_gate` |
| L3 | Source Gate | Enforce provenance-based KG extraction policies (`allow`, `quarantine`, `block`) | `guardllm.security.source_gate` |
| L4 | Canary Detection | Session canary generation/detection to flag leakage/exfiltration | `guardllm.security.canary` |
| L5 | Tool Firewall | Authorize tools by policy + explicit authorization events | `guardllm.security.policy_engine` |
| L6 | Outbound DLP | Block high-overlap egress and secret-like patterns | `guardllm.security.outbound_dlp` |
| L7 | Provenance Tracking | Track untrusted spans and block suspicious reuse across trust boundaries | `guardllm.security.provenance` |
| L8 | Rate Limiting | Per-context action throttling for abuse resistance | `guardllm.security.rate_limiter` |
| L9 | Request Binding | Bind tool execution to message hash + args hash + TTL | `guardllm.security.request_binding` |
| L10 | OAuth Scope Progression | Scope narrowing/escalation policy between auth/session states | Host application responsibility |
| L11 | Audit Logging | Structured security event logging for analysis and incident response | `guardllm.security.audit` |

Note: Layer numbering intentionally matches the parent hardening model. L10 is documented for completeness but remains outside the library boundary.

## Guard API Coverage (Current)

This section is the source of truth for what is wired through `guardllm.Guard` today.

| Layer | Status | Guard API Surface |
|---|---|---|
| L0 Input Sanitization | Implemented | `process_inbound(...)` |
| L1 Content Isolation | Implemented | `process_inbound(...)` |
| L2 Action Gate | Implemented | `confirm_action(...)`, `guard_tool_call(..., require_confirmation=True)` |
| L3 Source Gate | Implemented | `guardllm.security.source_gate.check_extraction_allowed(...)` |
| L4 Canary Detection | Implemented | `Guard(canary_session_id=...)` + inbound/outbound checks |
| L5 Tool Firewall | Implemented | `check_tool_call(...)`, `guard_tool_call(...)` |
| L6 Outbound DLP | Implemented | `check_outbound(...)` |
| L7 Provenance Tracking | Implemented | `process_inbound(...)`, `check_outbound(...)` |
| L8 Rate Limiting | Implemented | `check_tool_call(...)`, `check_outbound(...)`, `guard_tool_call(...)` |
| L9 Request Binding | Implemented | `bind_request(...)`, `check_tool_call(...)`, `guard_tool_call(...)` |
| L10 OAuth Scope Progression | Not implemented in library | Host application responsibility |
| L11 Audit Logging | Implemented | `Guard(audit_logger=...)` emits security events |
| Validation (spec §12.2) | Implemented | `validate_tool_args(...)`, `guard_tool_call(validate=True)` |
| Error Sanitization (spec §12.6) | Implemented | `sanitize_exception(...)` |

## Unified Pipeline

The central orchestrator is `guardllm.security.pipeline.SecurityPipeline`, exposed through the high-level `Guard` API.

Inbound path:
1. Sanitize untrusted input (L0)
2. Isolate by trust level (L1)
3. Ingest for outbound DLP comparisons (L6 data prep)
4. Record provenance spans (L7)
5. Check canary presence in inbound payloads (L4)

L0 encoded payload handling:
- Base64 and URL-encoded segments are decoded and scored with the prompt-injection detector.
- This avoids relying only on fixed suspicious keyword lists.

Tool-call path:
1. Tool authorization/firewall checks (L5)
2. Rate limiting (L8)
3. Optional request binding verification (L9)

Outbound path:
1. DLP overlap/secret checks (L6)
2. Provenance reuse guard (L7)
3. Rate limiting (L8)
4. Canary leakage detection (L4)

Threshold tuning:
- L6 and L7 overlap thresholds are configurable per context via `PolicyConfig`
  (`dlp_verbatim_lcs_min`, `dlp_ngram_overlap_min`,
  `provenance_verbatim_lcs_min`, `provenance_ngram_overlap_min`).
- Defaults preserve prior behavior (`100/0.40` for DLP, `50/0.30` for provenance).

## Unknown-Provenance Source Handling

guardllm supports explicit security contexts for:
- MCP server responses (`context_mcp_server`)
- MCP client requests (`context_mcp_client`)
- Documents (`context_document`)
- Web results (`context_web`)

You can also define custom `SecurityContext` values for sources like:
- `email_content`
- `calendar_content`
- `tool_output`
- `rag_content`

These source types integrate directly with source-gate and provenance behavior.

## Default Security Posture

- Trust defaults to `UNTRUSTED`.
- Destructive tool calls are blocked unless explicitly enabled via `PolicyConfig(enable_destructive=True)`.
- Destructive tool calls require authorization events in client mode.
- Request binding is optional but recommended for all write-capable actions.
- OAuth/OIDC integration is supported via host-side scope-to-policy mapping (see `docs/oauth_integration.md`).

## Threats Covered

- Hidden-instruction prompt injection in HTML/text payloads
- Unicode obfuscation attacks (zero-width/bidi controls)
- Exfiltration by copying untrusted spans into outbound content
- Replay/deferred tool execution after conversation state changes
- Over-privileged tool invocation and destructive action abuse

## Operational Boundaries

guardllm is an application-layer hardening library. It does not replace:
- network segmentation
- host/container isolation
- secret management systems
- transport-layer authN/authZ
- OAuth/OIDC token issuance, validation, and lifecycle management

Use guardllm as one layer in a full security architecture.
