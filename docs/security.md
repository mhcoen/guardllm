# Security Architecture

guardllm uses a defense-in-depth security pipeline designed to harden MCP servers and MCP clients against prompt injection, data exfiltration, replay attacks, and trust-boundary violations from unknown-provenance content sources such as web search results, emails, documents, calendar data, and other untrusted inputs.

## Defense Layers

| Layer | Name | Purpose | Primary Module |
|---|---|---|---|
| L0 | Input Sanitization | Strip hidden HTML, dangerous attributes/comments, invisible Unicode, and normalize content before further processing | `guardllm.security.sanitizer` |
| L1 | Content Isolation | Wrap untrusted input in `<untrusted_content ...>` tags with source attribution | `guardllm.security.isolation` |
| L2 | Source Gate | Enforce provenance-based KG extraction policies (`allow`, `quarantine`, `block`) | `guardllm.security.source_gate` |
| L3 | Outbound DLP | Block high-overlap egress, secret-like patterns, hex decode-then-scan entropy detection, and deobfuscated variants (reversed text, spelled-out characters) | `guardllm.security.outbound_dlp` |
| L4 | Provenance Tracking | Track untrusted spans and block suspicious reuse across trust boundaries, including deobfuscated content variants | `guardllm.security.provenance` |
| L5 | Canary Detection | Session canary generation/detection to flag leakage/exfiltration | `guardllm.security.canary` |
| L6 | Rate Limiting | Per-context action throttling for abuse resistance | `guardllm.security.rate_limiter` |
| L7 | Error Sanitization | Sanitize error payloads before returning to clients | `guardllm.security.error_sanitizer` |
| L8 | OAuth Scope Resolution | Scope narrowing/escalation policy between auth/session states | Host application responsibility |
| L9 | Tool Firewall | Authorize tools by policy + explicit authorization events | `guardllm.security.policy_engine` |
| L10 | Validation | Validate tool arguments before dispatch | `guardllm.security.validation` |
| L11 | Request Binding | Bind tool execution to message hash + args hash + TTL | `guardllm.security.request_binding` |
| L12 | Action Gate | Optional interactive confirmation gate for sensitive actions, with G6 commitment verification | `guardllm.security.action_gate` |
| - | Audit Logging | Structured security event logging for analysis and incident response (cross-cutting observer) | `guardllm.security.audit` |

Note: Layer numbering follows pipeline execution order. L8 is documented for completeness but remains outside the library boundary.

## Guard API Coverage (Current)

This section is the source of truth for what is wired through `guardllm.Guard` today.

| Layer | Status | Guard API Surface |
|---|---|---|
| L0 Input Sanitization | Implemented | `process_inbound(...)` |
| L1 Content Isolation | Implemented | `process_inbound(...)` |
| L2 Source Gate | Implemented | `guardllm.security.source_gate.check_extraction_allowed(...)` |
| L3 Outbound DLP | Implemented | `check_outbound(...)` |
| L4 Provenance Tracking | Implemented | `process_inbound(...)`, `check_outbound(...)` |
| L5 Canary Detection | Implemented | `Guard(canary_session_id=...)` + inbound/outbound checks |
| L6 Rate Limiting | Implemented | `check_tool_call(...)`, `check_outbound(...)`, `guard_tool_call(...)` |
| L7 Error Sanitization | Implemented | `sanitize_exception(...)` |
| L8 OAuth Scope Resolution | Not implemented in library | Host application responsibility |
| L9 Tool Firewall | Implemented | `check_tool_call(...)`, `guard_tool_call(...)` |
| L10 Validation | Implemented | `validate_tool_args(...)`, `guard_tool_call(validate=True)` |
| L11 Request Binding | Implemented | `bind_request(...)`, `check_tool_call(...)`, `guard_tool_call(...)` |
| L12 Action Gate | Implemented | `confirm_action(...)`, `guard_tool_call(..., require_confirmation=True)` |
| Audit Logging | Implemented | `Guard(audit_logger=...)` emits security events |

## Unified Pipeline

The central orchestrator is `guardllm.security.pipeline.SecurityPipeline`, exposed through the high-level `Guard` API.

Inbound path:
1. TR39 confusable normalization (homoglyph characters mapped to ASCII)
2. Sanitize untrusted input (L0)
3. Isolate by trust level (L1)
4. Ingest for outbound DLP comparisons (L3 data prep)
5. Record provenance spans (L4)
6. Check canary presence in inbound payloads (L5)

Compound ingress (`process_inbound_compound`):
- Accepts a list of (content, SecurityContext) spans representing a single message with mixed provenance (e.g., a trusted envelope wrapping a forwarded untrusted payload).
- Each span is processed independently through the pipeline above. Session state (contamination, DLP buffers, provenance) accumulates across all spans.
- Core invariant: a trusted transport does not upgrade embedded untrusted content. Forwarding cannot launder untrusted content into trusted extraction.
- If any span has `source_trust == UNTRUSTED`, the session contamination flag is set, widening downstream egress and tool-call checks for the entire session.

L0 encoded payload handling:
- Base64 and URL-encoded segments are decoded and scored with the prompt-injection detector.
- This avoids relying only on fixed suspicious keyword lists.

Tool-call path:
1. Tool authorization/firewall checks (L9)
2. Rate limiting (L6)
3. Optional request binding verification (L11)
4. Optional L12 confirmation gate with G6 commitment verification: the action gate captures a canonical snapshot of tool args before the confirmation handler is called. After confirmation, `verify_commitment` checks that the args have not been mutated. If args changed between confirmation and execution, the call is rejected (prevents TOCTOU attacks on the confirmation flow).

Outbound path:
1. TR39 confusable normalization (homoglyph characters mapped to ASCII)
2. DLP overlap/secret checks (L3), including deobfuscated variants (reversed text, spelled-out characters) and hex decode-then-scan for entropy detection
3. Provenance reuse guard (L4), including deobfuscated variants
4. Rate limiting (L6)
5. Canary leakage detection (L5)

Threshold tuning:
- L3 and L4 overlap thresholds are configurable per context via `PolicyConfig`
  (`dlp_verbatim_lcs_min`, `dlp_ngram_overlap_min`,
  `provenance_verbatim_lcs_min`, `provenance_ngram_overlap_min`).
- DLP defaults: `dlp_verbatim_lcs_min=14`, `dlp_sensitive_lcs_min=12`, `dlp_ngram_overlap_min=0.40`.
- Provenance defaults: `provenance_verbatim_lcs_min=50`, `provenance_ngram_overlap_min=0.30`.

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

- Both trust axes default to `UNTRUSTED`: `source_trust` (per-content) and `principal_trust` (per-session caller) each default to `TrustLevel.UNTRUSTED`.
- Destructive tool calls are blocked unless explicitly enabled via `PolicyConfig(enable_destructive=True)`.
- Destructive tool calls require authorization events in client mode.
- Request binding is optional but recommended for all write-capable actions.
- OAuth/OIDC integration is supported via host-side scope-to-policy mapping (see `docs/oauth_integration.md`).

## Threats Covered

- Hidden-instruction prompt injection in HTML/text payloads
- Unicode obfuscation attacks (zero-width/bidi controls, TR39 homoglyph substitution)
- Exfiltration by copying untrusted spans into outbound content
- Obfuscated exfiltration via reversed text or spelled-out characters (e.g. `s-t-r-i-p-e`)
- Hex-encoded secret exfiltration (decoded and entropy-scanned)
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
