"""§12.1: Unified security pipeline.

Orchestrates all security layers for both client and server mode.
Parameterized by SecurityContext rather than branching on direction.
"""

from __future__ import annotations

from typing import Optional

from guardllm.security.canary import detect_canary, generate_canary
from guardllm.security.source_gate import (
    check_extraction_allowed,
    ExtractionPolicy,
    SourceGateResult,
)
from guardllm.security.isolation import wrap_untrusted
from guardllm.security.outbound_dlp import OutboundDLP
from guardllm.security.policy_engine import PolicyEngine
from guardllm.security.prompt_injection_detector import detect_prompt_injection
from guardllm.security.provenance import ProvenancedSpan, ProvenanceTracker
from guardllm.security.rate_limiter import RateLimiter
from guardllm.security.request_binding import verify_binding
from guardllm.security.sanitizer import sanitize
from guardllm.security.types import (
    AuthorizationEvent,
    Binding,
    GateResult,
    OutboundResult,
    ProcessedContent,
    SecurityContext,
    TrustLevel,
)


class SecurityPipeline:
    """Unified security pipeline for client and server mode.

    Entry points:
    - process_inbound: Content arriving from any source
    - check_outbound: Content leaving the system
    - check_tool_execution: Policy check before tool execution
    """

    def __init__(
        self,
        audit_logger: Optional[object] = None,
        canary_session_id: Optional[str] = None,
    ) -> None:
        self._sanitizer = sanitize
        self._provenance = ProvenanceTracker()
        self._dlp = OutboundDLP()
        self._policy = PolicyEngine()
        self._rate_limiter = RateLimiter()
        self._audit_logger = audit_logger
        self._canary: Optional[str] = None
        if canary_session_id:
            self._canary = generate_canary(canary_session_id)

    def process_inbound(
        self,
        content: str,
        ctx: SecurityContext,
    ) -> ProcessedContent:
        """Process content arriving from any source.

        Runs: L0 (sanitize) -> L1 (isolate) -> DLP ingest -> provenance.

        Client mode: MCP server response content.
        Server mode: MCP client argument content.
        """
        warnings: list[str] = []

        # Early prompt-injection signal pass on raw input.
        detection = detect_prompt_injection(content, ctx.content_type)
        warnings.extend(detection.warnings)

        # L0: Sanitize
        san_result = self._sanitizer(content, ctx.content_type)
        cleaned = san_result.cleaned_text
        warnings.extend(san_result.warnings)

        # L1: Isolate untrusted/semi-trusted content
        isolated = False
        if ctx.trust_level in (TrustLevel.UNTRUSTED, TrustLevel.SEMI_TRUSTED):
            cleaned = wrap_untrusted(
                cleaned,
                source_type=ctx.source_type,
                source_id=ctx.source_id,
                trust=ctx.trust_level.value,
            )
            isolated = True
        elif detection.is_attack:
            # If trusted content carries strong injection signals, keep the same
            # structural boundary used for untrusted input.
            cleaned = wrap_untrusted(
                cleaned,
                source_type=ctx.source_type,
                source_id=ctx.source_id,
                trust=ctx.trust_level.value,
            )
            isolated = True

        # Ingest into DLP buffer for later outbound checks
        if ctx.trust_level in (TrustLevel.UNTRUSTED, TrustLevel.SEMI_TRUSTED):
            self._dlp.ingest_untrusted(content)

        # Add provenance span
        self._provenance.add_span(ProvenancedSpan(
            text=content,
            source_type=ctx.source_type,
            source_id=ctx.source_id,
            trust_level=ctx.trust_level.value,
        ))

        # Canary detection on inbound (exfiltration attempt)
        if self._canary and detect_canary(content, self._canary):
            warnings.append("Canary token detected in inbound content")

        return ProcessedContent(
            content=cleaned,
            sanitization=san_result,
            isolated=isolated,
            source_type=ctx.source_type,
            source_id=ctx.source_id,
            warnings=warnings,
        )

    def check_outbound(
        self,
        content: str,
        ctx: SecurityContext,
        has_quoting_directive: bool = False,
    ) -> OutboundResult:
        """Check content leaving the system.

        Runs: L6 (DLP) -> L7 (provenance) -> L8 (rate limit) -> L4 (canary).

        Ordering rationale (spec §7, §8):
        - DLP runs first as a coarse pre-filter (default LCS >= 100,
          n-gram >= 40%, configurable via PolicyConfig) to catch obvious
          exfiltration cheaply before provenance.
        - Provenance runs second as the primary no-copy enforcement
          (default LCS >= 50, n-gram >= 30%, configurable via PolicyConfig).
        - Both layers share overlap utilities from normalization.py.
        - Secrets are always checked (even with quoting) in the DLP step.

        Client mode: tool arguments (e.g. email body).
        Server mode: tool responses.
        """
        # L6: DLP scan (coarse pre-filter, higher thresholds)
        dlp_result = self._dlp.check(content, ctx, has_quoting_directive)
        if not dlp_result.allowed:
            return dlp_result

        # L7: Provenance check
        prov_allowed, prov_reason = self._provenance.check_outbound(
            content,
            has_quoting_directive,
            lcs_threshold=int(getattr(ctx.policy, "provenance_verbatim_lcs_min", 50)),
            ngram_threshold=float(getattr(ctx.policy, "provenance_ngram_overlap_min", 0.30)),
        )
        if not prov_allowed:
            return OutboundResult(
                allowed=False,
                reason=prov_reason,
                provenance_blocked=True,
            )

        # L8: Rate limit check
        rate_result = self._rate_limiter.check(
            action="outbound",
            ctx=ctx,
        )
        if not rate_result.allowed:
            return OutboundResult(
                allowed=False,
                reason=rate_result.reason,
            )

        # L4: Canary detection on outbound
        if self._canary and detect_canary(content, self._canary):
            return OutboundResult(
                allowed=False,
                reason="Canary token detected in outbound content",
            )

        return OutboundResult(allowed=True, reason="clean")

    def check_tool_execution(
        self,
        tool: str,
        args: dict,
        ctx: SecurityContext,
        auth_event: Optional[AuthorizationEvent] = None,
        binding: Optional[Binding] = None,
        message_hash: Optional[str] = None,
    ) -> GateResult:
        """Policy check before tool execution.

        Runs: L5 (policy) -> L8 (rate limit) -> L9 (request binding).

        Client mode: calling external MCP tool.
        Server mode: executing internal tool for MCP client.
        """
        # L5: Policy engine check
        policy_result = self._policy.check_tool_execution(
            tool, args, auth_event, ctx
        )
        if not policy_result.allowed:
            return policy_result

        # L8: Rate limit
        rate_result = self._rate_limiter.check(action=tool, ctx=ctx)
        if not rate_result.allowed:
            return GateResult(
                allowed=False,
                reason=rate_result.reason,
                confidence="none",
            )

        # L9: Request binding verification
        if binding is not None:
            msg_hash = message_hash or (
                auth_event.message_hash if auth_event else ""
            )
            bind_ok, bind_reason = verify_binding(
                binding, tool, args, msg_hash
            )
            if not bind_ok:
                return GateResult(
                    allowed=False,
                    reason=bind_reason,
                    confidence="none",
                )

        return policy_result

    def check_kg_extraction(
        self,
        source_type: str,
        source_id: str = "",
    ) -> SourceGateResult:
        """Check if KG extraction is allowed for this source (Layer 3)."""
        return check_extraction_allowed(source_type, source_id)
