"""§12.1: Unified security pipeline.

Orchestrates all security layers for both client and server mode.
Parameterized by SecurityContext rather than branching on direction.
"""

from __future__ import annotations

from guardllm.security.canary import detect_canary, generate_canary
from guardllm.security.isolation import wrap_untrusted
from guardllm.security.normalization import normalize_confusables
from guardllm.security.outbound_dlp import OutboundDLP
from guardllm.security.policy_engine import PolicyEngine
from guardllm.security.prompt_injection_detector import detect_prompt_injection
from guardllm.security.provenance import ProvenancedSpan, ProvenanceTracker
from guardllm.security.rate_limiter import RateLimiter
from guardllm.security.request_binding import verify_binding
from guardllm.security.sanitizer import sanitize
from guardllm.security.source_gate import (
    SourceGateResult,
    check_extraction_allowed,
)
from guardllm.security.types import (
    AuthorizationEvent,
    Binding,
    GateResult,
    OutboundResult,
    ProcessedContent,
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)

# Tool-gating policy strictness ranking. When multiple session-risk signals
# fire (contamination, egress escalation), the strictest policy wins.
_POLICY_RANK = {"allow": 0, "require_auth": 1, "deny": 2}


class SecurityPipeline:
    """Unified security pipeline for client and server mode.

    Entry points:
    - process_inbound: Content arriving from any source
    - check_outbound: Content leaving the system
    - check_tool_execution: Policy check before tool execution
    """

    def __init__(
        self,
        audit_logger: object | None = None,
        canary_session_id: str | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
    ) -> None:
        self._sanitizer = sanitize
        self._provenance = ProvenanceTracker()
        self._dlp = OutboundDLP()
        self._policy = PolicyEngine()
        self._rate_limiter = RateLimiter()
        self._audit_logger = audit_logger
        self._principal_trust = principal_trust
        self._context_contaminated: bool = False
        self._session_escalated: bool = False
        self._canary: str | None = None
        if canary_session_id:
            self._canary = generate_canary(canary_session_id)

    @property
    def principal_trust(self) -> TrustLevel:
        """Session-level principal trust, immutable after construction."""
        return self._principal_trust

    @property
    def context_contaminated(self) -> bool:
        """True once untrusted content has entered this session."""
        return self._context_contaminated

    @property
    def session_escalated(self) -> bool:
        """True once a DLP block has fired at egress in this session."""
        return self._session_escalated

    def reset(self) -> None:
        """Reset pipeline state for a new session.

        Clears both contamination and egress-escalation state. Hosts must call
        this only at genuine session/task boundaries (see docs/security.md):
        escalation is monotonic within a session and reset is the only way to
        clear it.
        """
        self._context_contaminated = False
        self._session_escalated = False
        self._provenance = ProvenanceTracker()
        self._dlp = OutboundDLP()
        self._rate_limiter = RateLimiter()

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
        if ctx.principal_trust != self._principal_trust:
            raise ValueError(
                f"principal_trust mismatch: context has {ctx.principal_trust}, "
                f"pipeline was constructed with {self._principal_trust}"
            )
        warnings: list[str] = []

        # TR39 confusable normalization at inbound trust boundary.
        # Maps homoglyph characters to ASCII before any security check.
        content = normalize_confusables(content)

        # Early prompt-injection signal pass on raw input.
        detection = detect_prompt_injection(content, ctx.content_type)
        warnings.extend(detection.warnings)

        # L0: Sanitize
        san_result = self._sanitizer(content, ctx.content_type)
        cleaned = san_result.cleaned_text
        warnings.extend(san_result.warnings)

        # L1: Isolate untrusted content
        isolated = False
        if ctx.source_trust == TrustLevel.UNTRUSTED:
            cleaned = wrap_untrusted(
                cleaned,
                source_type=ctx.source_type,
                source_id=ctx.source_id,
                trust=ctx.source_trust.value,
            )
            isolated = True
        elif detection.is_attack:
            # If trusted content carries strong injection signals, keep the same
            # structural boundary used for untrusted input.
            cleaned = wrap_untrusted(
                cleaned,
                source_type=ctx.source_type,
                source_id=ctx.source_id,
                trust=ctx.source_trust.value,
            )
            isolated = True

        # Ingest into DLP buffer for later outbound checks
        if ctx.source_trust == TrustLevel.UNTRUSTED:
            self._dlp.ingest_untrusted(content)
            self._context_contaminated = True

        # Ingest sensitive content into DLP for contaminated-context checks
        if ctx.sensitivity == SensitivityLevel.SENSITIVE:
            self._dlp.ingest_sensitive(content)

        # Add provenance span
        self._provenance.add_span(
            ProvenancedSpan(
                text=content,
                source_type=ctx.source_type,
                source_id=ctx.source_id,
                source_trust=ctx.source_trust,
                sensitivity=ctx.sensitivity,
            )
        )

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
        recipient: str | None = None,
    ) -> OutboundResult:
        """Check content leaving the system.

        Runs: L3 (DLP) -> L4 (provenance) -> L6 (rate limit) -> L5 (canary).

        Ordering rationale (spec §7, §8):
        - DLP runs first as a coarse pre-filter (default LCS >= 14 for
          untrusted echo, >= 12 for sensitive leak, n-gram >= 40%,
          configurable via PolicyConfig) to catch exfiltration cheaply
          before provenance.
        - Provenance runs second as the primary no-copy enforcement
          (default LCS >= 50, n-gram >= 30%, configurable via PolicyConfig).
        - Both layers share overlap utilities from normalization.py.
        - Secrets are always checked (even with quoting) in the DLP step.

        Client mode: tool arguments (e.g. email body).
        Server mode: tool responses.
        """
        if ctx.principal_trust != self._principal_trust:
            raise ValueError(
                f"principal_trust mismatch: context has {ctx.principal_trust}, "
                f"pipeline was constructed with {self._principal_trust}"
            )
        # TR39 confusable normalization at outbound trust boundary.
        content = normalize_confusables(content)

        # L3: DLP scan (coarse pre-filter, higher thresholds)
        dlp_result = self._dlp.check(
            content,
            ctx,
            has_quoting_directive,
            contaminated=self._context_contaminated,
        )
        if not dlp_result.allowed:
            # Egress-feedback escalation: a DLP hard block is a high-confidence
            # signal that something bad happened this session. Record it so
            # subsequent tool calls can be tightened (backward-propagating,
            # the reverse complement of _context_contaminated). DLP blocks
            # only -- echo signals return allowed=True, provenance/rate/canary
            # blocks are handled below and do not set this flag.
            self._session_escalated = True
            return dlp_result

        # L4: Provenance check
        prov_allowed, prov_reason = self._provenance.check_outbound(
            content,
            has_quoting_directive,
            lcs_threshold=int(getattr(ctx.policy, "provenance_verbatim_lcs_min", 50)),
            ngram_threshold=float(getattr(ctx.policy, "provenance_ngram_overlap_min", 0.30)),
            contaminated=self._context_contaminated,
        )
        if not prov_allowed:
            contamination_triggered = "sensitive" in prov_reason and self._context_contaminated
            reason = prov_reason
            if contamination_triggered and ctx.policy.contaminated_action == "confirm":
                reason = f"Confirmation required: {prov_reason}"
            return OutboundResult(
                allowed=False,
                reason=reason,
                provenance_blocked=True,
                contamination_triggered=contamination_triggered,
                echo_detected=dlp_result.echo_detected,
                echo_lcs=dlp_result.echo_lcs,
            )

        # L6: Rate limit check
        rate_result = self._rate_limiter.check(
            action="outbound",
            ctx=ctx,
            recipient=recipient,
        )
        if not rate_result.allowed:
            return OutboundResult(
                allowed=False,
                reason=rate_result.reason,
                anomalies=rate_result.anomalies,
            )

        # L5: Canary detection on outbound
        if self._canary and detect_canary(content, self._canary):
            return OutboundResult(
                allowed=False,
                reason="Canary token detected in outbound content",
                anomalies=rate_result.anomalies,
            )

        # L6: record the now-permitted outbound action so the rate limiter
        # accumulates state across calls (otherwise check() never trips).
        self._rate_limiter.record(action="outbound", ctx=ctx, recipient=recipient)

        # Surface non-blocking anomaly signals (burst, novel recipient) rather
        # than discarding them, so downstream audit/callers can act on them.
        return OutboundResult(
            allowed=True,
            reason="clean" if not dlp_result.echo_detected else "clean (echo signal only)",
            echo_detected=dlp_result.echo_detected,
            echo_lcs=dlp_result.echo_lcs,
            anomalies=rate_result.anomalies,
        )

    def check_tool_execution(
        self,
        tool: str,
        args: dict,
        ctx: SecurityContext,
        auth_event: AuthorizationEvent | None = None,
        binding: Binding | None = None,
        message_hash: str | None = None,
        recipient: str | None = None,
    ) -> GateResult:
        """Policy check before tool execution.

        Runs: contamination gate -> L9 (policy) -> L6 (rate limit) -> L11 (request binding).

        Client mode: calling external MCP tool.
        Server mode: executing internal tool for MCP client.
        """
        if ctx.principal_trust != self._principal_trust:
            raise ValueError(
                f"principal_trust mismatch: context has {ctx.principal_trust}, "
                f"pipeline was constructed with {self._principal_trust}"
            )
        # Session-risk tool gating (cross-stage invariant). Contamination
        # (forward, from untrusted ingest) and egress escalation (backward,
        # from a DLP block) are independent signals that each tighten tool
        # policy. Compute one effective policy -- the strictest of the active
        # signals -- and enumerate the contributing triggers in the reason so
        # provenance is preserved.
        active_signals: list[tuple[str, str]] = []
        if self._context_contaminated:
            active_signals.append(("session contaminated", ctx.policy.contaminated_tool_policy))
        if self._session_escalated:
            active_signals.append(("egress escalated", ctx.policy.escalated_tool_policy))

        effective_policy = "allow"
        for _label, policy in active_signals:
            if _POLICY_RANK[policy] > _POLICY_RANK[effective_policy]:
                effective_policy = policy

        if effective_policy != "allow":
            # Auditability: name each contributing trigger with its policy, e.g.
            # "session contaminated=deny; egress escalated=require_auth", so the
            # deciding signal is unambiguous in mixed-policy denials.
            triggers = "; ".join(
                f"{label}={policy}" for label, policy in active_signals if policy != "allow"
            )
            if effective_policy == "deny":
                return GateResult(
                    allowed=False,
                    reason=f"Tool call denied: {triggers}",
                    confidence="none",
                )
            if effective_policy == "require_auth" and auth_event is None:
                return GateResult(
                    allowed=False,
                    reason=f"Authorization required: {triggers}",
                    confidence="none",
                )

        # L9: Policy engine check. Pass the genuine current message hash (not
        # the auth_event fallback) so message binding can detect replay.
        policy_result = self._policy.check_tool_execution(
            tool, args, auth_event, ctx, current_message_hash=message_hash
        )
        if not policy_result.allowed:
            return policy_result

        # L6: Rate limit
        rate_result = self._rate_limiter.check(action=tool, ctx=ctx, recipient=recipient)
        if not rate_result.allowed:
            return GateResult(
                allowed=False,
                reason=rate_result.reason,
                confidence="none",
                anomalies=rate_result.anomalies,
            )

        # L11: Request binding verification
        if binding is not None:
            msg_hash = message_hash or (auth_event.message_hash if auth_event else "")
            bind_ok, bind_reason = verify_binding(binding, tool, args, msg_hash)
            if not bind_ok:
                return GateResult(
                    allowed=False,
                    reason=bind_reason,
                    confidence="none",
                )

        # L6: record the now-permitted tool action so the rate limiter
        # accumulates state across calls (otherwise check() never trips).
        self._rate_limiter.record(action=tool, ctx=ctx, recipient=recipient)

        # Surface non-blocking anomaly signals (burst, novel recipient) rather
        # than discarding them.
        policy_result.anomalies = rate_result.anomalies
        return policy_result

    def check_kg_extraction(
        self,
        ctx: SecurityContext,
    ) -> SourceGateResult:
        """Check if KG extraction is allowed for this source (Layer 2)."""
        return check_extraction_allowed(
            ctx.source_type,
            ctx.source_id,
            source_trust=ctx.source_trust,
            source_gate_overrides=ctx.policy.source_gate_overrides,
            require_source_id_for=ctx.policy.require_source_id_for,
        )
