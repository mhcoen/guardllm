"""Stable high-level API for integrating guardllm into applications."""

from __future__ import annotations

import hashlib
import time

from guardllm.security import profiles
from guardllm.security.action_gate import ActionGate, ActionProposal
from guardllm.security.audit import AuditLogger
from guardllm.security.error_sanitizer import sanitize_error
from guardllm.security.pipeline import SecurityPipeline
from guardllm.security.policy_engine import DESTRUCTIVE_TOOLS
from guardllm.security.request_binding import create_binding
from guardllm.security.types import (
    AuditEvent,
    AuthorizationEvent,
    Binding,
    ContentType,
    GateResult,
    OutboundResult,
    PolicyConfig,
    ProcessedContent,
    SecurityContext,
    TrustLevel,
)
from guardllm.security.validation import ValidationResult, validate_arguments


class Guard:
    """High-level facade for guardllm security workflows."""

    def __init__(
        self,
        *,
        canary_session_id: str | None = None,
        audit_logger: object | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
    ) -> None:
        self._pipeline = SecurityPipeline(
            audit_logger=audit_logger,
            canary_session_id=canary_session_id,
            principal_trust=principal_trust,
        )
        self._action_gate = ActionGate()
        self._audit_logger = audit_logger

    @staticmethod
    def hash_message(message: str) -> str:
        """Create a stable SHA-256 hash for a user message."""
        return hashlib.sha256(message.encode()).hexdigest()

    @staticmethod
    def authorize(
        action: str,
        scope: dict,
        *,
        source: str = "api",
        user_message: str | None = None,
        message_hash: str | None = None,
        session_id: str | None = None,
        timestamp: float | None = None,
    ) -> AuthorizationEvent:
        """Build an authorization event for a tool call."""
        msg_hash = message_hash
        if msg_hash is None and user_message is not None:
            msg_hash = Guard.hash_message(user_message)
        if not msg_hash:
            raise ValueError("Provide either user_message or message_hash")
        return AuthorizationEvent(
            action=action,
            scope=scope,
            message_hash=msg_hash,
            timestamp=time.time() if timestamp is None else timestamp,
            source=source,
            session_id=session_id,
        )

    @staticmethod
    def bind_request(
        tool: str,
        args: dict,
        *,
        authorization: AuthorizationEvent | None = None,
        user_message: str | None = None,
        message_hash: str | None = None,
        ttl: float = 120.0,
    ) -> Binding:
        """Create a request binding to protect against replay."""
        msg_hash = message_hash
        if msg_hash is None and user_message is not None:
            msg_hash = Guard.hash_message(user_message)
        return create_binding(
            tool=tool,
            args=args,
            auth_event=authorization,
            message_hash=msg_hash,
            ttl=ttl,
        )

    @staticmethod
    def context_mcp_server(
        server_id: str,
        *,
        source_trust: TrustLevel = TrustLevel.UNTRUSTED,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: PolicyConfig | None = None,
    ) -> SecurityContext:
        return profiles.mcp_server_response(
            server_id=server_id,
            source_trust=source_trust,
            content_type=content_type,
            policy=policy,
        )

    @staticmethod
    def context_mcp_client(
        client_id: str,
        *,
        source_trust: TrustLevel = TrustLevel.UNTRUSTED,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: PolicyConfig | None = None,
    ) -> SecurityContext:
        return profiles.mcp_client_request(
            client_id=client_id,
            source_trust=source_trust,
            content_type=content_type,
            policy=policy,
        )

    @staticmethod
    def context_document(
        document_id: str,
        *,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: PolicyConfig | None = None,
    ) -> SecurityContext:
        return profiles.untrusted_document(
            document_id=document_id,
            content_type=content_type,
            policy=policy,
        )

    @staticmethod
    def context_web(
        *,
        source_id: str = "web",
        content_type: ContentType = ContentType.HTML,
        policy: PolicyConfig | None = None,
    ) -> SecurityContext:
        return profiles.web_query_result(
            source_id=source_id,
            content_type=content_type,
            policy=policy,
        )

    @staticmethod
    def context_internal_sensitive(
        *,
        source_id: str = "internal",
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: PolicyConfig | None = None,
    ) -> SecurityContext:
        return profiles.internal_sensitive(
            source_id=source_id,
            content_type=content_type,
            policy=policy,
        )

    def reset(self) -> None:
        """Reset pipeline and action gate for a new session."""
        self._pipeline.reset()
        self._action_gate = ActionGate()

    def process_inbound(self, content: str, context: SecurityContext) -> ProcessedContent:
        """Sanitize and isolate inbound content."""
        result = self._pipeline.process_inbound(content, context)
        self._audit(
            AuditEvent(
                event_type="inbound_processed",
                action_summary="Processed inbound content",
                warnings=result.warnings,
                session_id=context.source_id,
            )
        )
        return result

    def process_inbound_compound(
        self,
        spans: list[tuple[str, SecurityContext]],
        compound_id: str | None = None,
    ) -> list[ProcessedContent]:
        """Process multiple spans of a compound message with different provenance.

        Each span is processed independently through the existing inbound
        pipeline.  Session state (contamination, DLP buffers, provenance)
        accumulates across all spans.  If any span has
        source_trust == UNTRUSTED, the session contamination flag is set,
        widening downstream egress checks for the entire session.

        Args:
            spans: (content, SecurityContext) pairs, one per provenance span.
            compound_id: Links spans for provenance and audit.  Generated
                from a hash of all span contents when None.

        Returns:
            List of ProcessedContent, one per input span, in order.
        """
        if compound_id is None:
            h = hashlib.sha256()
            for content, _ in spans:
                h.update(content.encode())
            compound_id = h.hexdigest()[:16]

        results: list[ProcessedContent] = []
        for content, ctx in spans:
            result = self.process_inbound(content, ctx)
            results.append(result)

        self._audit(
            AuditEvent(
                event_type="compound_inbound_processed",
                action_summary=f"Processed {len(spans)} spans",
                request_id=compound_id,
                warnings=[w for r in results for w in r.warnings] or None,
            )
        )
        return results

    def check_tool_call(
        self,
        tool: str,
        args: dict,
        context: SecurityContext,
        *,
        authorization: AuthorizationEvent | None = None,
        binding: Binding | None = None,
        user_message: str | None = None,
        message_hash: str | None = None,
    ) -> GateResult:
        """Run policy/rate-limit/binding checks for a tool call."""
        msg_hash = message_hash
        if msg_hash is None and user_message is not None:
            msg_hash = self.hash_message(user_message)
        result = self._pipeline.check_tool_execution(
            tool=tool,
            args=args,
            ctx=context,
            auth_event=authorization,
            binding=binding,
            message_hash=msg_hash,
        )
        self._audit(
            AuditEvent(
                event_type="tool_call_checked",
                tool_name=tool,
                action_summary=result.reason,
                firewall_result={"allowed": result.allowed, "confidence": result.confidence},
                session_id=context.source_id,
            )
        )
        return result

    def check_outbound(
        self,
        content: str,
        context: SecurityContext,
        *,
        has_quoting_directive: bool = False,
    ) -> OutboundResult:
        """Run outbound DLP/provenance/rate checks."""
        result = self._pipeline.check_outbound(
            content=content,
            ctx=context,
            has_quoting_directive=has_quoting_directive,
        )
        self._audit(
            AuditEvent(
                event_type="outbound_checked",
                action_summary=result.reason,
                dlp_result={
                    "allowed": result.allowed,
                    "overlap_pct": result.overlap_pct,
                    "secrets_found": result.secrets_found,
                },
                provenance_result={"blocked": result.provenance_blocked},
                session_id=context.source_id,
            )
        )
        return result

    def validate_tool_args(self, tool: str, args: dict) -> ValidationResult:
        """Validate tool arguments before security checks/dispatch."""
        result = validate_arguments(tool, args)
        self._audit(
            AuditEvent(
                event_type="tool_args_validated",
                tool_name=tool,
                action_summary="validation_passed" if result.valid else "validation_failed",
                warnings=result.errors if not result.valid else None,
            )
        )
        return result

    def sanitize_exception(self, exception: Exception, retry_after: int | None = None) -> dict:
        """Return a sanitized outward-safe error payload."""
        result = sanitize_error(exception, retry_after=retry_after)
        self._audit(
            AuditEvent(
                event_type="error_sanitized",
                action_summary=result.get("error", {}).get("code"),
            )
        )
        return result

    async def confirm_action(
        self,
        tool: str,
        args: dict,
        context: SecurityContext,
        *,
        summary: str,
        proposal_context: dict | None = None,
        heightened_scrutiny: bool = False,
        context_has_web_derived: bool = False,
    ) -> bool:
        """Run L12 action-gate confirmation for a proposed operation."""
        proposal = ActionProposal(
            tool_name=tool,
            args=args,
            summary=summary,
            context=proposal_context or {},
            heightened_scrutiny=heightened_scrutiny,
        )
        allowed = await self._action_gate.confirm(
            proposal,
            context,
            context_has_web_derived=context_has_web_derived,
        )
        self._audit(
            AuditEvent(
                event_type="action_gate_confirmed",
                tool_name=tool,
                user_confirmed=allowed,
                action_summary=summary,
                session_id=context.source_id,
            )
        )
        return allowed

    async def guard_tool_call(
        self,
        tool: str,
        args: dict,
        context: SecurityContext,
        *,
        summary: str | None = None,
        proposal_context: dict | None = None,
        authorization: AuthorizationEvent | None = None,
        binding: Binding | None = None,
        user_message: str | None = None,
        message_hash: str | None = None,
        context_has_web_derived: bool = False,
        require_confirmation: bool = False,
        heightened_scrutiny: bool = False,
        validate: bool = True,
    ) -> GateResult:
        """Full tool-call guard flow: validation -> policy -> optional confirmation."""
        # L12: auto-require confirmation for destructive tools when policy says so
        if context.policy.auto_confirm_destructive and tool in DESTRUCTIVE_TOOLS:
            require_confirmation = True

        # INV-MUSE-7 / confirm_all_below: escalate to enhanced confirmation when
        # the policy demands it for web-derived context or a low-trust principal.
        # Without this the escalation gate never fires through the guard flow.
        if not require_confirmation:
            escalation_proposal = ActionProposal(
                tool_name=tool,
                args=args,
                summary=summary or f"Execute tool {tool}",
                context=proposal_context or {},
                heightened_scrutiny=heightened_scrutiny,
            )
            if self._action_gate.requires_confirmation(
                escalation_proposal,
                context,
                context_has_web_derived=context_has_web_derived,
            ):
                require_confirmation = True

        if validate:
            validation = self.validate_tool_args(tool, args)
            if not validation.valid:
                return GateResult(
                    allowed=False,
                    reason=f"Validation failed: {validation.errors[0]}",
                    confidence="none",
                )

        gate = self.check_tool_call(
            tool=tool,
            args=args,
            context=context,
            authorization=authorization,
            binding=binding,
            user_message=user_message,
            message_hash=message_hash,
        )
        if not gate.allowed:
            return gate

        if require_confirmation:
            approved = await self.confirm_action(
                tool=tool,
                args=args,
                context=context,
                summary=summary or f"Execute tool {tool}",
                proposal_context=proposal_context,
                heightened_scrutiny=heightened_scrutiny,
                context_has_web_derived=context_has_web_derived,
            )
            if not approved:
                return GateResult(
                    allowed=False,
                    reason="User denied confirmation",
                    confidence="none",
                )
            # G6: verify args match the confirmed commitment
            ok, reason = self._action_gate.verify_commitment(tool, args)
            if not ok:
                return GateResult(
                    allowed=False,
                    reason=f"Commitment verification failed: {reason}",
                    confidence="none",
                )

        return gate

    def _audit(self, event: AuditEvent) -> None:
        if self._audit_logger is None:
            return
        if isinstance(self._audit_logger, AuditLogger):
            self._audit_logger.log(event)
            return
        if hasattr(self._audit_logger, "log"):
            self._audit_logger.log(event)
