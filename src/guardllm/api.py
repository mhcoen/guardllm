"""Stable high-level API for integrating guardllm into applications."""

from __future__ import annotations

import hashlib
import time
from typing import Optional

from guardllm.security import profiles
from guardllm.security.action_gate import ActionGate, ActionProposal
from guardllm.security.audit import AuditLogger
from guardllm.security.error_sanitizer import sanitize_error
from guardllm.security.pipeline import SecurityPipeline
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
        canary_session_id: Optional[str] = None,
        audit_logger: Optional[object] = None,
    ) -> None:
        self._pipeline = SecurityPipeline(
            audit_logger=audit_logger,
            canary_session_id=canary_session_id,
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
        user_message: Optional[str] = None,
        message_hash: Optional[str] = None,
        session_id: Optional[str] = None,
        timestamp: Optional[float] = None,
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
        authorization: Optional[AuthorizationEvent] = None,
        user_message: Optional[str] = None,
        message_hash: Optional[str] = None,
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
        trust_level: TrustLevel = TrustLevel.UNTRUSTED,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: Optional[PolicyConfig] = None,
    ) -> SecurityContext:
        return profiles.mcp_server_response(
            server_id=server_id,
            trust_level=trust_level,
            content_type=content_type,
            policy=policy,
        )

    @staticmethod
    def context_mcp_client(
        client_id: str,
        *,
        trust_level: TrustLevel = TrustLevel.UNTRUSTED,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: Optional[PolicyConfig] = None,
    ) -> SecurityContext:
        return profiles.mcp_client_request(
            client_id=client_id,
            trust_level=trust_level,
            content_type=content_type,
            policy=policy,
        )

    @staticmethod
    def context_document(
        document_id: str,
        *,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: Optional[PolicyConfig] = None,
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
        policy: Optional[PolicyConfig] = None,
    ) -> SecurityContext:
        return profiles.web_query_result(
            source_id=source_id,
            content_type=content_type,
            policy=policy,
        )

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

    def check_tool_call(
        self,
        tool: str,
        args: dict,
        context: SecurityContext,
        *,
        authorization: Optional[AuthorizationEvent] = None,
        binding: Optional[Binding] = None,
        user_message: Optional[str] = None,
        message_hash: Optional[str] = None,
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

    def sanitize_exception(self, exception: Exception, retry_after: Optional[int] = None) -> dict:
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
        proposal_context: Optional[dict] = None,
        heightened_scrutiny: bool = False,
        context_has_web_derived: bool = False,
    ) -> bool:
        """Run L2 action-gate confirmation for a proposed operation."""
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
        summary: Optional[str] = None,
        proposal_context: Optional[dict] = None,
        authorization: Optional[AuthorizationEvent] = None,
        binding: Optional[Binding] = None,
        user_message: Optional[str] = None,
        message_hash: Optional[str] = None,
        context_has_web_derived: bool = False,
        require_confirmation: bool = False,
        heightened_scrutiny: bool = False,
        validate: bool = True,
    ) -> GateResult:
        """Full tool-call guard flow: validation -> policy -> optional confirmation."""
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

        return gate

    def _audit(self, event: AuditEvent) -> None:
        if self._audit_logger is None:
            return
        if isinstance(self._audit_logger, AuditLogger):
            self._audit_logger.log(event)
            return
        if hasattr(self._audit_logger, "log"):
            self._audit_logger.log(event)
