"""Stable high-level API for integrating GuardLLM into applications."""

from __future__ import annotations

import hashlib
import time
from typing import Optional

from guardllm.security import profiles
from guardllm.security.pipeline import SecurityPipeline
from guardllm.security.request_binding import create_binding
from guardllm.security.types import (
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


class Guard:
    """High-level facade for GuardLLM security workflows."""

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
        return self._pipeline.process_inbound(content, context)

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
        return self._pipeline.check_tool_execution(
            tool=tool,
            args=args,
            ctx=context,
            auth_event=authorization,
            binding=binding,
            message_hash=msg_hash,
        )

    def check_outbound(
        self,
        content: str,
        context: SecurityContext,
        *,
        has_quoting_directive: bool = False,
    ) -> OutboundResult:
        """Run outbound DLP/provenance/rate checks."""
        return self._pipeline.check_outbound(
            content=content,
            ctx=context,
            has_quoting_directive=has_quoting_directive,
        )
