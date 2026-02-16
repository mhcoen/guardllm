"""Prebuilt security-context profiles for common hardening flows."""

from __future__ import annotations

from guardllm.security.types import (
    ContentType,
    PolicyConfig,
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)


def mcp_server_response(
    server_id: str,
    trust_level: TrustLevel = TrustLevel.UNTRUSTED,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
) -> SecurityContext:
    """Context for inbound content from an MCP server to a client app."""
    return SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id=server_id,
        trust_level=trust_level,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def mcp_client_request(
    client_id: str,
    trust_level: TrustLevel = TrustLevel.UNTRUSTED,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
) -> SecurityContext:
    """Context for inbound content from an MCP client to a server app."""
    return SecurityContext(
        mode="server",
        source_type="mcp_client",
        source_id=client_id,
        trust_level=trust_level,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def untrusted_document(
    document_id: str,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
) -> SecurityContext:
    """Context for documents/PDF/attachments with unknown provenance."""
    return SecurityContext(
        mode="client",
        source_type="rag_content",
        source_id=document_id,
        trust_level=TrustLevel.UNTRUSTED,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def web_query_result(
    source_id: str = "web",
    content_type: ContentType = ContentType.HTML,
    policy: PolicyConfig | None = None,
) -> SecurityContext:
    """Context for web results/snippets/HTML returned by search providers."""
    return SecurityContext(
        mode="client",
        source_type="web_content",
        source_id=source_id,
        trust_level=TrustLevel.UNTRUSTED,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def internal_sensitive(
    source_id: str = "internal",
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
) -> SecurityContext:
    """Context for trusted but sensitive internal content (API keys, PII, etc.)."""
    return SecurityContext(
        mode="client",
        source_type="internal",
        source_id=source_id,
        trust_level=TrustLevel.TRUSTED,
        sensitivity=SensitivityLevel.SENSITIVE,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )
