"""Prebuilt security-context profiles for common hardening flows."""

from __future__ import annotations

from vordur.security.types import (
    ContentType,
    PolicyConfig,
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)


def mcp_server_response(
    server_id: str,
    source_trust: TrustLevel = TrustLevel.UNTRUSTED,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SecurityContext:
    """Context for inbound content from an MCP server to a client app."""
    return SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id=server_id,
        source_trust=source_trust,
        principal_trust=principal_trust,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def mcp_client_request(
    client_id: str,
    source_trust: TrustLevel = TrustLevel.UNTRUSTED,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
    principal_id: str | None = None,
) -> SecurityContext:
    """Context for inbound content from an MCP client to a server app.

    ``principal_id`` attributes this content to an authenticated principal, so
    that a reply addressed back to them can skip it under no-copy. Pass it only
    when the transport authenticated the caller, and never derive it from
    ``client_id``: client_id is a descriptive label, not an identity.

    This is the only profile that takes one. The others describe content from
    servers, documents, the web, or internal storage -- none of which is a
    principal's own words -- so they cannot attribute a span to a principal
    and their spans are always subject to no-copy.
    """
    return SecurityContext(
        mode="server",
        source_type="mcp_client",
        source_id=client_id,
        source_trust=source_trust,
        principal_trust=principal_trust,
        principal_id=principal_id,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def untrusted_document(
    document_id: str,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SecurityContext:
    """Context for documents/PDF/attachments with unknown provenance."""
    return SecurityContext(
        mode="client",
        source_type="rag_content",
        source_id=document_id,
        source_trust=TrustLevel.UNTRUSTED,
        principal_trust=principal_trust,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def web_query_result(
    source_id: str = "web",
    content_type: ContentType = ContentType.HTML,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SecurityContext:
    """Context for web results/snippets/HTML returned by search providers."""
    return SecurityContext(
        mode="client",
        source_type="web_content",
        source_id=source_id,
        source_trust=TrustLevel.UNTRUSTED,
        principal_trust=principal_trust,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def internal_sensitive(
    source_id: str = "internal",
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SecurityContext:
    """Context for trusted but sensitive internal content (API keys, PII, etc.)."""
    return SecurityContext(
        mode="client",
        source_type="internal",
        source_id=source_id,
        source_trust=TrustLevel.TRUSTED,
        principal_trust=principal_trust,
        sensitivity=SensitivityLevel.SENSITIVE,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )
