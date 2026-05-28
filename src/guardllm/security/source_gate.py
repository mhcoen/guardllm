"""Layer 2: Source gate -- KG extraction filtering.

Determines whether content from a given source is eligible for
KG extraction, and whether extracted triples should be quarantined.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from guardllm.security.types import ExtractionPolicy

if TYPE_CHECKING:
    from guardllm.security.types import TrustLevel

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SourceGateResult:
    policy: ExtractionPolicy
    reason: str
    source_origin: str  # Provenance tag for kg_assertions


# Source-type to policy mapping (spec Part 4 table)
_SOURCE_POLICY = {
    "user_input": ExtractionPolicy.ALLOW,
    "assistant_response": ExtractionPolicy.ALLOW,
    "cli": ExtractionPolicy.ALLOW,
    "email_content": ExtractionPolicy.BLOCK,
    "calendar_content": ExtractionPolicy.BLOCK,
    "web_content": ExtractionPolicy.BLOCK,
    "rag_content": ExtractionPolicy.BLOCK,
    "tool_output": ExtractionPolicy.BLOCK,
    "mcp_client": ExtractionPolicy.QUARANTINE,
    # user_indexed_email: user explicitly asked to index email content
    "user_indexed_email": ExtractionPolicy.QUARANTINE,
    "user_indexed_web": ExtractionPolicy.QUARANTINE,
    # web_synthesis: muse-mode responses shaped by untrusted web sources
    "web_synthesis": ExtractionPolicy.QUARANTINE,
}


def check_extraction_allowed(
    source_type: str,
    source_id: str = "",
    *,
    source_trust: TrustLevel | None = None,
    source_gate_overrides: dict[Any, ExtractionPolicy] | None = None,
    require_source_id_for: frozenset[str] = frozenset(),
) -> SourceGateResult:
    """Check whether KG extraction is allowed for this source.

    Args:
        source_type: One of the keys in _SOURCE_POLICY.
        source_id: Optional identifier (e.g., client_id, email sender).
        source_trust: Optional source trust level for override lookup.
        source_gate_overrides: Optional dict keyed by (source_type, TrustLevel)
            that overrides _SOURCE_POLICY. Falls back to _SOURCE_POLICY if no
            override matches.
        require_source_id_for: Source types that require non-empty source_id.

    Returns:
        SourceGateResult with policy, reason, and provenance tag.
    """
    # Log warning for empty source_id on common source types
    if not source_id and source_type in (
        "mcp_server",
        "mcp_client",
        "web_content",
        "email_content",
    ):
        logger.warning(
            "source_id missing for source_type=%s; provenance origin will "
            "collapse to source_type, rate limit session may be shared",
            source_type,
        )

    # Enforce require_source_id_for policy
    if source_type in require_source_id_for and not source_id:
        return SourceGateResult(
            policy=ExtractionPolicy.BLOCK,
            reason=f"source_id required for source_type={source_type}",
            source_origin=source_type,
        )

    # Check policy overrides first
    policy: ExtractionPolicy | None = None
    if source_gate_overrides and source_trust is not None:
        policy = source_gate_overrides.get((source_type, source_trust))

    # Fall back to static policy table; unknown source types default to BLOCK
    if policy is None:
        policy = _SOURCE_POLICY.get(source_type, ExtractionPolicy.BLOCK)

    if policy == ExtractionPolicy.ALLOW:
        origin = "cli" if source_type in ("user_input", "cli") else source_type
        return SourceGateResult(
            policy=policy,
            reason=f"Source type '{source_type}' is trusted",
            source_origin=origin,
        )

    if policy == ExtractionPolicy.QUARANTINE:
        origin = f"mcp:{source_id}" if source_id else source_type
        return SourceGateResult(
            policy=policy,
            reason=f"Source type '{source_type}' requires quarantine",
            source_origin=origin,
        )

    # BLOCK (explicit default)
    return SourceGateResult(
        policy=ExtractionPolicy.BLOCK,
        reason=f"KG extraction blocked for source type '{source_type}'",
        source_origin=source_type,
    )
