"""Layer 3: Source gate — KG extraction trust-level filtering.

Determines whether content from a given source is eligible for
KG extraction, and whether extracted triples should be quarantined.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from guardllm.security.types import TrustLevel


class ExtractionPolicy(Enum):
    ALLOW = "allow"              # Extract normally, no quarantine
    QUARANTINE = "quarantine"    # Extract but quarantine all triples
    BLOCK = "block"              # Do not extract


@dataclass(frozen=True)
class SourceGateResult:
    policy: ExtractionPolicy
    reason: str
    source_origin: str           # Provenance tag for kg_assertions


# Source-type to policy mapping (spec Part 4 table)
_SOURCE_POLICY = {
    "user_input":           ExtractionPolicy.ALLOW,
    "assistant_response":   ExtractionPolicy.ALLOW,
    "cli":                  ExtractionPolicy.ALLOW,
    "email_content":        ExtractionPolicy.BLOCK,
    "calendar_content":     ExtractionPolicy.BLOCK,
    "web_content":          ExtractionPolicy.BLOCK,
    "rag_content":          ExtractionPolicy.BLOCK,
    "tool_output":          ExtractionPolicy.BLOCK,
    "mcp_client":           ExtractionPolicy.QUARANTINE,
    # user_indexed_email: user explicitly asked to index email content
    "user_indexed_email":   ExtractionPolicy.QUARANTINE,
    "user_indexed_web":     ExtractionPolicy.QUARANTINE,
    # web_synthesis: muse-mode responses shaped by untrusted web sources
    "web_synthesis":        ExtractionPolicy.QUARANTINE,
}


def check_extraction_allowed(
    source_type: str,
    source_id: str = "",
) -> SourceGateResult:
    """Check whether KG extraction is allowed for this source.

    Args:
        source_type: One of the keys in _SOURCE_POLICY.
        source_id: Optional identifier (e.g., client_id, email sender).

    Returns:
        SourceGateResult with policy, reason, and provenance tag.
    """
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

    # BLOCK
    return SourceGateResult(
        policy=policy,
        reason=f"KG extraction blocked for source type '{source_type}'",
        source_origin=source_type,
    )
