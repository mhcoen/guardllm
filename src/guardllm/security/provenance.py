"""Part 8: Provenance tracking and no-copy enforcement.

Tracks the origin of content through the pipeline using ProvenancedSpan
objects. Prevents untrusted content from being copied into outbound
messages without explicit user authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from guardllm.security.normalization import (
    compute_lcs_length,
    compute_ngram_overlap,
    normalize_for_overlap,
)


@dataclass
class ProvenancedSpan:
    """A span of text with provenance tracking.

    Carries the origin of content through the pipeline so that
    outbound DLP and no-copy enforcement can determine whether
    content came from an untrusted source.
    """

    text: str
    source_type: str          # "mcp_server", "mcp_client", "cli_user", "assistant"
    source_id: str            # Specific source identifier
    trust_level: str          # "trusted", "semi_trusted", "untrusted"
    topic_of_origin: Optional[str] = None  # For cross-topic leak detection


class ProvenanceTracker:
    """Tracks provenance spans and enforces no-copy policy.

    See spec Part 8 for full requirements:
    - Tag all content with source provenance
    - Block outbound content containing untrusted spans
    - Last-mile guard: mechanical overlap check
    - Exception for explicit quoting/forwarding directives
    """

    def __init__(self) -> None:
        self._spans: List[ProvenancedSpan] = []

    def add_span(self, span: ProvenancedSpan) -> None:
        """Register a provenance span."""
        self._spans.append(span)

    def check_outbound(
        self,
        content: str,
        has_quoting_directive: bool = False,
        *,
        lcs_threshold: int = 50,
        ngram_threshold: float = 0.30,
    ) -> tuple[bool, str]:
        """Check if outbound content violates no-copy policy.

        Returns (allowed, reason).
        """
        if has_quoting_directive:
            return (True, "quoting directive")

        untrusted = [s for s in self._spans if s.trust_level == "untrusted"]
        if not untrusted:
            return (True, "clean")

        normalized_content = normalize_for_overlap(content)

        for span in untrusted:
            normalized_span = normalize_for_overlap(span.text)
            if not normalized_span:
                continue

            # LCS check: configurable (default >= 50 chars) is a block
            lcs_len = compute_lcs_length(normalized_content, normalized_span)
            if lcs_len >= lcs_threshold:
                return (
                    False,
                    f"Verbatim overlap ({lcs_len} chars) with untrusted "
                    f"content from {span.source_type}:{span.source_id}",
                )

            # N-gram overlap check: configurable (default >= 30%) is a block
            overlap = compute_ngram_overlap(normalized_content, normalized_span, n=5)
            if overlap >= ngram_threshold:
                return (
                    False,
                    f"N-gram overlap ({overlap:.0%}) with untrusted "
                    f"content from {span.source_type}:{span.source_id}",
                )

        return (True, "clean")
