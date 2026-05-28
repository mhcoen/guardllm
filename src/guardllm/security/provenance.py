"""Part 8: Provenance tracking and no-copy enforcement.

Tracks the origin of content through the pipeline using ProvenancedSpan
objects. Prevents untrusted content from being copied into outbound
messages without explicit user authorization.
"""

from __future__ import annotations

from dataclasses import dataclass

from guardllm.security.normalization import (
    compute_lcs_length,
    compute_ngram_overlap,
    deobfuscate_reversed,
    deobfuscate_spelled,
    normalize_for_overlap,
)
from guardllm.security.types import SensitivityLevel, TrustLevel


@dataclass
class ProvenancedSpan:
    """A span of text with provenance tracking.

    Carries the origin of content through the pipeline so that
    outbound DLP and no-copy enforcement can determine whether
    content came from an untrusted source.
    """

    text: str
    source_type: str  # "mcp_server", "mcp_client", "cli_user", "assistant"
    source_id: str  # Specific source identifier
    source_trust: TrustLevel = TrustLevel.UNTRUSTED
    sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC
    topic_of_origin: str | None = None  # For cross-topic leak detection


class ProvenanceTracker:
    """Tracks provenance spans and enforces no-copy policy.

    See spec Part 8 for full requirements:
    - Tag all content with source provenance
    - Block outbound content containing untrusted spans
    - Last-mile guard: mechanical overlap check
    - Exception for explicit quoting/forwarding directives
    """

    def __init__(self) -> None:
        self._spans: list[ProvenancedSpan] = []

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
        contaminated: bool = False,
    ) -> tuple[bool, str]:
        """Check if outbound content violates no-copy policy.

        Returns (allowed, reason).
        """
        if has_quoting_directive:
            return (True, "quoting directive")

        # Select spans to check: always untrusted, plus sensitive when contaminated
        check_spans: list[tuple[ProvenancedSpan, str]] = [
            (s, "untrusted") for s in self._spans if s.source_trust == TrustLevel.UNTRUSTED
        ]
        if contaminated:
            check_spans.extend(
                (s, "sensitive") for s in self._spans if s.sensitivity == SensitivityLevel.SENSITIVE
            )

        if not check_spans:
            return (True, "clean")

        normalized_content = normalize_for_overlap(content)

        # Build deobfuscated variants for overlap checks
        content_variants = [normalized_content]
        reversed_norm = normalize_for_overlap(deobfuscate_reversed(content))
        if reversed_norm != normalized_content:
            content_variants.append(reversed_norm)
        spelled_norm = normalize_for_overlap(deobfuscate_spelled(content))
        if spelled_norm != normalized_content:
            content_variants.append(spelled_norm)

        for variant in content_variants:
            deob = " (deobfuscated)" if variant is not normalized_content else ""
            for span, label in check_spans:
                normalized_span = normalize_for_overlap(span.text)
                if not normalized_span:
                    continue

                # LCS check: configurable (default >= 50 chars) is a block
                lcs_len = compute_lcs_length(variant, normalized_span)
                if lcs_len >= lcs_threshold:
                    return (
                        False,
                        f"Verbatim overlap ({lcs_len} chars){deob} with {label} "
                        f"content from {span.source_type}:{span.source_id}",
                    )

                # N-gram overlap check: configurable (default >= 30%) is a block
                overlap = compute_ngram_overlap(variant, normalized_span, n=5)
                if overlap >= ngram_threshold:
                    return (
                        False,
                        f"N-gram overlap ({overlap:.0%}){deob} with {label} "
                        f"content from {span.source_type}:{span.source_id}",
                    )

        return (True, "clean")
