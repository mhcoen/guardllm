"""Part 7: Outbound DLP (Data Loss Prevention).

Scans outbound content against recently ingested untrusted content
to detect exfiltration attempts. Checks verbatim overlap, n-gram
overlap, and secret patterns.
"""

from __future__ import annotations

import math
import re
from collections import deque
from typing import Deque, List

from guardllm.security.normalization import (
    compute_lcs_length,
    compute_ngram_overlap,
    normalize_for_overlap,
)
from guardllm.security.types import OutboundResult, SecurityContext

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: List[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"sk-proj-[A-Za-z0-9\-_]{20,}"), "OpenAI project key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"ya29\.[A-Za-z0-9_\-]{20,}"), "Google OAuth token"),
    (re.compile(r"gho_[A-Za-z0-9]{36,}"), "GitHub OAuth token"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "GitHub personal access token"),
    (re.compile(r"ghs_[A-Za-z0-9]{36,}"), "GitHub app token"),
    (re.compile(r"ghr_[A-Za-z0-9]{36,}"), "GitHub refresh token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ), "Private key header"),
]

_ENTROPY_THRESHOLD = 4.5
_ENTROPY_MIN_LENGTH = 20


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values()
    )


def _scan_secrets(text: str) -> List[str]:
    """Scan text for known secret patterns and high-entropy strings."""
    found: List[str] = []
    for pattern, label in _SECRET_PATTERNS:
        if pattern.search(text):
            found.append(label)

    # High-entropy token detection: look for long hex/base64-like tokens
    for token in re.findall(r"[A-Za-z0-9+/\-_]{20,}", text):
        if len(token) >= _ENTROPY_MIN_LENGTH:
            entropy = _shannon_entropy(token)
            if entropy >= _ENTROPY_THRESHOLD:
                label = f"High-entropy token ({entropy:.1f} bits)"
                if label not in found:
                    found.append(label)
    return found


# ---------------------------------------------------------------------------
# OutboundDLP
# ---------------------------------------------------------------------------

class OutboundDLP:
    """Outbound content exfiltration detector.

    Before any outbound action executes, scans content against recently
    ingested untrusted content. Checks:
    - Secret patterns (always, even with quoting directive)
    - Verbatim overlap (>= 100 chars)
    - N-gram overlap (>= 40% 5-gram overlap)
    """

    def __init__(self, buffer_max: int = 50) -> None:
        self._buffer: Deque[str] = deque(maxlen=buffer_max)

    def ingest_untrusted(self, content: str) -> None:
        """Normalize and buffer untrusted content for later DLP checks."""
        normalized = normalize_for_overlap(content)
        if normalized:
            self._buffer.append(normalized)

    def check(
        self,
        content: str,
        ctx: SecurityContext,
        has_quoting_directive: bool = False,
    ) -> OutboundResult:
        """Check outbound content for exfiltration indicators.

        Args:
            content: Outbound content to check.
            ctx: Security context.
            has_quoting_directive: True if user explicitly directed quoting.

        Returns:
            OutboundResult with allowed=True if content passes DLP.
        """
        # Step 1: Secret scan (always runs, even with quoting directive)
        secrets = _scan_secrets(content)
        if secrets:
            return OutboundResult(
                allowed=False,
                reason=f"Secret pattern detected: {', '.join(secrets)}",
                secrets_found=secrets,
            )

        # With quoting directive, skip overlap checks
        if has_quoting_directive:
            return OutboundResult(allowed=True, reason="clean (quoting)")

        normalized_content = normalize_for_overlap(content)

        for buffered in self._buffer:
            # Step 2: Verbatim overlap (LCS >= 100 chars)
            lcs_len = compute_lcs_length(normalized_content, buffered)
            if lcs_len >= 100:
                return OutboundResult(
                    allowed=False,
                    reason=f"Verbatim overlap ({lcs_len} chars) with "
                           f"ingested untrusted content",
                    overlap_pct=0.0,
                )

            # Step 3: N-gram overlap (>= 40%)
            overlap = compute_ngram_overlap(normalized_content, buffered, n=5)
            if overlap >= 0.40:
                return OutboundResult(
                    allowed=False,
                    reason=f"N-gram overlap ({overlap:.0%}) with "
                           f"ingested untrusted content",
                    overlap_pct=overlap,
                )

        return OutboundResult(allowed=True, reason="clean")
