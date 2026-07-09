"""Layer 5: Canary token generation and detection (Part 5).

Generates deterministic canary tokens embedded in system prompts.
If a canary appears in outbound content, the system prompt has been
exfiltrated.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from guardllm.security.normalization import (
    deobfuscate_separated,
    normalize_for_overlap,
)

# Default secret:
# - use EPISODIC_CANARY_SECRET when configured
# - otherwise generate a process-local random secret
_ENV_SECRET = os.environ.get("EPISODIC_CANARY_SECRET")
_DEFAULT_SECRET = _ENV_SECRET.encode("utf-8") if _ENV_SECRET else secrets.token_bytes(32)


def generate_canary(session_id: str, secret: bytes = _DEFAULT_SECRET) -> str:
    """Generate a deterministic canary token for a session.

    Uses HMAC-SHA256 of the session_id with a server secret. The token
    is a 16-char hex string prefixed with ``CANARY-``.

    Args:
        session_id: Unique session identifier.
        secret: Server secret for HMAC. Override in production.

    Returns:
        Canary token string, e.g. ``CANARY-a1b2c3d4e5f6g7h8``.
    """
    mac = hmac.new(secret, session_id.encode(), hashlib.sha256)
    return f"CANARY-{mac.hexdigest()[:16]}"


def _canonicalize(s: str) -> str:
    """Canonicalize for canary matching: lowercase, drop invisibles and
    any separators so a token split by spaces/hyphens/zero-width chars or
    re-cased still matches (e.g. ``CANARY-A1B2 C3D4`` -> ``canarya1b2c3d4``)."""
    return deobfuscate_separated(normalize_for_overlap(s))


def detect_canary(text: str, expected: str) -> bool:
    """Check if text contains the expected canary token.

    Matching is done on a canonicalized form of both sides so that
    case changes, inserted whitespace/hyphens, or zero-width characters
    cannot hide an exfiltrated token.

    Args:
        text: Content to scan (e.g. outbound email body).
        expected: The canary token generated for this session.

    Returns:
        True if the canary is found (system prompt exfiltration detected).
    """
    canon_expected = _canonicalize(expected)
    if not canon_expected:
        return False
    return canon_expected in _canonicalize(text)
