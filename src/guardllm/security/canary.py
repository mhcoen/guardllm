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


def detect_canary(text: str, expected: str) -> bool:
    """Check if text contains the expected canary token.

    Args:
        text: Content to scan (e.g. outbound email body).
        expected: The canary token generated for this session.

    Returns:
        True if the canary is found (system prompt exfiltration detected).
    """
    return expected in text
