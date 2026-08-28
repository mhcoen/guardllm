"""Tests for MCP security canary token generation and detection (spec tests 63-64).

Covers:
- Canary token in text -> detected (True)
- Canary token absent -> not detected (False)
- Canary is deterministic (same session_id -> same token)
- Different session_id -> different token
"""

import pytest

from vordur.security.canary import detect_canary, generate_canary


class TestCanaryGeneration:
    """Tests for canary token generation."""

    def test_deterministic_same_session_id(self):
        """Same session_id produces the same canary token."""
        token1 = generate_canary("session-42")
        token2 = generate_canary("session-42")
        assert token1 == token2

    def test_different_session_id_different_token(self):
        """Different session_ids produce different tokens."""
        token1 = generate_canary("session-1")
        token2 = generate_canary("session-2")
        assert token1 != token2

    def test_token_format(self):
        """Canary token starts with CANARY- prefix."""
        token = generate_canary("session-x")
        assert token.startswith("CANARY-")

    def test_token_hex_suffix(self):
        """Canary token suffix is 16 hex characters."""
        token = generate_canary("session-x")
        suffix = token[len("CANARY-") :]
        assert len(suffix) == 16
        assert all(c in "0123456789abcdef" for c in suffix)

    def test_custom_secret_changes_token(self):
        """Different secret produces different token for same session_id."""
        token1 = generate_canary("session-1", secret=b"secret-a")
        token2 = generate_canary("session-1", secret=b"secret-b")
        assert token1 != token2

    def test_custom_secret_deterministic(self):
        """Same session_id + same secret -> same token."""
        secret = b"my-custom-secret"
        token1 = generate_canary("session-1", secret=secret)
        token2 = generate_canary("session-1", secret=secret)
        assert token1 == token2

    def test_empty_session_id(self):
        """Empty session_id still produces a valid token."""
        token = generate_canary("")
        assert token.startswith("CANARY-")
        assert len(token) == len("CANARY-") + 16


class TestCanaryDetection:
    """Tests for canary token detection in text."""

    def test_canary_detected_in_text(self):
        """Canary token present in text is detected."""
        token = generate_canary("session-42")
        text = f"Here is some content with the canary {token} embedded in it."
        assert detect_canary(text, token) is True

    def test_canary_at_start_of_text(self):
        """Canary at the start of text is detected."""
        token = generate_canary("session-42")
        text = f"{token} and then some more text"
        assert detect_canary(text, token) is True

    def test_canary_at_end_of_text(self):
        """Canary at the end of text is detected."""
        token = generate_canary("session-42")
        text = f"Some text and then {token}"
        assert detect_canary(text, token) is True

    def test_canary_absent(self):
        """Text without canary returns False."""
        token = generate_canary("session-42")
        text = "This text does not contain any canary token at all."
        assert detect_canary(text, token) is False

    def test_wrong_canary_not_detected(self):
        """A different session's canary is not detected."""
        token_42 = generate_canary("session-42")
        token_99 = generate_canary("session-99")
        text = f"Content with {token_99}"
        assert detect_canary(text, token_42) is False

    def test_partial_canary_not_detected(self):
        """A partial canary token is not detected (substring match only)."""
        token = generate_canary("session-42")
        # Take only half the token
        partial = token[: len(token) // 2]
        text = f"Some text with partial {partial} but not the full token."
        assert detect_canary(text, token) is False

    def test_empty_text(self):
        """Empty text does not contain canary."""
        token = generate_canary("session-42")
        assert detect_canary("", token) is False

    def test_canary_surrounded_by_newlines(self):
        """Canary surrounded by newlines is still detected."""
        token = generate_canary("session-42")
        text = f"Line 1\n{token}\nLine 3"
        assert detect_canary(text, token) is True

    def test_multiple_canaries_in_text(self):
        """Multiple occurrences of the canary are still detected."""
        token = generate_canary("session-42")
        text = f"{token} middle text {token}"
        assert detect_canary(text, token) is True

    @pytest.mark.parametrize(
        "transform",
        [
            lambda token: token.upper(),
            lambda token: f"CaNaRy - {token[7:11]} {token[11:15]} {token[15:]}",
            lambda token: "\u200b".join(token),
            lambda token: token.replace("-", " / "),
        ],
        ids=["case", "chunk-separators", "zero-width", "slash-separator"],
    )
    def test_canonicalized_transformations_detected(self, transform):
        """Supported case and separator transformations retain attribution."""
        token = generate_canary("canonicalized-session", secret=b"fixed-test-secret")
        assert detect_canary(transform(token), token) is True


class TestCanaryIsolation:
    """Canary tokens are session-specific and secret-specific."""

    @pytest.mark.parametrize(
        "session_id",
        [
            "session-1",
            "session-2",
            "abc-def-ghi",
            "12345",
            "a" * 100,
        ],
    )
    def test_unique_per_session(self, session_id):
        """Each session_id produces a unique token."""
        token = generate_canary(session_id)
        other = generate_canary(session_id + "-other")
        assert token != other

    def test_many_sessions_all_unique(self):
        """100 different sessions produce 100 unique tokens."""
        tokens = {generate_canary(f"session-{i}") for i in range(100)}
        assert len(tokens) == 100
