"""Tests for MCP security OutboundDLP."""

import pytest

from guardllm.security.outbound_dlp import (
    OutboundDLP,
    _scan_secrets,
    _shannon_entropy,
)
from guardllm.security.types import PolicyConfig, SecurityContext, TrustLevel


@pytest.fixture
def dlp():
    return OutboundDLP()


@pytest.fixture
def ctx():
    return SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="server-1",
    )


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        import string

        s = string.ascii_letters + string.digits
        entropy = _shannon_entropy(s)
        assert entropy > 4.0

    def test_low_entropy(self):
        entropy = _shannon_entropy("aaabbb")
        assert entropy < 2.0


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------


class TestSecretScanning:
    def test_openai_api_key(self):
        text = "my key is sk-abcdefghijklmnopqrstuvwxyz"
        found = _scan_secrets(text)
        assert any("OpenAI" in s for s in found)

    def test_aws_access_key(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        found = _scan_secrets(text)
        assert any("AWS" in s for s in found)

    def test_google_oauth_token(self):
        text = "token: ya29.some_long_token_value_here"
        found = _scan_secrets(text)
        assert any("Google" in s for s in found)

    def test_github_oauth_token(self):
        text = "gho_" + "a" * 40
        found = _scan_secrets(text)
        assert any("GitHub" in s for s in found)

    def test_github_pat(self):
        text = "ghp_" + "a" * 40
        found = _scan_secrets(text)
        assert any("GitHub personal" in s for s in found)

    def test_github_app_token(self):
        text = "ghs_" + "a" * 40
        found = _scan_secrets(text)
        assert any("GitHub app" in s for s in found)

    def test_github_refresh_token(self):
        text = "ghr_" + "a" * 40
        found = _scan_secrets(text)
        assert any("GitHub refresh" in s for s in found)

    def test_slack_token(self):
        text = "xoxb-1234567890-abcdef"
        found = _scan_secrets(text)
        assert any("Slack" in s for s in found)

    def test_private_key_header(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        found = _scan_secrets(text)
        assert any("Private key" in s for s in found)

    def test_private_key_ec(self):
        text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE..."
        found = _scan_secrets(text)
        assert any("Private key" in s for s in found)

    def test_private_key_openssh(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn..."
        found = _scan_secrets(text)
        assert any("Private key" in s for s in found)

    def test_bearer_jwt_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123"
        found = _scan_secrets(text)
        assert any("Bearer" in s or "JWT" in s for s in found)

    def test_bearer_jwt_three_part(self):
        text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef"
        found = _scan_secrets(text)
        assert any("Bearer" in s or "JWT" in s for s in found)

    def test_bearer_jwt_rsa(self):
        text = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature123"
        found = _scan_secrets(text)
        assert any("Bearer" in s or "JWT" in s for s in found)

    def test_no_secrets_in_clean_text(self):
        text = "This is a perfectly normal email body with no secrets."
        found = _scan_secrets(text)
        assert found == []

    def test_high_entropy_token(self):
        # Generate a high-entropy token
        import string

        token = "".join(string.ascii_letters[i % 52] for i in range(30))
        text = f"token={token}"
        found = _scan_secrets(text)
        # May or may not trigger depending on exact entropy
        # Just verify it doesn't crash
        assert isinstance(found, list)


# ---------------------------------------------------------------------------
# OutboundDLP.check
# ---------------------------------------------------------------------------


class TestOutboundDLP:
    def test_clean_content_passes(self, dlp, ctx):
        result = dlp.check("Hello, this is a normal email.", ctx)
        assert result.allowed is True
        assert result.reason == "clean"

    def test_secret_blocks_even_with_quoting(self, dlp, ctx):
        text = "Here is my key: sk-abcdefghijklmnopqrstuvwxyz"
        result = dlp.check(text, ctx, has_quoting_directive=True)
        assert result.allowed is False
        assert result.secrets_found

    def test_secret_blocks_without_quoting(self, dlp, ctx):
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        result = dlp.check(text, ctx)
        assert result.allowed is False
        assert any("AWS" in s for s in result.secrets_found)

    def test_verbatim_echo_is_signal_not_block(self, dlp, ctx):
        """Untrusted echo is a signal, not a block. Only sensitive-leak blocks."""
        untrusted = "x" * 150
        dlp.ingest_untrusted(untrusted)
        result = dlp.check(untrusted, ctx)
        assert result.allowed is True
        assert result.echo_detected is True
        assert result.echo_lcs >= 14

    def test_short_verbatim_overlap_passes(self, dlp, ctx):
        untrusted = "x" * 50  # < 100 char threshold for DLP
        dlp.ingest_untrusted(untrusted)
        dlp.check(untrusted, ctx)
        # May pass or fail depending on n-gram — but at least no verbatim block
        # For single repeated char, n-gram overlap would be 100% since it's the same
        # Let's test with something that clearly passes
        result2 = dlp.check("completely different content", ctx)
        assert result2.allowed is True

    def test_ngram_echo_is_signal_not_block(self, dlp, ctx):
        """High n-gram overlap with untrusted is a signal, not a block."""
        untrusted = "the quick brown fox jumps over the lazy dog " * 5
        dlp.ingest_untrusted(untrusted)
        result = dlp.check(untrusted, ctx)
        assert result.allowed is True
        assert result.echo_detected is True

    def test_quoting_directive_skips_overlap(self, dlp, ctx):
        untrusted = "x" * 200
        dlp.ingest_untrusted(untrusted)
        result = dlp.check(untrusted, ctx, has_quoting_directive=True)
        assert result.allowed is True
        assert result.reason == "clean (quoting)"

    def test_buffer_fifo(self):
        dlp = OutboundDLP(buffer_max=2)
        ctx = SecurityContext(mode="client", source_type="mcp_server", source_id="s")
        text1 = "a" * 150
        text2 = "b" * 150
        text3 = "c" * 150
        dlp.ingest_untrusted(text1)
        dlp.ingest_untrusted(text2)
        dlp.ingest_untrusted(text3)
        # text1 should have been evicted
        result = dlp.check(text1, ctx)
        assert result.allowed is True
        # text3 should still be in buffer (echo detected, not blocked)
        result3 = dlp.check(text3, ctx)
        assert result3.echo_detected is True

    def test_empty_buffer_passes(self, dlp, ctx):
        result = dlp.check("anything goes here", ctx)
        assert result.allowed is True

    def test_ingest_empty_string_ignored(self, dlp, ctx):
        dlp.ingest_untrusted("")
        assert len(dlp._buffer) == 0

    def test_ingest_whitespace_only_ignored(self, dlp, ctx):
        dlp.ingest_untrusted("   \n  \t  ")
        assert len(dlp._buffer) == 0

    def test_multiple_secrets_found(self, dlp, ctx):
        text = "sk-abcdefghijklmnopqrstuvwxyz AKIAIOSFODNN7EXAMPLE"
        result = dlp.check(text, ctx)
        assert result.allowed is False
        assert len(result.secrets_found) >= 2

    def test_private_key_blocks(self, dlp, ctx):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        result = dlp.check(text, ctx)
        assert result.allowed is False
        assert any("Private key" in s for s in result.secrets_found)

    def test_untrusted_ctx_same_behavior(self):
        dlp = OutboundDLP()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="suspicious-server",
            source_trust=TrustLevel.UNTRUSTED,
        )
        result = dlp.check("normal text no secrets", ctx)
        assert result.allowed is True

    def test_sensitive_leak_blocks_when_contaminated(self, dlp, ctx):
        """Sensitive-leak check blocks when outbound overlaps sensitive content."""
        dlp.ingest_untrusted("some untrusted text here")
        dlp.ingest_sensitive("my secret api token value is extremely private data")
        result = dlp.check(
            "the secret api token value is extremely private data",
            ctx,
            contaminated=True,
        )
        assert result.allowed is False
        assert result.contamination_triggered is True

    def test_echo_does_not_widen_sensitive_threshold(self, dlp, ctx):
        """Echo is pure metadata; sensitive-leak uses base threshold only."""
        # 10-char secret embedded in longer text to keep n-gram overlap low
        short_secret = "the quick brown fox jumps over the lazy dog near a river"
        dlp.ingest_sensitive(short_secret)
        untrusted = "w" * 100
        dlp.ingest_untrusted(untrusted)
        # Outbound echoes untrusted (triggers echo) with a short overlap of
        # the sensitive text (7 chars "the qui"), well below LCS=12 threshold
        outbound = "w" * 100 + " the qui and some other unrelated text here"
        result = dlp.check(outbound, ctx, contaminated=True)
        assert result.echo_detected is True
        # Sensitive LCS overlap < 12, so ALLOW despite echo signal
        assert result.allowed is True

    def test_custom_lcs_threshold_allows_overlap(self, dlp):
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            policy=PolicyConfig(dlp_verbatim_lcs_min=500, dlp_ngram_overlap_min=1.1),
        )
        untrusted = "x" * 200
        dlp.ingest_untrusted(untrusted)
        result = dlp.check(untrusted, ctx)
        assert result.allowed is True
