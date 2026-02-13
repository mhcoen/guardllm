"""Tests for MCP security rate limiter (spec tests 59-62).

Covers:
- Exceed hourly limit (record 10 actions, 11th blocked) -> blocked
- Novel recipient flagged in anomalies
- Rapid burst detected (3+ in 10s window)
- Reset after clearing session
- Within limits -> allowed
"""

import time

import pytest

from guardllm.security.rate_limiter import DEFAULT_LIMITS, RateLimiter
from guardllm.security.types import SecurityContext, TrustLevel


@pytest.fixture
def ctx():
    """A standard SecurityContext for rate limiter tests."""
    return SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="session-test",
    )


@pytest.fixture
def limiter():
    """A fresh RateLimiter with default limits."""
    return RateLimiter()


class TestWithinLimits:
    """Actions within limits are allowed."""

    def test_first_action_allowed(self, limiter, ctx):
        """The very first action is always allowed."""
        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is True
        assert result.reason == "within limits"

    def test_remaining_count(self, limiter, ctx):
        """Remaining count reflects available quota."""
        result = limiter.check("gmail_send_email", ctx)
        assert result.remaining == DEFAULT_LIMITS["emails_per_hour"]

    def test_after_one_record(self, limiter, ctx):
        """After recording one action, remaining decreases."""
        limiter.record("gmail_send_email", ctx)
        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is True
        assert result.remaining == DEFAULT_LIMITS["emails_per_hour"] - 1

    def test_different_actions_independent(self, limiter, ctx):
        """Different action types have independent counters."""
        for _ in range(10):
            limiter.record("gmail_send_email", ctx)

        # gmail_send_email is now at limit, but different action is fine
        result = limiter.check("slack_send_message", ctx)
        assert result.allowed is True
        assert result.remaining == DEFAULT_LIMITS["emails_per_hour"]


class TestExceedHourlyLimit:
    """Spec test 59: exceed hourly limit -> blocked."""

    def test_11th_action_blocked(self, limiter, ctx):
        """After 10 recorded actions, the 11th check is blocked."""
        for _ in range(10):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is False
        assert result.remaining == 0
        assert "limit" in result.reason.lower() or "exceeded" in result.reason.lower()

    def test_retry_after_present(self, limiter, ctx):
        """Blocked result includes retry_after."""
        for _ in range(10):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.retry_after is not None
        assert result.retry_after > 0

    def test_exactly_at_limit_blocked(self, limiter, ctx):
        """Exactly at the hourly limit (10 recorded), next check is blocked."""
        for _ in range(10):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is False

    def test_custom_limit(self, ctx):
        """Custom hourly limit is respected."""
        custom_limiter = RateLimiter(limits={
            "emails_per_hour": 3,
            "burst_threshold": 3,
            "burst_window_seconds": 10,
            "novel_recipient_flag": True,
        })
        for _ in range(3):
            custom_limiter.record("gmail_send_email", ctx)

        result = custom_limiter.check("gmail_send_email", ctx)
        assert result.allowed is False


class TestNovelRecipient:
    """Spec test 60: novel recipient flagged in anomalies."""

    def test_novel_recipient_flagged(self, limiter, ctx):
        """First message to a new recipient is flagged as anomaly."""
        result = limiter.check(
            "gmail_send_email", ctx, recipient="unknown@suspicious.com"
        )
        assert result.allowed is True
        assert any("novel" in a.lower() for a in result.anomalies)
        assert any("unknown@suspicious.com" in a for a in result.anomalies)

    def test_known_recipient_not_flagged(self, limiter, ctx):
        """After recording a recipient, they are no longer novel."""
        limiter.record("gmail_send_email", ctx, recipient="alice@example.com")

        result = limiter.check(
            "gmail_send_email", ctx, recipient="alice@example.com"
        )
        assert not any("novel" in a.lower() for a in result.anomalies)

    def test_no_recipient_no_anomaly(self, limiter, ctx):
        """When no recipient is provided, no novel-recipient anomaly."""
        result = limiter.check("gmail_send_email", ctx)
        assert not any("novel" in a.lower() for a in result.anomalies)

    def test_multiple_novel_recipients(self, limiter, ctx):
        """Each new recipient triggers a novel-recipient anomaly."""
        r1 = limiter.check("gmail_send_email", ctx, recipient="bob@test.com")
        assert any("novel" in a.lower() for a in r1.anomalies)

        # Record bob so he becomes known
        limiter.record("gmail_send_email", ctx, recipient="bob@test.com")

        # Carol is still novel
        r2 = limiter.check("gmail_send_email", ctx, recipient="carol@test.com")
        assert any("novel" in a.lower() for a in r2.anomalies)


class TestRapidBurst:
    """Spec test 61: rapid burst detected (3+ in 10s window)."""

    def test_burst_detected(self, limiter, ctx):
        """3+ actions in 10s window triggers burst anomaly."""
        # Record 3 actions in quick succession
        for _ in range(3):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is True  # Burst is an anomaly, not a block
        assert any("burst" in a.lower() or "rapid" in a.lower() for a in result.anomalies)

    def test_no_burst_below_threshold(self, limiter, ctx):
        """2 actions in quick succession does not trigger burst."""
        limiter.record("gmail_send_email", ctx)
        limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert not any("burst" in a.lower() for a in result.anomalies)

    def test_burst_and_novel_combine(self, limiter, ctx):
        """Burst and novel recipient can both appear in anomalies."""
        for _ in range(3):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check(
            "gmail_send_email", ctx, recipient="new@stranger.com"
        )
        anomaly_text = " ".join(result.anomalies).lower()
        assert "burst" in anomaly_text or "rapid" in anomaly_text
        assert "novel" in anomaly_text


class TestReset:
    """Spec test 62: reset after clearing session."""

    def test_reset_specific_session(self, limiter, ctx):
        """Resetting a specific session clears its counters."""
        for _ in range(10):
            limiter.record("gmail_send_email", ctx)

        # At limit
        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is False

        # Reset the session
        limiter.reset(session_id=ctx.source_id)

        # Now allowed again
        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is True
        assert result.remaining == DEFAULT_LIMITS["emails_per_hour"]

    def test_reset_all_sessions(self, limiter, ctx):
        """Resetting all sessions clears all counters."""
        for _ in range(10):
            limiter.record("gmail_send_email", ctx)

        limiter.reset()

        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is True

    def test_reset_one_session_preserves_another(self, limiter):
        """Resetting session A does not affect session B."""
        ctx_a = SecurityContext(
            mode="client", source_type="mcp_server", source_id="session-A"
        )
        ctx_b = SecurityContext(
            mode="client", source_type="mcp_server", source_id="session-B"
        )

        for _ in range(10):
            limiter.record("gmail_send_email", ctx_a)
            limiter.record("gmail_send_email", ctx_b)

        limiter.reset(session_id="session-A")

        # A is reset
        result_a = limiter.check("gmail_send_email", ctx_a)
        assert result_a.allowed is True

        # B is still at limit
        result_b = limiter.check("gmail_send_email", ctx_b)
        assert result_b.allowed is False

    def test_reset_clears_known_recipients(self, limiter, ctx):
        """Resetting clears known recipients so they become novel again."""
        limiter.record("gmail_send_email", ctx, recipient="alice@example.com")

        # Alice is now known
        r1 = limiter.check("gmail_send_email", ctx, recipient="alice@example.com")
        assert not any("novel" in a.lower() for a in r1.anomalies)

        limiter.reset(session_id=ctx.source_id)

        # After reset, Alice is novel again
        r2 = limiter.check("gmail_send_email", ctx, recipient="alice@example.com")
        assert any("novel" in a.lower() for a in r2.anomalies)


class TestSessionIsolation:
    """Different sessions have independent counters."""

    def test_different_sessions_independent(self, limiter):
        """Two sessions have independent rate limits."""
        ctx_a = SecurityContext(
            mode="client", source_type="mcp_server", source_id="session-A"
        )
        ctx_b = SecurityContext(
            mode="client", source_type="mcp_server", source_id="session-B"
        )

        for _ in range(10):
            limiter.record("gmail_send_email", ctx_a)

        # A is at limit
        assert limiter.check("gmail_send_email", ctx_a).allowed is False

        # B is fresh
        assert limiter.check("gmail_send_email", ctx_b).allowed is True

    def test_explicit_session_id_overrides_ctx(self, limiter, ctx):
        """Explicit session_id parameter overrides ctx.source_id."""
        limiter.record("gmail_send_email", ctx, session_id="custom-session")

        # Default session (ctx.source_id) has no records
        result = limiter.check("gmail_send_email", ctx)
        assert result.remaining == DEFAULT_LIMITS["emails_per_hour"]

        # Custom session has 1 record
        result = limiter.check("gmail_send_email", ctx, session_id="custom-session")
        assert result.remaining == DEFAULT_LIMITS["emails_per_hour"] - 1
