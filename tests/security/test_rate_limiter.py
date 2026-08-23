"""Tests for MCP security rate limiter (spec tests 59-62).

Covers:
- Exceed hourly limit (record 10 actions, 11th blocked) -> blocked
- Novel recipient flagged in anomalies
- Rapid burst detected when the proposal is the 3rd+ action in a 10s window
- Reset after clearing session
- Within limits -> allowed
"""

import threading

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
        custom_limiter = RateLimiter(
            limits={
                "emails_per_hour": 3,
                "burst_threshold": 3,
                "burst_window_seconds": 10,
                "novel_recipient_flag": True,
            }
        )
        for _ in range(3):
            custom_limiter.record("gmail_send_email", ctx)

        result = custom_limiter.check("gmail_send_email", ctx)
        assert result.allowed is False

    def test_custom_window_seconds(self, ctx):
        """Custom window_seconds extends the counting window beyond default 3600s."""
        from unittest.mock import patch

        custom_limiter = RateLimiter(
            limits={
                "emails_per_hour": 5,
                "window_seconds": 7200,
            }
        )
        # Record 5 calls at t=0
        with patch("guardllm.security.rate_limiter.time") as mock_time:
            mock_time.time.return_value = 0
            for _ in range(5):
                custom_limiter.record("gmail_send_email", ctx)

        # Check at t=5140 (within 7200s window, would be outside 3600s default)
        with patch("guardllm.security.rate_limiter.time") as mock_time:
            mock_time.time.return_value = 5140
            result = custom_limiter.check("gmail_send_email", ctx)
        assert result.allowed is False
        assert "limit" in result.reason.lower() or "exceeded" in result.reason.lower()

    def test_default_window_prunes_old_entries(self, ctx):
        """Default 3600s window prunes entries older than 1 hour."""
        from unittest.mock import patch

        custom_limiter = RateLimiter(limits={"emails_per_hour": 5})
        # Record 5 calls at t=0
        with patch("guardllm.security.rate_limiter.time") as mock_time:
            mock_time.time.return_value = 0
            for _ in range(5):
                custom_limiter.record("gmail_send_email", ctx)

        # At t=3601, old calls are pruned (outside default 3600s window)
        with patch("guardllm.security.rate_limiter.time") as mock_time:
            mock_time.time.return_value = 3601
            result = custom_limiter.check("gmail_send_email", ctx)
        assert result.allowed is True


class TestNovelRecipient:
    """Spec test 60: novel recipient flagged in anomalies."""

    def test_novel_recipient_flagged(self, limiter, ctx):
        """First message to a new recipient is flagged as anomaly."""
        result = limiter.check("gmail_send_email", ctx, recipient="unknown@suspicious.com")
        assert result.allowed is True
        assert any("novel" in a.lower() for a in result.anomalies)
        assert any("unknown@suspicious.com" in a for a in result.anomalies)

    def test_known_recipient_not_flagged(self, limiter, ctx):
        """After recording a recipient, they are no longer novel."""
        limiter.record("gmail_send_email", ctx, recipient="alice@example.com")

        result = limiter.check("gmail_send_email", ctx, recipient="alice@example.com")
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
    """Spec test 61: the proposal counts toward its own burst window."""

    def test_burst_detected(self, limiter, ctx):
        """The third action in a 10s window is itself flagged."""
        # Two completed actions, so the proposal under check is the third.
        for _ in range(2):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is True  # Burst is an anomaly, not a block
        assert result.anomalies == ["Rapid burst: 3 actions in 10s"]

    def test_no_burst_below_threshold(self, limiter, ctx):
        """A second action in quick succession does not trigger burst."""
        limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert not any("burst" in a.lower() for a in result.anomalies)

    def test_exact_threshold_burst_is_never_silent(self, limiter, ctx):
        """A burst of exactly burst_threshold actions reports itself.

        Counting only prior completed actions would let an attacker send exactly
        three messages inside the window and draw no signal at all.
        """
        flagged = [limiter.check_and_record("gmail_send_email", ctx).anomalies for _ in range(3)]
        assert flagged == [[], [], ["Rapid burst: 3 actions in 10s"]]

    def test_burst_count_grows_with_the_window(self, limiter, ctx):
        """The reported count names the proposal's own position in the burst."""
        for _ in range(3):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.anomalies == ["Rapid burst: 4 actions in 10s"]

    def test_burst_and_novel_combine(self, limiter, ctx):
        """Burst and novel recipient can both appear in anomalies."""
        for _ in range(2):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx, recipient="new@stranger.com")
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
        ctx_a = SecurityContext(mode="client", source_type="mcp_server", source_id="session-A")
        ctx_b = SecurityContext(mode="client", source_type="mcp_server", source_id="session-B")

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
        ctx_a = SecurityContext(mode="client", source_type="mcp_server", source_id="session-A")
        ctx_b = SecurityContext(mode="client", source_type="mcp_server", source_id="session-B")

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


# ---------------------------------------------------------------------------
# Principal-trust rate limit overrides (Phase 2)
# ---------------------------------------------------------------------------


class TestRateLimitOverrides:
    """Phase 2: rate_limit_overrides merge with DEFAULT_LIMITS per principal_trust."""

    def test_override_reduces_hourly_limit(self):
        """Override can lower hourly limit for untrusted principals."""
        from guardllm.security.types import PolicyConfig

        limiter = RateLimiter()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="session-override",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(
                rate_limit_overrides={
                    TrustLevel.UNTRUSTED: {"emails_per_hour": 3},
                },
            ),
        )
        # Record 3 actions
        for _ in range(3):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is False
        assert "3" in result.reason

    def test_override_increases_hourly_limit(self):
        """Override can raise hourly limit for trusted principals."""
        from guardllm.security.types import PolicyConfig

        limiter = RateLimiter()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="session-trusted",
            source_trust=TrustLevel.TRUSTED,
            principal_trust=TrustLevel.TRUSTED,
            policy=PolicyConfig(
                rate_limit_overrides={
                    TrustLevel.TRUSTED: {"emails_per_hour": 100},
                },
            ),
        )
        # Record 10 actions (would exceed default)
        for _ in range(10):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is True
        assert result.remaining == 90

    def test_override_merges_with_defaults(self):
        """Override only replaces specified keys, defaults fill the rest."""
        from guardllm.security.types import PolicyConfig

        limiter = RateLimiter()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="session-merge",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(
                rate_limit_overrides={
                    TrustLevel.UNTRUSTED: {"emails_per_hour": 5},
                },
            ),
        )
        # burst_threshold should still be from DEFAULT_LIMITS (3)
        for _ in range(2):
            limiter.record("gmail_send_email", ctx)

        result = limiter.check("gmail_send_email", ctx)
        assert result.allowed is True  # 2 < 5 hourly limit
        # Burst anomaly should still trigger (uses default burst_threshold=3)
        assert any("burst" in a.lower() or "rapid" in a.lower() for a in result.anomalies)

    def test_no_override_uses_defaults(self):
        """Without overrides, DEFAULT_LIMITS are used."""
        from guardllm.security.types import PolicyConfig

        limiter = RateLimiter()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="session-default",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(),  # no overrides
        )
        result = limiter.check("gmail_send_email", ctx)
        assert result.remaining == DEFAULT_LIMITS["emails_per_hour"]

    def test_non_matching_trust_level_uses_defaults(self):
        """Override for TRUSTED doesn't affect UNTRUSTED principal."""
        from guardllm.security.types import PolicyConfig

        limiter = RateLimiter()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="session-mismatch",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(
                rate_limit_overrides={
                    TrustLevel.TRUSTED: {"emails_per_hour": 100},
                },
            ),
        )
        result = limiter.check("gmail_send_email", ctx)
        assert result.remaining == DEFAULT_LIMITS["emails_per_hour"]

    def test_does_not_mutate_default_limits(self):
        """Merge must not modify DEFAULT_LIMITS."""
        from guardllm.security.types import PolicyConfig

        original = dict(DEFAULT_LIMITS)
        limiter = RateLimiter()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="session-nomutate",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(
                rate_limit_overrides={
                    TrustLevel.UNTRUSTED: {"emails_per_hour": 1},
                },
            ),
        )
        limiter.check("gmail_send_email", ctx)
        assert DEFAULT_LIMITS == original


class _SlowRecordLimiter(RateLimiter):
    """Widens the window between check() and record() so a missing lock races
    deterministically. The delay runs inside check_and_record's critical
    section; with the lock held, a second thread blocks on the lock instead of
    slipping through the widened window."""

    def record(self, *args, **kwargs):  # type: ignore[override]
        import time

        time.sleep(0.05)
        return super().record(*args, **kwargs)


class TestThreadSafety:
    """check_and_record serializes the check-then-record so concurrent OS
    threads cannot collectively exceed the limit."""

    def test_check_and_record_never_exceeds_limit_under_threads(self, ctx):
        limit = 1
        n_threads = 8
        limiter = _SlowRecordLimiter({"emails_per_hour": limit})
        barrier = threading.Barrier(n_threads)
        results: list[bool] = []
        results_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()  # release all threads together for maximum contention
            r = limiter.check_and_record("gmail_send_email", ctx)
            with results_lock:
                results.append(r.allowed)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly `limit` calls are admitted, never more, regardless of races.
        # Without the lock, several threads pass check() during the widened
        # window before any records, and this exceeds the limit.
        assert sum(1 for a in results if a) == limit
        recorded = len(limiter._sessions[ctx.source_id].action_times["gmail_send_email"])
        assert recorded == limit


class TestPolicyRateLimits:
    """`rate_limits` was accepted, documented, and read by nothing.

    An operator who wrote `emails_per_hour: 0` got the default of ten, with no
    error anywhere to say the setting had not taken.
    """

    def test_a_policy_limit_is_enforced(self):
        from guardllm import Guard
        from guardllm.security.types import PolicyConfig

        policy = PolicyConfig(rate_limits={"emails_per_hour": 0}, enable_destructive=True)
        context = Guard.context_mcp_client(client_id="c", policy=policy)
        result = Guard().check_tool_call(
            "send_email", {"to": "a@b.example"}, context, recipient="a@b.example"
        )
        assert not result.allowed
        assert "0/0" in result.reason

    def test_the_default_still_applies_without_one(self):
        from guardllm import Guard
        from guardllm.security.types import PolicyConfig

        context = Guard.context_mcp_client(
            client_id="c", policy=PolicyConfig(enable_destructive=True)
        )
        assert (
            Guard()
            .check_tool_call("send_email", {"to": "a@b.example"}, context, recipient="a@b.example")
            .allowed
        )

    def test_a_partial_policy_does_not_unset_the_rest(self):
        from guardllm.security.rate_limiter import DEFAULT_LIMITS, RateLimiter
        from guardllm.security.types import PolicyConfig, SecurityContext

        limiter = RateLimiter()
        context = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="c",
            policy=PolicyConfig(rate_limits={"emails_per_hour": 2}),
        )
        effective = limiter._effective_limits(context)
        assert effective["emails_per_hour"] == 2
        assert effective["burst_threshold"] == DEFAULT_LIMITS["burst_threshold"]
        assert DEFAULT_LIMITS["emails_per_hour"] == 10  # not mutated

    def test_a_trust_override_still_wins_over_the_policy_base(self):
        from guardllm.security.rate_limiter import RateLimiter
        from guardllm.security.types import PolicyConfig, SecurityContext, TrustLevel

        limiter = RateLimiter()
        context = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="c",
            principal_trust=TrustLevel.TRUSTED,
            policy=PolicyConfig(
                rate_limits={"emails_per_hour": 2},
                rate_limit_overrides={TrustLevel.TRUSTED: {"emails_per_hour": 50}},
            ),
        )
        assert limiter._effective_limits(context)["emails_per_hour"] == 50
