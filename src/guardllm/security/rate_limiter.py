"""Layer 6: Rate limiting and anomaly detection (Part 9).

Per-session counters with time windows. Detects anomalous patterns
(novel recipients, rapid bursts, high volume) independent of LLM
compliance or user attentiveness.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

from guardllm.security.types import RateLimitResult, SecurityContext


@dataclass
class _SessionCounters:
    """Tracks actions within time windows for a single session."""

    # action_type -> list of timestamps
    action_times: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    known_recipients: set[str] = field(default_factory=set)


# Default limits from spec §9
DEFAULT_LIMITS = {
    "emails_per_hour": 10,
    "burst_threshold": 3,  # actions in burst_window_seconds, counting the proposal
    "burst_window_seconds": 10,
    "novel_recipient_flag": True,
}


class RateLimiter:
    """Per-session rate limiter with anomaly detection.

    Supports both client mode (outbound tool call limiting) and server
    mode (inbound request limiting). Same counter mechanism, different
    dimensions.
    """

    def __init__(self, limits: dict | None = None):
        self._limits = limits or DEFAULT_LIMITS
        self._sessions: dict[str, _SessionCounters] = {}
        # Serializes the compound check-then-record so it is atomic for hosts
        # that drive one session from multiple OS threads. check() and record()
        # remain lock-free primitives; check_and_record() holds this across both.
        self._lock = threading.Lock()

    def _get_session(self, session_id: str) -> _SessionCounters:
        if session_id not in self._sessions:
            self._sessions[session_id] = _SessionCounters()
        return self._sessions[session_id]

    def _prune_old(self, times: list[float], window_seconds: float) -> list[float]:
        """Remove timestamps older than the window."""
        cutoff = time.time() - window_seconds
        return [t for t in times if t > cutoff]

    def _effective_limits(self, ctx: SecurityContext) -> dict:
        """Merge principal_trust overrides with base limits.

        Override wins for any key present. Base limits fill in the rest.
        Never mutates DEFAULT_LIMITS or self._limits.
        """
        overrides = ctx.policy.rate_limit_overrides.get(ctx.principal_trust)
        if not overrides:
            return self._limits
        merged = dict(self._limits)
        merged.update(overrides)
        return merged

    def check(
        self,
        action: str,
        ctx: SecurityContext,
        recipient: str | None = None,
        session_id: str | None = None,
    ) -> RateLimitResult:
        """Check if an action is within rate limits.

        The hourly cap blocks and counts only completed actions. The burst and
        novel-recipient signals are advisory and never block; the burst count
        includes the action being checked, so ``burst_threshold`` actions inside
        the window flag the last of them rather than the one after it.

        Args:
            action: Action type (e.g. "gmail_send_email").
            ctx: Security context.
            recipient: Optional recipient for novel-recipient detection.
            session_id: Session identifier. Uses ctx.source_id if not provided.

        Returns:
            RateLimitResult with allowed=True if within limits.
        """
        sid = session_id or ctx.source_id
        session = self._get_session(sid)
        anomalies: list[str] = []
        limits = self._effective_limits(ctx)

        # Prune old entries using configured window (default 3600s)
        window = limits.get("window_seconds", 3600)
        session.action_times[action] = self._prune_old(session.action_times[action], window)
        hourly_count = len(session.action_times[action])

        # Check hourly limit
        hourly_limit = limits.get("emails_per_hour", 10)
        if hourly_count >= hourly_limit:
            return RateLimitResult(
                allowed=False,
                reason=f"Hourly limit exceeded ({hourly_count}/{hourly_limit})",
                remaining=0,
                retry_after=self._seconds_until_slot(session.action_times[action], window),
            )

        # Check the burst pattern the proposed action would produce, counting it
        # alongside the prior completed actions in the window. The proposal is
        # recorded only after every check permits it, so counting only the prior
        # actions would make a burst of exactly burst_threshold actions invisible:
        # the signal would first appear on the action after the burst.
        #
        # This deliberately differs from the hourly cap above, which counts only
        # completed actions because it governs quota and must reflect what
        # actually happened. The burst signal is advisory and never blocks, so
        # naming a call that a later gate may still deny costs nothing, while
        # missing a threshold-sized burst is a detection gap.
        burst_threshold = limits.get("burst_threshold", 3)
        burst_window = limits.get("burst_window_seconds", 10)
        recent = self._prune_old(session.action_times[action], burst_window)
        proposed_burst = len(recent) + 1
        if proposed_burst >= burst_threshold:
            anomalies.append(f"Rapid burst: {proposed_burst} actions in {burst_window}s")

        # Check novel recipient
        if (
            recipient
            and limits.get("novel_recipient_flag", True)
            and recipient not in session.known_recipients
        ):
            anomalies.append(f"Novel recipient: {recipient}")

        return RateLimitResult(
            allowed=True,
            reason="within limits",
            anomalies=anomalies,
            remaining=hourly_limit - hourly_count,
        )

    def record(
        self,
        action: str,
        ctx: SecurityContext,
        recipient: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Record a completed action for rate tracking.

        Call this AFTER the action executes successfully.
        """
        sid = session_id or ctx.source_id
        session = self._get_session(sid)
        session.action_times[action].append(time.time())
        if recipient:
            session.known_recipients.add(recipient)

    def check_and_record(
        self,
        action: str,
        ctx: SecurityContext,
        recipient: str | None = None,
        session_id: str | None = None,
    ) -> RateLimitResult:
        """Atomically check the limit and record the action if it is within it.

        The check and the record run under a single lock acquisition, so two
        callers cannot both pass a near-full limit before either records. This
        closes the check-then-record gap for hosts driving one session from
        multiple OS threads (asyncio already serializes because there is no
        ``await`` between the two). Returns the check result; a caller denies
        the action when ``allowed`` is False.
        """
        with self._lock:
            result = self.check(action, ctx, recipient=recipient, session_id=session_id)
            if result.allowed:
                self.record(action, ctx, recipient=recipient, session_id=session_id)
            return result

    def _seconds_until_slot(self, times: list[float], window: float = 3600) -> int:
        """Calculate seconds until the oldest entry expires from the window."""
        if not times:
            return 0
        oldest = min(times)
        remaining = window - (time.time() - oldest)
        return max(1, int(remaining))

    def reset(self, session_id: str | None = None) -> None:
        """Reset counters. If session_id given, reset only that session."""
        if session_id:
            self._sessions.pop(session_id, None)
        else:
            self._sessions.clear()
