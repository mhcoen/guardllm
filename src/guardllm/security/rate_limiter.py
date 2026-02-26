"""Layer 6: Rate limiting and anomaly detection (Part 9).

Per-session counters with time windows. Detects anomalous patterns
(novel recipients, rapid bursts, high volume) independent of LLM
compliance or user attentiveness.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from guardllm.security.types import RateLimitResult, SecurityContext


@dataclass
class _SessionCounters:
    """Tracks actions within time windows for a single session."""

    # action_type -> list of timestamps
    action_times: Dict[str, List[float]] = field(
        default_factory=lambda: defaultdict(list)
    )
    known_recipients: Set[str] = field(default_factory=set)


# Default limits from spec §9
DEFAULT_LIMITS = {
    "emails_per_hour": 10,
    "burst_threshold": 3,       # actions in burst_window_seconds
    "burst_window_seconds": 10,
    "novel_recipient_flag": True,
}


class RateLimiter:
    """Per-session rate limiter with anomaly detection.

    Supports both client mode (outbound tool call limiting) and server
    mode (inbound request limiting). Same counter mechanism, different
    dimensions.
    """

    def __init__(self, limits: Optional[Dict] = None):
        self._limits = limits or DEFAULT_LIMITS
        self._sessions: Dict[str, _SessionCounters] = {}

    def _get_session(self, session_id: str) -> _SessionCounters:
        if session_id not in self._sessions:
            self._sessions[session_id] = _SessionCounters()
        return self._sessions[session_id]

    def _prune_old(self, times: List[float], window_seconds: float) -> List[float]:
        """Remove timestamps older than the window."""
        cutoff = time.time() - window_seconds
        return [t for t in times if t > cutoff]

    def _effective_limits(self, ctx: SecurityContext) -> Dict:
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
        recipient: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> RateLimitResult:
        """Check if an action is within rate limits.

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
        anomalies: List[str] = []
        limits = self._effective_limits(ctx)

        # Prune old entries using configured window (default 3600s)
        window = limits.get("window_seconds", 3600)
        session.action_times[action] = self._prune_old(
            session.action_times[action], window
        )
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

        # Check burst pattern
        burst_threshold = limits.get("burst_threshold", 3)
        burst_window = limits.get("burst_window_seconds", 10)
        recent = self._prune_old(session.action_times[action], burst_window)
        if len(recent) >= burst_threshold:
            anomalies.append(
                f"Rapid burst: {len(recent)} actions in {burst_window}s"
            )

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
        recipient: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """Record a completed action for rate tracking.

        Call this AFTER the action executes successfully.
        """
        sid = session_id or ctx.source_id
        session = self._get_session(sid)
        session.action_times[action].append(time.time())
        if recipient:
            session.known_recipients.add(recipient)

    def _seconds_until_slot(self, times: List[float], window: float = 3600) -> int:
        """Calculate seconds until the oldest entry expires from the window."""
        if not times:
            return 0
        oldest = min(times)
        remaining = window - (time.time() - oldest)
        return max(1, int(remaining))

    def reset(self, session_id: Optional[str] = None) -> None:
        """Reset counters. If session_id given, reset only that session."""
        if session_id:
            self._sessions.pop(session_id, None)
        else:
            self._sessions.clear()
