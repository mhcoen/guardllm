"""The decision chain for one session, held in memory and lost on restart.

This is the view that makes the product legible. A content filter's log is a
list of independent verdicts; the thing Vörður does that a filter cannot is
carry a fact from one turn into a decision several turns later. That is
invisible in any per-request log and obvious in a chain:

    1. ingest   web_search      recorded   contaminated=True
    2. egress   model           allowed    contaminated=True
    3. tool_call wire_funds     BLOCKED    session contaminated=deny

Step 3 is only explicable by step 1, and they are different requests.

Ephemeral on purpose. Retention, search and history across restarts are the
console, which is a paid tier; what belongs here is the single live session, so
that someone running the free tier sees the mechanism at least once.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

#: Enough to show a session's shape without letting one long-lived session grow
#: without bound. The gateway holds thousands of sessions, so this is a memory
#: budget as much as a display choice.
_MAX_STEPS = 200


@dataclass(frozen=True)
class Step:
    """One decision, and the session state it left behind."""

    stage: str  # "ingest" | "tool_call" | "egress"
    detail: str  # the tool or source name the decision was about
    outcome: str  # "allowed" | "blocked" | "recorded"
    reason: str
    contaminated: bool
    escalated: bool
    at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "detail": self.detail,
            "outcome": self.outcome,
            "reason": self.reason,
            "contaminated": self.contaminated,
            "escalated": self.escalated,
            "at": self.at,
        }


class Chain:
    """A bounded, ordered record of one session's decisions.

    Holds no content: a step names the stage, the tool or source it concerned,
    and the verdict. The reason strings come from the library and are already
    written to exclude the values they are about, which is the same rule the
    audit logger follows.
    """

    def __init__(self, max_steps: int = _MAX_STEPS) -> None:
        self._steps: deque[Step] = deque(maxlen=max_steps)

    def record(
        self,
        *,
        stage: str,
        detail: str,
        outcome: str,
        reason: str,
        guard: object,
    ) -> None:
        """Append a step, reading session state from the guard at this moment.

        State is captured per step rather than reported once at the end,
        because the whole point is WHEN a flag was set relative to the decision
        it later governed.
        """
        pipeline = getattr(guard, "_pipeline", None)
        self._steps.append(
            Step(
                stage=stage,
                detail=detail,
                outcome=outcome,
                reason=reason,
                contaminated=bool(getattr(pipeline, "context_contaminated", False)),
                escalated=bool(getattr(pipeline, "session_escalated", False)),
            )
        )

    @property
    def steps(self) -> list[Step]:
        return list(self._steps)

    def as_dict(self) -> dict[str, object]:
        steps = self.steps
        return {
            "steps": [s.as_dict() for s in steps],
            "step_count": len(steps),
            "blocked_count": sum(1 for s in steps if s.outcome == "blocked"),
            "contaminated": steps[-1].contaminated if steps else False,
            "escalated": steps[-1].escalated if steps else False,
        }

    def __len__(self) -> int:
        return len(self._steps)
