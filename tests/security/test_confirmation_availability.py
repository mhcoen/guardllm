"""A missing confirmation handler is a configuration failure, not a denial.

Both outcomes deny the call, but conflating them tells an operator that a user
declined when no user was ever asked, and leaves the audit trail asserting a
decision nobody made.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time

from guardllm import Guard, PolicyConfig
from guardllm.security.types import SecurityContext


class _Approves:
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        return True


class _Declines:
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        return False


TOOL = "gmail_send_email"
ARGS = {"to": "alice@example.com", "subject": "Update", "body": "Hello"}


def _context(handler) -> SecurityContext:
    ctx = Guard.context_mcp_server(
        server_id="mcp-gsuite", policy=PolicyConfig(enable_destructive=True)
    )
    if handler is None:
        return ctx
    return dataclasses.replace(ctx, confirmation_handler=handler)


async def _attempt(guard: Guard, handler):
    ctx = _context(handler)
    auth = Guard.authorize(action=TOOL, scope=ARGS, user_message="send it", timestamp=time.time())
    binding = Guard.bind_request(tool=TOOL, args=ARGS, authorization=auth)
    return await guard.guard_tool_call(
        tool=TOOL,
        args=ARGS,
        context=ctx,
        authorization=auth,
        binding=binding,
        user_message="send it",
        require_confirmation=True,
        summary=f"Execute {TOOL}",
        validate=True,
    )


def test_missing_handler_reports_unavailable_not_denial():
    result = asyncio.run(_attempt(Guard(), None))
    assert result.allowed is False
    assert result.reason == "Confirmation unavailable: no confirmation handler configured"


def test_declining_handler_still_reports_user_denial():
    result = asyncio.run(_attempt(Guard(), _Declines()))
    assert result.allowed is False
    assert result.reason == "User denied confirmation"


def test_approving_handler_permits():
    result = asyncio.run(_attempt(Guard(), _Approves()))
    assert result.allowed is True


def test_audit_distinguishes_the_two_outcomes():
    """user_confirmed=False asserts a decision. Nobody decided anything."""
    events: list = []

    for handler, expected_type, expected_confirmed in (
        (None, "action_gate_unavailable", None),
        (_Declines(), "action_gate_confirmed", False),
        (_Approves(), "action_gate_confirmed", True),
    ):
        captured: list = []
        guard = Guard(audit_logger=type("L", (), {"log": staticmethod(captured.append)})())
        asyncio.run(_attempt(guard, handler))
        gate_events = [
            e for e in captured if getattr(e, "event_type", "").startswith("action_gate")
        ]
        assert gate_events, f"no action gate event for {expected_type}"
        event = gate_events[-1]
        assert event.event_type == expected_type
        assert event.user_confirmed is expected_confirmed
        events.append(event)

    # The unavailable case must not be recorded as a user decision at all.
    assert events[0].user_confirmed is None
    assert events[1].user_confirmed is False
