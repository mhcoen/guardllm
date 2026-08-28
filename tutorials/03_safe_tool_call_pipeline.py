"""Tutorial 03: safe tool call pipeline (validate + authorize + bind + confirm + outbound check)."""

from __future__ import annotations

import asyncio
import time

from _bootstrap import ROOT  # noqa: F401

from vordur import Guard
from vordur.security.types import ConfirmationHandler, PolicyConfig


class AllowAll(ConfirmationHandler):
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        return True


async def main() -> None:
    guard = Guard()
    ctx = Guard.context_mcp_server(
        server_id="mcp-gsuite",
        # require_message_binding="destructive" makes anti-replay fail closed:
        # a destructive tool call must be bound to the current user message.
        policy=PolicyConfig(
            enable_destructive=True,
            require_message_binding="destructive",
        ),
    )
    ctx.confirmation_handler = AllowAll()

    tool = "gmail_send_email"
    args = {"to": "alice@example.com"}
    msg = "send summary to alice@example.com"

    auth = Guard.authorize(
        action=tool,
        scope={"to": "alice@example.com"},
        user_message=msg,
        timestamp=time.time(),
    )
    binding = Guard.bind_request(tool=tool, args=args, authorization=auth)

    gate = await guard.guard_tool_call(
        tool=tool,
        args=args,
        context=ctx,
        authorization=auth,
        binding=binding,
        user_message=msg,
        require_confirmation=True,
        summary="Send summary email",
        validate=True,
    )
    print("tool gate:", gate.allowed, "|", gate.reason)
    assert gate.allowed

    outbound = guard.check_outbound("Safe summary body", ctx)
    print("outbound:", outbound.allowed, "|", outbound.reason)
    assert outbound.allowed

    # Anti-replay: the same authorization replayed after the conversation has
    # advanced (a different user message) is denied by message binding.
    replay = await guard.guard_tool_call(
        tool=tool,
        args=args,
        context=ctx,
        authorization=auth,
        binding=binding,
        user_message="what's the weather tomorrow?",
        require_confirmation=True,
        summary="Send summary email",
        validate=True,
    )
    print("replay on a later message:", replay.allowed, "|", replay.reason)
    assert not replay.allowed
    assert "replay" in replay.reason.lower()

    # Egress feedback escalation: a DLP block at egress is a session-risk
    # signal that tightens subsequent tool calls (default escalated_tool_policy
    # is "require_auth"). Use a fresh Guard so this session starts clean.
    esc_guard = Guard()
    esc_ctx = Guard.context_mcp_server(
        server_id="mcp-gsuite",
        policy=PolicyConfig(enable_destructive=True),
    )
    # A secret pattern in outbound content is a DLP hard block.
    leak = esc_guard.check_outbound(
        "for your records the key is sk-abcdefghijklmnopqrstuvwxyz1234",
        esc_ctx,
    )
    print("egress DLP block:", leak.allowed, "|", leak.reason)
    assert not leak.allowed

    # A later tool call in the same session is now tightened: without an
    # authorization event it is denied, and the reason names the trigger.
    tightened = esc_guard.check_tool_call("search_docs", {"query": "roadmap"}, esc_ctx)
    print("tool call after egress block:", tightened.allowed, "|", tightened.reason)
    assert not tightened.allowed
    assert "egress escalated" in tightened.reason.lower()


if __name__ == "__main__":
    asyncio.run(main())
