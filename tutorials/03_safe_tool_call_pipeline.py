"""Tutorial 03: safe tool call pipeline (validate + authorize + bind + confirm + outbound check)."""

from __future__ import annotations

import asyncio
import time

from _bootstrap import ROOT  # noqa: F401

from guardllm import Guard
from guardllm.security.types import ConfirmationHandler, PolicyConfig


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


if __name__ == "__main__":
    asyncio.run(main())
