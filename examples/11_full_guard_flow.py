"""Demonstrate full Guard API parity flow in one place.

Covers: validation (L12.2), policy/binding (L5/L9), action gate (L2),
audit logging (L11), and error sanitization.
"""

from __future__ import annotations

import asyncio
import time

from _bootstrap import ROOT  # noqa: F401
from guardllm import Guard
from guardllm.security.audit import AuditLogger
from guardllm.security.error_sanitizer import PermissionDeniedError
from guardllm.security.types import ConfirmationHandler, PolicyConfig


class AllowAllHandler(ConfirmationHandler):
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        return True


async def main() -> None:
    audit = AuditLogger()
    guard = Guard(audit_logger=audit)

    ctx = Guard.context_mcp_server(
        server_id="mail-tools",
        policy=PolicyConfig(enable_destructive=True),
    )
    ctx.confirmation_handler = AllowAllHandler()

    tool = "gmail_send_email"
    args = {"to": "alice@example.com"}
    user_message = "send email to alice@example.com"

    auth = Guard.authorize(
        action=tool,
        scope={"to": "alice@example.com"},
        user_message=user_message,
        timestamp=time.time(),
    )
    binding = Guard.bind_request(tool=tool, args=args, authorization=auth)

    result = await guard.guard_tool_call(
        tool=tool,
        args=args,
        context=ctx,
        authorization=auth,
        binding=binding,
        user_message=user_message,
        require_confirmation=True,
        summary="Send email to alice@example.com",
        validate=True,
    )
    print("[full] gated tool call allowed:", result.allowed, "|", result.reason)

    invalid = await guard.guard_tool_call(
        tool="search_knowledge",
        args={"thread_handle": "bad@#$"},
        context=ctx,
        validate=True,
    )
    print("[full] validation failed:", invalid.allowed, "|", invalid.reason)

    sanitized = guard.sanitize_exception(PermissionDeniedError("blocked"))
    print("[full] sanitized error:", sanitized)

    print("[full] audit events:", [e["event_type"] for e in audit.get_events(limit=20)])


if __name__ == "__main__":
    asyncio.run(main())
