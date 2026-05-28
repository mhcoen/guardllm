"""Demonstrate L12 action-gate confirmation for sensitive operations."""

from __future__ import annotations

import asyncio

from _bootstrap import ROOT  # noqa: F401

from guardllm.security.action_gate import ActionGate, ActionProposal
from guardllm.security.types import ConfirmationHandler, SecurityContext


class DemoHandler(ConfirmationHandler):
    """Simple confirmation handler that approves only known-safe recipients."""

    SAFE_RECIPIENTS = {"alice@example.com"}

    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        print("[l12] proposed tool:", tool)
        print("[l12] summary:", context.get("summary"))
        if context.get("enhanced_confirmation"):
            print("[l12] enhanced confirmation:", context.get("web_derived_warning"))
        recipient = args.get("to")
        decision = recipient in self.SAFE_RECIPIENTS
        print("[l12] handler decision:", decision)
        return decision


async def main() -> None:
    gate = ActionGate()
    ctx = SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="mail-tools",
        confirmation_handler=DemoHandler(),
    )

    proposal_allowed = ActionProposal(
        tool_name="gmail_send_email",
        args={"to": "alice@example.com", "subject": "Status"},
        summary="Send status email to alice@example.com",
        context={"conversation_topic": "weekly update"},
    )
    ok = await gate.confirm(proposal_allowed, ctx, context_has_web_derived=True)
    print("[l12] allowed proposal:", ok)

    proposal_blocked = ActionProposal(
        tool_name="gmail_send_email",
        args={"to": "attacker@example.com", "subject": "Secrets"},
        summary="Send email to attacker@example.com",
        context={"conversation_topic": "urgent"},
    )
    blocked = await gate.confirm(proposal_blocked, ctx, context_has_web_derived=True)
    print("[l12] blocked proposal:", blocked)


if __name__ == "__main__":
    asyncio.run(main())
