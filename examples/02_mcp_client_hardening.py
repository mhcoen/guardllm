"""Demonstrate hardening an MCP client before calling external tools."""

from __future__ import annotations

from _bootstrap import ROOT  # noqa: F401
from guardllm import Guard
from guardllm.security.types import PolicyConfig


def main() -> None:
    guard = Guard(canary_session_id="client-session-1")

    client_ctx = Guard.context_mcp_server(
        server_id="mail-tools",
        policy=PolicyConfig(enable_destructive=True),
    )

    tool = "gmail_send_email"
    args = {"to": "alice@example.com"}
    user_message = "send email to alice@example.com"

    # Without authorization event, destructive call is blocked.
    no_auth = guard.check_tool_call(tool=tool, args=args, context=client_ctx)
    print("[client] no auth blocked:", no_auth.allowed, "|", no_auth.reason)

    # With explicit authorization + request binding, call is allowed.
    auth = Guard.authorize(
        action=tool,
        scope={"to": "alice@example.com"},
        user_message=user_message,
        source="slash_command",
    )
    binding = Guard.bind_request(tool=tool, args=args, authorization=auth)
    gated = guard.check_tool_call(
        tool=tool,
        args=args,
        context=client_ctx,
        authorization=auth,
        binding=binding,
        user_message=user_message,
    )
    print("[client] authorized call allowed:", gated.allowed, "|", gated.reason)


if __name__ == "__main__":
    main()
