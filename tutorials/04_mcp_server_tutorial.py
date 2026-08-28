"""Tutorial 04: MCP server hardening with vordur.

Focus: protecting a server from untrusted MCP client requests.
"""

from __future__ import annotations

from _bootstrap import ROOT  # noqa: F401

from vordur import Guard
from vordur.security.error_sanitizer import InvalidParamsError
from vordur.security.types import PolicyConfig


class FakeServerDispatcher:
    """Tiny demo dispatcher that only supports read-only tools."""

    def run(self, tool: str, args: dict) -> dict:
        if tool == "search_knowledge":
            # Deliberately avoid echoing untrusted user input in the response.
            return {"ok": True, "results": ["knowledge search completed"]}
        return {"ok": False, "reason": "unknown tool"}


def handle_mcp_request(guard: Guard, dispatcher: FakeServerDispatcher, request: dict) -> dict:
    """Reference server-side request flow with vordur."""

    tool = request["tool"]
    args = request["args"]
    client_id = request.get("client_id", "unknown-client")

    # 1) Build server context for inbound MCP client traffic.
    server_ctx = Guard.context_mcp_client(
        client_id=client_id,
        policy=PolicyConfig(
            capability_scopes={
                "search_knowledge": {},
                "get_topics": {},
            },
            enable_destructive=False,
        ),
    )

    # 2) Validate args before processing.
    valid = guard.validate_tool_args(tool, args)
    if not valid.valid:
        return guard.sanitize_exception(InvalidParamsError(valid.field_name or "unknown"))

    # 3) Sanitize inbound string arguments from the untrusted client.
    safe_args = dict(args)
    if isinstance(safe_args.get("query"), str):
        safe_args["query"] = guard.process_inbound(safe_args["query"], server_ctx).content

    # 4) Enforce policy/rate/binding checks for this tool call.
    gate = guard.check_tool_call(tool=tool, args=safe_args, context=server_ctx)
    if not gate.allowed:
        return {"error": {"code": "permission_denied", "message": gate.reason}}

    # 5) Execute.
    result = dispatcher.run(tool, safe_args)

    # 6) Check outbound response before returning to client.
    out = guard.check_outbound(str(result), server_ctx)
    if not out.allowed:
        return {"error": {"code": "blocked", "message": out.reason}}

    return result


def main() -> None:
    guard = Guard()
    dispatcher = FakeServerDispatcher()

    print("=== server tutorial: safe request ===")
    safe_req = {
        "client_id": "agent-42",
        "tool": "search_knowledge",
        "args": {"query": "project roadmap milestones"},
    }
    safe_resp = handle_mcp_request(guard, dispatcher, safe_req)
    print(safe_resp)
    assert "error" not in safe_resp and safe_resp.get("ok") is True

    print("\n=== server tutorial: blocked request (tool not in capability scopes) ===")
    blocked_req = {
        "client_id": "agent-42",
        "tool": "gmail_send_email",
        "args": {"to": "attacker@example.com"},
    }
    blocked_resp = handle_mcp_request(guard, dispatcher, blocked_req)
    print(blocked_resp)
    assert "error" in blocked_resp

    print("\n=== server tutorial: fail-closed default (server_default_deny) ===")
    # If you forget to configure capability_scopes, server mode allows
    # non-destructive tools by default. Set server_default_deny=True so a
    # missing scope config denies everything instead of failing open.
    locked_ctx = Guard.context_mcp_client(
        client_id="agent-42",
        policy=PolicyConfig(server_default_deny=True),  # no capability_scopes
    )
    locked = guard.check_tool_call(tool="search_knowledge", args={}, context=locked_ctx)
    print("search_knowledge with server_default_deny:", locked.allowed, "|", locked.reason)
    assert not locked.allowed


if __name__ == "__main__":
    main()
