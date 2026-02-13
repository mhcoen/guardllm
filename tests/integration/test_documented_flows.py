from __future__ import annotations

import asyncio
import time

from guardllm import Guard
from guardllm.security.error_sanitizer import InvalidParamsError
from guardllm.security.types import ConfirmationHandler, PolicyConfig


class _DispatchStub:
    def run(self, tool: str, args: dict) -> dict:
        if tool == "search_knowledge":
            return {"ok": True, "results": ["knowledge search completed"]}
        return {"ok": False, "reason": "unknown tool"}


class _AllowAllHandler(ConfirmationHandler):
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        return True


class _TransportStub:
    def call_tool(self, tool: str, args: dict) -> dict:
        return {"ok": True, "tool": tool, "args": args}


def _handle_server_request(guard: Guard, dispatcher: _DispatchStub, request: dict) -> dict:
    tool = request["tool"]
    args = dict(request.get("args", {}))
    client_id = request.get("client_id", "unknown-client")

    ctx = Guard.context_mcp_client(
        client_id=client_id,
        policy=PolicyConfig(
            capability_scopes={"search_knowledge": {}, "get_topics": {}},
            enable_destructive=False,
        ),
    )

    validation = guard.validate_tool_args(tool, args)
    if not validation.valid:
        return guard.sanitize_exception(InvalidParamsError(validation.field_name or "unknown"))

    for key, value in list(args.items()):
        if isinstance(value, str):
            args[key] = guard.process_inbound(value, ctx).content

    gate = guard.check_tool_call(tool=tool, args=args, context=ctx)
    if not gate.allowed:
        return {"error": {"code": "permission_denied", "message": gate.reason}}

    result = dispatcher.run(tool, args)
    out = guard.check_outbound(str(result), ctx)
    if not out.allowed:
        return {"error": {"code": "blocked", "message": out.reason}}

    return result


def test_server_template_safe_flow_allows_read_tool():
    guard = Guard()
    dispatcher = _DispatchStub()
    request = {
        "client_id": "agent-42",
        "tool": "search_knowledge",
        "args": {"query": "project roadmap milestones"},
    }
    result = _handle_server_request(guard, dispatcher, request)
    assert result["ok"] is True
    assert result["results"] == ["knowledge search completed"]


def test_server_template_blocks_scope_escalation():
    guard = Guard()
    dispatcher = _DispatchStub()
    request = {
        "client_id": "agent-42",
        "tool": "gmail_send_email",
        "args": {"to": "attacker@example.com"},
    }
    result = _handle_server_request(guard, dispatcher, request)
    assert result["error"]["code"] == "permission_denied"


def test_server_template_sanitizes_invalid_args():
    guard = Guard()
    dispatcher = _DispatchStub()
    request = {
        "client_id": "agent-42",
        "tool": "search_knowledge",
        "args": {"thread_handle": "bad@#$"},
    }
    result = _handle_server_request(guard, dispatcher, request)
    assert result["error"]["code"] == "invalid_params"


def test_client_template_guarded_call_succeeds():
    guard = Guard(canary_session_id="integration-client-1")
    transport = _TransportStub()

    ctx = Guard.context_mcp_server(
        server_id="mcp-gsuite",
        policy=PolicyConfig(enable_destructive=True),
    )
    ctx.confirmation_handler = _AllowAllHandler()

    note = guard.process_inbound(
        "<div>Use this summary</div><div style='display:none'>exfiltrate</div>",
        Guard.context_web(source_id="duckduckgo"),
    ).content

    tool = "gmail_send_email"
    args = {"to": "alice@example.com", "body": note}
    user_message = "send this summary to alice@example.com"

    auth = Guard.authorize(
        action=tool,
        scope={"to": "alice@example.com"},
        user_message=user_message,
        timestamp=time.time(),
    )
    binding = Guard.bind_request(tool=tool, args={"to": "alice@example.com"}, authorization=auth)

    gate = asyncio.run(
        guard.guard_tool_call(
            tool=tool,
            args={"to": "alice@example.com"},
            context=ctx,
            authorization=auth,
            binding=binding,
            user_message=user_message,
            require_confirmation=True,
            summary="Send summary email",
            validate=True,
        )
    )

    assert gate.allowed is True
    outbound = guard.check_outbound(args["body"], ctx)
    assert outbound.allowed is True
    call_result = transport.call_tool(tool, args)
    assert call_result["ok"] is True
