from __future__ import annotations

import asyncio
import time

from guardllm import Guard
from guardllm.security.audit import AuditLogger
from guardllm.security.error_sanitizer import PermissionDeniedError
from guardllm.security.types import PolicyConfig


def test_authorize_uses_user_message_hash():
    event = Guard.authorize(
        action="gmail_send_email",
        scope={"to": "alice@example.com"},
        user_message="send email to alice",
        source="unit_test",
    )
    assert event.message_hash == Guard.hash_message("send email to alice")
    assert event.source == "unit_test"


def test_context_builders():
    ctx_web = Guard.context_web(source_id="duckduckgo")
    assert ctx_web.source_type == "web_content"
    ctx_doc = Guard.context_document(document_id="doc-123")
    assert ctx_doc.source_id == "doc-123"


def test_end_to_end_tool_flow_with_binding():
    guard = Guard()
    client_ctx = Guard.context_mcp_server(
        server_id="server-1",
        policy=PolicyConfig(enable_destructive=True),
    )
    tool = "gmail_send_email"
    args = {"to": "alice@example.com"}
    user_message = "send email to alice@example.com"

    auth = Guard.authorize(
        action=tool,
        scope={"to": "alice@example.com"},
        user_message=user_message,
        timestamp=time.time(),
    )
    binding = Guard.bind_request(
        tool=tool,
        args=args,
        authorization=auth,
    )

    result = guard.check_tool_call(
        tool=tool,
        args=args,
        context=client_ctx,
        authorization=auth,
        binding=binding,
        user_message=user_message,
    )
    assert result.allowed is True


def test_inbound_and_outbound():
    guard = Guard(canary_session_id="s1")
    ctx = Guard.context_web(source_id="web")
    processed = guard.process_inbound("<div>hello</div>", ctx)
    assert "hello" in processed.content
    outbound = guard.check_outbound("clean answer", ctx)
    assert outbound.allowed is True


def test_validate_tool_args_failure():
    guard = Guard()
    validation = guard.validate_tool_args("tool_x", {"thread_handle": "bad@#$"})
    assert validation.valid is False
    assert validation.field_name == "thread_handle"


def test_sanitize_exception_wrapper():
    guard = Guard()
    payload = guard.sanitize_exception(PermissionDeniedError("blocked"))
    assert payload["error"]["code"] == "permission_denied"


def test_audit_logger_receives_events():
    audit = AuditLogger()
    guard = Guard(audit_logger=audit)
    ctx = Guard.context_web(source_id="web")
    guard.process_inbound("<div>hello</div>", ctx)
    events = audit.get_events(limit=10)
    assert any(e["event_type"] == "inbound_processed" for e in events)


class _AcceptAllHandler:
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        return True


def test_guard_tool_call_with_confirmation():
    guard = Guard()
    ctx = Guard.context_mcp_server(
        server_id="server-1",
        policy=PolicyConfig(enable_destructive=True),
    )
    ctx.confirmation_handler = _AcceptAllHandler()
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

    result = asyncio.run(
        guard.guard_tool_call(
            tool=tool,
            args=args,
            context=ctx,
            authorization=auth,
            binding=binding,
            user_message=user_message,
            require_confirmation=True,
            summary="Send email to alice@example.com",
            context_has_web_derived=True,
        )
    )
    assert result.allowed is True
