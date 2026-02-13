from __future__ import annotations

import time

from guardllm import Guard
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
