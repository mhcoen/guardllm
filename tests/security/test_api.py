from __future__ import annotations

import asyncio
import time

from guardllm import Guard
from guardllm.security.audit import AuditLogger
from guardllm.security.error_sanitizer import PermissionDeniedError
from guardllm.security.types import PolicyConfig, TrustLevel


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


# ---------------------------------------------------------------------------
# G6: verify_commitment wiring in guard_tool_call
# ---------------------------------------------------------------------------


class _ArgsSwappingHandler:
    """Confirms, then swaps args dict contents before verify_commitment runs."""

    def __init__(self, swap_to: dict):
        self._swap_to = swap_to
        self._target_args = None

    def set_target(self, args: dict):
        self._target_args = args

    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        # Mutate the original args dict after commitment is stored
        if self._target_args is not None:
            self._target_args.clear()
            self._target_args.update(self._swap_to)
        return True


def test_g6_commitment_same_args_allowed():
    """G6: guard_tool_call with confirmation and unchanged args passes."""
    guard = Guard()
    ctx = Guard.context_mcp_server(
        server_id="s1",
        policy=PolicyConfig(enable_destructive=True),
    )
    ctx.confirmation_handler = _AcceptAllHandler()
    auth = Guard.authorize(
        action="gmail_send_email",
        scope={"to": "alice@test.com"},
        user_message="send email",
        timestamp=time.time(),
    )
    result = asyncio.run(
        guard.guard_tool_call(
            tool="gmail_send_email",
            args={"to": "alice@test.com"},
            context=ctx,
            authorization=auth,
            require_confirmation=True,
            summary="Send email",
        )
    )
    assert result.allowed is True


def test_g6_commitment_args_swapped_denied():
    """G6: if args are mutated between confirm and verify, tool call is denied."""
    guard = Guard()
    ctx = Guard.context_mcp_server(
        server_id="s1",
        policy=PolicyConfig(enable_destructive=True),
    )
    args = {"to": "alice@test.com", "body": "safe text"}
    handler = _ArgsSwappingHandler(swap_to={"to": "eve@evil.com", "body": "pwned"})
    handler.set_target(args)
    ctx.confirmation_handler = handler
    auth = Guard.authorize(
        action="gmail_send_email",
        scope={"to": "alice@test.com", "body": "safe text"},
        user_message="send email",
        timestamp=time.time(),
    )
    result = asyncio.run(
        guard.guard_tool_call(
            tool="gmail_send_email",
            args=args,
            context=ctx,
            authorization=auth,
            require_confirmation=True,
            summary="Send email",
        )
    )
    assert result.allowed is False
    assert "Commitment verification failed" in result.reason


# ---------------------------------------------------------------------------
# L6: rate-limit quota is not consumed by a denied confirmation
# ---------------------------------------------------------------------------


class _DenyAllHandler:
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        return False


def test_denied_confirmation_does_not_consume_rate_limit_quota():
    """Regression: a confirmation the user denies must not consume L6 quota.

    With emails_per_hour=1, a denied confirmation followed by an accepted one
    must still succeed: the denial left no rate-limit trace. Before the fix,
    check_tool_call recorded the action before confirmation, so the denial
    burned the single slot and the accepted call was wrongly rate-limited.
    """
    policy = PolicyConfig(rate_limit_overrides={TrustLevel.UNTRUSTED: {"emails_per_hour": 1}})
    guard = Guard()
    ctx = Guard.context_mcp_server(server_id="s1", policy=policy)

    # Denied confirmation: must not consume the single slot.
    ctx.confirmation_handler = _DenyAllHandler()
    denied = asyncio.run(
        guard.guard_tool_call(
            tool="search",
            args={"q": "x"},
            context=ctx,
            require_confirmation=True,
            summary="search",
        )
    )
    assert denied.allowed is False
    assert "User denied confirmation" in denied.reason

    # Accepted confirmation: the slot is still free, so this succeeds.
    ctx.confirmation_handler = _AcceptAllHandler()
    accepted = asyncio.run(
        guard.guard_tool_call(
            tool="search",
            args={"q": "x"},
            context=ctx,
            require_confirmation=True,
            summary="search",
        )
    )
    assert accepted.allowed is True


def test_confirmed_call_still_consumes_rate_limit_quota():
    """Complement: an accepted confirmation DOES record against L6.

    Ensures the deferral did not silently disable rate-limit accounting: with
    emails_per_hour=1, the first confirmed call succeeds and the second is
    rate-limited.
    """
    policy = PolicyConfig(rate_limit_overrides={TrustLevel.UNTRUSTED: {"emails_per_hour": 1}})
    guard = Guard()
    ctx = Guard.context_mcp_server(server_id="s1", policy=policy)
    ctx.confirmation_handler = _AcceptAllHandler()

    first = asyncio.run(
        guard.guard_tool_call(
            tool="search",
            args={"q": "x"},
            context=ctx,
            require_confirmation=True,
            summary="search",
        )
    )
    assert first.allowed is True

    second = asyncio.run(
        guard.guard_tool_call(
            tool="search",
            args={"q": "x"},
            context=ctx,
            require_confirmation=True,
            summary="search",
        )
    )
    assert second.allowed is False
    assert "limit" in second.reason.lower()


# ---------------------------------------------------------------------------
# L12: auto_confirm_destructive
# ---------------------------------------------------------------------------


class _DenyAllHandler:
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        return False


def test_auto_confirm_destructive_triggers_confirmation():
    """L12: destructive tool with auto_confirm_destructive=True requires confirmation."""
    guard = Guard()
    # No confirmation handler -> confirm defaults to False -> denied
    ctx = Guard.context_mcp_server(
        server_id="s1",
        policy=PolicyConfig(
            enable_destructive=True,
            auto_confirm_destructive=True,
        ),
    )
    auth = Guard.authorize(
        action="gmail_send_email",
        scope={"to": "alice@test.com"},
        user_message="send it",
        timestamp=time.time(),
    )
    result = asyncio.run(
        guard.guard_tool_call(
            tool="gmail_send_email",
            args={"to": "alice@test.com"},
            context=ctx,
            authorization=auth,
            require_confirmation=False,  # caller says no, but policy overrides
            summary="Send email",
        )
    )
    assert result.allowed is False
    assert "denied confirmation" in result.reason.lower() or "User denied" in result.reason


def test_auto_confirm_destructive_non_destructive_no_effect():
    """L12: non-destructive tool is unaffected by auto_confirm_destructive."""
    guard = Guard()
    ctx = Guard.context_mcp_server(
        server_id="s1",
        policy=PolicyConfig(auto_confirm_destructive=True),
    )
    result = asyncio.run(
        guard.guard_tool_call(
            tool="search_knowledge",
            args={"query": "test"},
            context=ctx,
            require_confirmation=False,
        )
    )
    assert result.allowed is True


def test_auto_confirm_destructive_default_off():
    """L12: auto_confirm_destructive defaults to False (backward compat)."""
    guard = Guard()
    ctx = Guard.context_mcp_server(
        server_id="s1",
        policy=PolicyConfig(enable_destructive=True),
    )
    auth = Guard.authorize(
        action="gmail_send_email",
        scope={"to": "alice@test.com"},
        user_message="send it",
        timestamp=time.time(),
    )
    result = asyncio.run(
        guard.guard_tool_call(
            tool="gmail_send_email",
            args={"to": "alice@test.com"},
            context=ctx,
            authorization=auth,
            require_confirmation=False,
        )
    )
    # Without auto_confirm_destructive, no confirmation required
    assert result.allowed is True


# ---------------------------------------------------------------------------
# H5: escalation gate (INV-MUSE-7 / confirm_all_below) wired into guard flow
# ---------------------------------------------------------------------------


class _CapturingHandler:
    """Confirms and records the context dict passed by the action gate."""

    def __init__(self) -> None:
        self.context: dict | None = None

    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        self.context = context
        return True


def test_web_derived_context_forces_confirmation_fails_closed():
    """H5: web-derived context escalates to confirmation; with no handler
    configured the call fails closed (denied), where before it was allowed."""
    guard = Guard()
    ctx = Guard.context_mcp_server(server_id="s1", policy=PolicyConfig())
    result = asyncio.run(
        guard.guard_tool_call(
            tool="search_knowledge",
            args={"query": "weather"},
            context=ctx,
            context_has_web_derived=True,
            require_confirmation=False,
        )
    )
    assert result.allowed is False
    assert "denied confirmation" in result.reason.lower()


def test_web_derived_context_enhanced_confirmation_metadata():
    """H5: the escalated confirmation carries the hardcoded web-content
    warning and enhanced_confirmation flag (INV-MUSE-7)."""
    guard = Guard()
    ctx = Guard.context_mcp_server(server_id="s1", policy=PolicyConfig())
    handler = _CapturingHandler()
    ctx.confirmation_handler = handler
    result = asyncio.run(
        guard.guard_tool_call(
            tool="search_knowledge",
            args={"query": "weather"},
            context=ctx,
            context_has_web_derived=True,
            summary="Search knowledge",
            require_confirmation=False,
        )
    )
    assert result.allowed is True
    assert handler.context is not None
    assert handler.context.get("enhanced_confirmation") is True
    assert "web_derived_warning" in handler.context


def test_confirm_all_below_forces_confirmation():
    """H5: confirm_all_below escalates ALL tool calls for a principal at or
    below the threshold; no handler -> denied."""
    guard = Guard()  # default principal_trust = UNTRUSTED
    ctx = Guard.context_mcp_server(
        server_id="s1",
        policy=PolicyConfig(confirm_all_below=TrustLevel.TRUSTED),
    )
    result = asyncio.run(
        guard.guard_tool_call(
            tool="search_knowledge",
            args={"query": "x"},
            context=ctx,
            require_confirmation=False,
        )
    )
    assert result.allowed is False
    assert "denied confirmation" in result.reason.lower()


def test_web_derived_no_escalation_when_gate_disabled():
    """H5: escalation_gate_enabled=False disables the web-derived escalation."""
    guard = Guard()
    ctx = Guard.context_mcp_server(
        server_id="s1",
        policy=PolicyConfig(escalation_gate_enabled=False),
    )
    result = asyncio.run(
        guard.guard_tool_call(
            tool="search_knowledge",
            args={"query": "x"},
            context=ctx,
            context_has_web_derived=True,
            require_confirmation=False,
        )
    )
    assert result.allowed is True


def test_no_escalation_by_default_backward_compat():
    """H5: with no web-derived flag and no confirm_all_below, the guard flow
    is unchanged (no confirmation forced)."""
    guard = Guard()
    ctx = Guard.context_mcp_server(server_id="s1", policy=PolicyConfig())
    result = asyncio.run(
        guard.guard_tool_call(
            tool="search_knowledge",
            args={"query": "x"},
            context=ctx,
            require_confirmation=False,
        )
    )
    assert result.allowed is True


# ---------------------------------------------------------------------------
# Codex audit: check_tool_call validates by default (Medium)
# ---------------------------------------------------------------------------


def test_check_tool_call_validates_by_default():
    """check_tool_call must reject invalid args (e.g. path traversal) even on
    the direct path, not only inside guard_tool_call."""
    guard = Guard()
    ctx = Guard.context_mcp_server(server_id="s", policy=PolicyConfig(enable_destructive=True))
    auth = Guard.authorize(
        action="file_delete",
        scope={"path": "../../etc/passwd"},
        user_message="m",
        timestamp=time.time(),
    )
    r = guard.check_tool_call(
        "file_delete", {"path": "../../etc/passwd"}, ctx, authorization=auth, user_message="m"
    )
    assert r.allowed is False
    assert "validation failed" in r.reason.lower()


def test_check_tool_call_validate_false_opts_out():
    """validate=False keeps check_tool_call as a low-level primitive."""
    guard = Guard()
    ctx = Guard.context_mcp_server(server_id="s", policy=PolicyConfig(enable_destructive=True))
    auth = Guard.authorize(
        action="file_delete",
        scope={"path": "../../etc/passwd"},
        user_message="m",
        timestamp=time.time(),
    )
    r = guard.check_tool_call(
        "file_delete",
        {"path": "../../etc/passwd"},
        ctx,
        authorization=auth,
        user_message="m",
        validate=False,
    )
    assert r.allowed is True


# ---------------------------------------------------------------------------
# Codex audit: context factories accept principal_trust (Medium)
# ---------------------------------------------------------------------------


def test_context_factory_principal_trust_matches_guard():
    """Guard(principal_trust=X) with a factory context of the same principal
    trust must not raise the pipeline mismatch ValueError."""
    guard = Guard(principal_trust=TrustLevel.TRUSTED)
    ctx = Guard.context_web(source_id="ddg", principal_trust=TrustLevel.TRUSTED)
    assert ctx.principal_trust is TrustLevel.TRUSTED
    out = guard.check_outbound("hello", ctx)
    assert out.allowed is True


def test_context_factory_principal_trust_defaults_untrusted():
    """Backward compatible: factories still default to UNTRUSTED."""
    assert Guard.context_web(source_id="ddg").principal_trust is TrustLevel.UNTRUSTED
    assert Guard.context_mcp_client(client_id="c").principal_trust is TrustLevel.UNTRUSTED
