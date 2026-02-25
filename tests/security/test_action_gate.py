"""Tests for MCP security ActionGate."""

import asyncio

import pytest

from guardllm.security.action_gate import ActionGate, ActionProposal
from guardllm.security.types import (
    ConfirmationHandler,
    SecurityContext,
    TrustLevel,
)


@pytest.fixture
def gate():
    return ActionGate()


@pytest.fixture
def ctx():
    return SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="server-1",
    )


@pytest.fixture
def proposal():
    return ActionProposal(
        tool_name="gmail_send_email",
        args={"to": "alice@example.com", "body": "Hello Alice"},
        summary="Send email to alice@example.com",
        context={"conversation_topic": "meeting follow-up"},
    )


# ---------------------------------------------------------------------------
# ActionProposal dataclass
# ---------------------------------------------------------------------------


class TestActionProposal:
    def test_creates_with_all_fields(self):
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "alice@test.com"},
            summary="Send email",
            context={"topic": "test"},
            heightened_scrutiny=True,
        )
        assert proposal.tool_name == "gmail_send_email"
        assert proposal.args == {"to": "alice@test.com"}
        assert proposal.summary == "Send email"
        assert proposal.context == {"topic": "test"}
        assert proposal.heightened_scrutiny is True

    def test_heightened_scrutiny_defaults_false(self):
        proposal = ActionProposal(
            tool_name="tool",
            args={},
            summary="summary",
            context={},
        )
        assert proposal.heightened_scrutiny is False


# ---------------------------------------------------------------------------
# ActionGate.confirm
# ---------------------------------------------------------------------------


class _AcceptingHandler(ConfirmationHandler):
    """Always confirms."""
    def __init__(self):
        self.last_tool = None
        self.last_args = None
        self.last_context = None

    async def confirm(self, tool, args, context):
        self.last_tool = tool
        self.last_args = args
        self.last_context = context
        return True


class _DenyingHandler(ConfirmationHandler):
    """Always denies."""
    async def confirm(self, tool, args, context):
        return False


class TestActionGate:
    def test_no_handler_denies(self, gate, proposal, ctx):
        """Without a confirmation handler, deny by default."""
        result = asyncio.run(gate.confirm(proposal, ctx))
        assert result is False

    def test_accepting_handler_confirms(self, gate, proposal):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        result = asyncio.run(gate.confirm(proposal, ctx))
        assert result is True

    def test_denying_handler_denies(self, gate, proposal):
        handler = _DenyingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        result = asyncio.run(gate.confirm(proposal, ctx))
        assert result is False

    def test_handler_receives_tool_and_args(self, gate, proposal):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_tool == "gmail_send_email"
        assert handler.last_args == {"to": "alice@example.com", "body": "Hello Alice"}

    def test_handler_receives_context_with_summary(self, gate, proposal):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_context["summary"] == "Send email to alice@example.com"

    def test_handler_receives_heightened_scrutiny(self, gate):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "bob@test.com"},
            summary="Send with scrutiny",
            context={"class_hiding_possible": True},
            heightened_scrutiny=True,
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_context["heightened_scrutiny"] is True

    def test_handler_receives_proposal_context_fields(self, gate):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        proposal = ActionProposal(
            tool_name="tool",
            args={},
            summary="summary",
            context={"custom_field": "value123"},
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_context["custom_field"] == "value123"

    def test_server_mode_no_handler_denies(self, gate, proposal):
        ctx = SecurityContext(
            mode="server",
            source_type="mcp_client",
            source_id="client-1",
        )
        result = asyncio.run(gate.confirm(proposal, ctx))
        assert result is False


# ---------------------------------------------------------------------------
# confirm_all_below (Phase 2)
# ---------------------------------------------------------------------------


class TestConfirmAllBelow:
    """Phase 2: confirm_all_below requires confirmation for all tools
    when principal_trust <= the configured threshold."""

    def test_requires_confirmation_below_threshold(self, gate, proposal):
        """UNTRUSTED principal requires confirmation when threshold is UNTRUSTED."""
        from guardllm.security.types import PolicyConfig
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.UNTRUSTED),
        )
        assert gate.requires_confirmation(proposal, ctx) is True

    def test_requires_confirmation_at_semi_trusted(self, gate, proposal):
        """SEMI_TRUSTED principal requires confirmation when threshold is SEMI_TRUSTED."""
        from guardllm.security.types import PolicyConfig
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.SEMI_TRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.SEMI_TRUSTED),
        )
        assert gate.requires_confirmation(proposal, ctx) is True

    def test_untrusted_requires_when_threshold_semi_trusted(self, gate, proposal):
        """UNTRUSTED (below SEMI_TRUSTED) requires confirmation."""
        from guardllm.security.types import PolicyConfig
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.SEMI_TRUSTED),
        )
        assert gate.requires_confirmation(proposal, ctx) is True

    def test_trusted_skips_when_threshold_semi_trusted(self, gate, proposal):
        """TRUSTED (above SEMI_TRUSTED) does not require confirmation."""
        from guardllm.security.types import PolicyConfig
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            source_trust=TrustLevel.TRUSTED,
            principal_trust=TrustLevel.TRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.SEMI_TRUSTED),
        )
        assert gate.requires_confirmation(proposal, ctx) is False

    def test_no_threshold_no_confirmation_required(self, gate, proposal):
        """Without confirm_all_below, no trust-gated confirmation."""
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.UNTRUSTED,
        )
        assert gate.requires_confirmation(proposal, ctx) is False

    def test_confirm_passes_trust_gated_flag_to_handler(self, gate, proposal):
        """confirm() passes trust_gated_confirmation context to handler."""
        from guardllm.security.types import PolicyConfig
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.UNTRUSTED),
            confirmation_handler=handler,
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_context.get("trust_gated_confirmation") is True

    def test_web_derived_independent_of_confirm_all_below(self, gate, proposal):
        """Web-derived warning is additive, not gated by confirm_all_below."""
        from guardllm.security.types import PolicyConfig
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            source_trust=TrustLevel.TRUSTED,
            principal_trust=TrustLevel.TRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.SEMI_TRUSTED),
        )
        # TRUSTED principal, above threshold, but web_derived still triggers
        assert gate.requires_confirmation(
            proposal, ctx, context_has_web_derived=True
        ) is True
