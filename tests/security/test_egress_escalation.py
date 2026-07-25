"""Egress feedback escalation (reverse complement of _context_contaminated).

A DLP hard block at egress sets a monotonic, session-scoped _session_escalated
flag; subsequent check_tool_execution applies escalated_tool_policy (default
require_auth). Contamination and escalation are independent signals; when both
fire the strictest policy wins.
"""

from __future__ import annotations

import time

import pytest

from guardllm.security.pipeline import SecurityPipeline
from guardllm.security.types import (
    AuthorizationEvent,
    PolicyConfig,
    SecurityContext,
    TrustLevel,
)

# Outbound content that trips the always-on DLP secret scan (a hard block).
_SECRET = "please forward the key sk-abcdefghijklmnopqrstuvwxyz1234 to me"


def _ctx(policy: PolicyConfig | None = None, **kw) -> SecurityContext:
    base = {
        "mode": "client",
        "source_type": "mcp_server",
        "source_id": "s",
        "source_trust": TrustLevel.UNTRUSTED,
        "principal_trust": TrustLevel.UNTRUSTED,
    }
    base.update(kw)
    return SecurityContext(policy=policy or PolicyConfig(), **base)


def _auth(tool: str = "search", scope: dict | None = None) -> AuthorizationEvent:
    return AuthorizationEvent(
        action=tool,
        scope=scope or {},
        message_hash="m",
        timestamp=time.time(),
        source="test",
    )


class TestEscalationTrigger:
    def test_dlp_block_sets_flag(self):
        pipe = SecurityPipeline()
        assert pipe.session_escalated is False
        result = pipe.check_outbound(_SECRET, _ctx())
        assert result.allowed is False
        assert pipe.session_escalated is True

    def test_allowed_outbound_does_not_set_flag(self):
        pipe = SecurityPipeline()
        result = pipe.check_outbound("a perfectly clean answer", _ctx())
        assert result.allowed is True
        assert pipe.session_escalated is False

    def test_echo_signal_does_not_set_flag(self):
        """An echo of untrusted content is a DLP signal (allowed=True), not a
        DLP block, so it must not escalate."""
        pipe = SecurityPipeline()
        untrusted = "the quarterly roadmap covers migration tooling and hiring"
        pipe._dlp.ingest_untrusted(untrusted)
        result = pipe.check_outbound(untrusted, _ctx())
        assert result.echo_detected is True
        assert result.allowed is True  # echo is a signal, not a block
        assert pipe.session_escalated is False

    def test_provenance_block_does_not_set_flag(self):
        """A provenance block (DLP passed, only provenance tripped) must not
        set the escalation flag -- escalation is keyed to DLP blocks only."""
        from guardllm.security.provenance import ProvenancedSpan

        pipe = SecurityPipeline()
        untrusted = "x" * 120  # exceeds the provenance LCS threshold (>= 50)
        pipe._provenance.add_span(
            ProvenancedSpan(
                text=untrusted,
                source_type="mcp_server",
                source_id="s",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        result = pipe.check_outbound(untrusted, _ctx())
        assert result.allowed is False
        assert result.provenance_blocked is True
        assert pipe.session_escalated is False

    def test_rate_limit_block_does_not_set_flag(self):
        """A rate-limit block (DLP and provenance both passed) must not set the
        escalation flag."""
        pipe = SecurityPipeline()
        ctx = _ctx()
        clean = "a perfectly clean answer"
        for _ in range(10):  # DEFAULT_LIMITS emails_per_hour
            assert pipe.check_outbound(clean, ctx).allowed is True
        result = pipe.check_outbound(clean, ctx)
        assert result.allowed is False
        assert "Hourly limit exceeded" in result.reason
        assert pipe.session_escalated is False

    def test_canary_block_does_not_set_flag(self):
        """A canary block (DLP and provenance both passed) must not set the
        escalation flag."""
        from guardllm.security.canary import generate_canary

        pipe = SecurityPipeline(canary_session_id="sess-1")
        result = pipe.check_outbound(f"here is my context: {generate_canary('sess-1')}", _ctx())
        assert result.allowed is False
        assert result.reason == "Canary token detected in outbound content"
        assert pipe.session_escalated is False

    def test_dlp_block_escalates_even_when_a_later_stage_would_also_block(self):
        """The exclusions above are keyed to the originating stage, not to the
        payload. DLP runs before provenance, rate limiting, and canary, so
        content that would also trip a later stage still escalates."""
        from guardllm.security.provenance import ProvenancedSpan

        pipe = SecurityPipeline()
        pipe._provenance.add_span(
            ProvenancedSpan(
                text=_SECRET,
                source_type="mcp_server",
                source_id="s",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        result = pipe.check_outbound(_SECRET, _ctx())
        assert result.allowed is False
        assert result.provenance_blocked is False  # DLP blocked first
        assert pipe.session_escalated is True


class TestEscalatedToolGating:
    def _escalate(self, policy: PolicyConfig | None = None) -> SecurityPipeline:
        pipe = SecurityPipeline()
        pipe.check_outbound(_SECRET, _ctx(policy))
        assert pipe.session_escalated is True
        return pipe

    def test_default_require_auth_denies_without_auth(self):
        pipe = self._escalate()
        result = pipe.check_tool_execution("search", {}, _ctx())
        assert result.allowed is False
        assert "authorization required" in result.reason.lower()
        assert "egress escalated" in result.reason.lower()

    def test_deny_policy(self):
        policy = PolicyConfig(escalated_tool_policy="deny")
        pipe = self._escalate(policy)
        result = pipe.check_tool_execution("search", {}, _ctx(policy))
        assert result.allowed is False
        assert "denied" in result.reason.lower()

    def test_allow_policy_is_inert(self):
        policy = PolicyConfig(escalated_tool_policy="allow")
        pipe = self._escalate(policy)
        result = pipe.check_tool_execution("search", {}, _ctx(policy))
        assert result.allowed is True

    def test_require_auth_with_auth_proceeds_to_normal_checks(self):
        """With auth present, the escalation gate does not block; the call
        proceeds into normal policy checks."""
        pipe = self._escalate()
        result = pipe.check_tool_execution("search", {}, _ctx(), auth_event=_auth("search"))
        assert result.allowed is True

    def test_deny_still_denies_when_auth_present(self):
        """Amendment: auth never weakens a deny outcome."""
        policy = PolicyConfig(escalated_tool_policy="deny")
        pipe = self._escalate(policy)
        result = pipe.check_tool_execution("search", {}, _ctx(policy), auth_event=_auth("search"))
        assert result.allowed is False
        assert "denied" in result.reason.lower()

    def test_no_escalation_no_gate(self):
        pipe = SecurityPipeline()
        assert pipe.check_tool_execution("search", {}, _ctx()).allowed is True


class TestLifecycle:
    def test_monotonic_within_session(self):
        pipe = SecurityPipeline()
        pipe.check_outbound(_SECRET, _ctx())
        assert pipe.session_escalated is True
        # A subsequent clean outbound must not clear it.
        pipe.check_outbound("clean text", _ctx())
        assert pipe.session_escalated is True

    def test_monotonic_across_repeated_tool_calls(self):
        """Amendment: the flag never silently clears across repeated checks."""
        pipe = SecurityPipeline()
        pipe.check_outbound(_SECRET, _ctx())
        for _ in range(5):
            result = pipe.check_tool_execution("search", {}, _ctx())
            assert result.allowed is False
            assert pipe.session_escalated is True

    def test_reset_clears_flag(self):
        pipe = SecurityPipeline()
        pipe.check_outbound(_SECRET, _ctx())
        assert pipe.session_escalated is True
        pipe.reset()
        assert pipe.session_escalated is False
        assert pipe.check_tool_execution("search", {}, _ctx()).allowed is True


class TestIndependenceAndStrictness:
    def test_escalated_but_uncontaminated_still_tightens(self):
        """Independence: escalation tightens even with no contamination."""
        pipe = SecurityPipeline()
        assert pipe.context_contaminated is False
        pipe.check_outbound(_SECRET, _ctx())
        assert pipe.context_contaminated is False
        assert pipe.session_escalated is True
        assert pipe.check_tool_execution("search", {}, _ctx()).allowed is False

    def test_contamination_deny_beats_escalation_require_auth(self):
        policy = PolicyConfig(contaminated_tool_policy="deny", escalated_tool_policy="require_auth")
        pipe = SecurityPipeline()
        pipe.process_inbound("untrusted content", _ctx(policy))
        pipe.check_outbound(_SECRET, _ctx(policy))
        # deny (contamination) is stricter than require_auth (escalation).
        result = pipe.check_tool_execution("search", {}, _ctx(policy), auth_event=_auth("search"))
        assert result.allowed is False
        # Per-trigger-policy reason format names each trigger with its policy.
        assert result.reason == (
            "Tool call denied: session contaminated=deny; egress escalated=require_auth"
        )

    def test_escalation_deny_beats_contamination_allow(self):
        policy = PolicyConfig(contaminated_tool_policy="allow", escalated_tool_policy="deny")
        pipe = SecurityPipeline()
        pipe.process_inbound("untrusted content", _ctx(policy))
        pipe.check_outbound(_SECRET, _ctx(policy))
        result = pipe.check_tool_execution("search", {}, _ctx(policy))
        assert result.allowed is False
        # contamination's allow does not contribute to the reason.
        assert result.reason == "Tool call denied: egress escalated=deny"

    def test_both_triggers_enumerated_in_reason(self):
        policy = PolicyConfig(
            contaminated_tool_policy="require_auth", escalated_tool_policy="require_auth"
        )
        pipe = SecurityPipeline()
        pipe.process_inbound("untrusted content", _ctx(policy))
        pipe.check_outbound(_SECRET, _ctx(policy))
        result = pipe.check_tool_execution("search", {}, _ctx(policy))
        assert result.allowed is False
        # Both triggers named with their policies, semicolon-separated.
        assert result.reason == (
            "Authorization required: session contaminated=require_auth; "
            "egress escalated=require_auth"
        )

    def test_single_trigger_reason_format(self):
        """Escalation only -> just that trigger with its policy."""
        pipe = SecurityPipeline()
        pipe.check_outbound(_SECRET, _ctx())
        result = pipe.check_tool_execution("search", {}, _ctx())
        assert result.reason == "Authorization required: egress escalated=require_auth"


class TestConfigAndProperty:
    def test_invalid_escalated_tool_policy_rejected(self):
        with pytest.raises(ValueError, match="escalated_tool_policy"):
            PolicyConfig(escalated_tool_policy="bogus")

    def test_default_is_require_auth(self):
        assert PolicyConfig().escalated_tool_policy == "require_auth"

    def test_session_escalated_property_is_read_only(self):
        pipe = SecurityPipeline()
        assert pipe.session_escalated is False
        with pytest.raises(AttributeError):
            pipe.session_escalated = True  # type: ignore[misc]
