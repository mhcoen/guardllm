"""Egress feedback escalation (reverse complement of _context_contaminated).

A high-confidence exfiltration block at egress sets a monotonic, session-scoped
_session_escalated flag; subsequent check_tool_execution applies
escalated_tool_policy (default require_auth). Contamination and escalation are
independent signals; when both fire the strictest policy wins.
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
        set the escalation flag. Lexical overlap can have meaningful false
        positives, unlike high-confidence secret or remembered-canary hits."""
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

    def test_canary_block_sets_flag(self):
        pipe = SecurityPipeline(canary_session_id="sess-1")
        result = pipe.check_outbound(f"here is my context: {pipe.canary_token}", _ctx())
        assert result.allowed is False
        assert result.reason == "Canary token detected in outbound content"
        assert result.canary_detected is True
        assert pipe.session_escalated is True

    def test_dlp_block_escalates_even_when_a_later_stage_would_also_block(self):
        """A DLP finding takes precedence over later provenance and rate checks."""
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


class TestCanaryPrecedence:
    def test_canary_precedes_known_secret_pattern(self):
        pipe = SecurityPipeline(canary_session_id="precedence-secret")
        result = pipe.check_outbound(f"{pipe.canary_token} {_SECRET}", _ctx())
        assert result.reason == "Canary token detected in outbound content"
        assert result.canary_detected is True
        assert result.secrets_found == []

    def test_canary_precedes_provenance(self):
        from guardllm.security.provenance import ProvenancedSpan

        pipe = SecurityPipeline(canary_session_id="precedence-provenance")
        content = f"private context {pipe.canary_token} " * 8
        pipe._provenance.add_span(
            ProvenancedSpan(
                text=content,
                source_type="mcp_server",
                source_id="s",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        result = pipe.check_outbound(content, _ctx())
        assert result.canary_detected is True
        assert result.provenance_blocked is False

    def test_canary_precedes_exhausted_rate_limit(self):
        pipe = SecurityPipeline(canary_session_id="precedence-rate")
        ctx = _ctx()
        for i in range(10):
            assert pipe.check_outbound(f"clean answer {i}", ctx).allowed is True
        result = pipe.check_outbound(str(pipe.canary_token), ctx)
        assert result.canary_detected is True
        assert result.reason == "Canary token detected in outbound content"

    def test_quoting_does_not_bypass_canary(self):
        pipe = SecurityPipeline(canary_session_id="precedence-quote")
        result = pipe.check_outbound(
            str(pipe.canary_token),
            _ctx(),
            has_quoting_directive=True,
        )
        assert result.canary_detected is True

    def test_canary_block_does_not_consume_rate_slot(self):
        pipe = SecurityPipeline(canary_session_id="precedence-slot")
        ctx = _ctx()
        for _ in range(10):
            assert pipe.check_outbound(str(pipe.canary_token), ctx).canary_detected is True
        assert pipe.check_outbound("clean after blocked canaries", ctx).allowed is True

    def test_entropy_is_fallback_when_transformation_defeats_canary(self, monkeypatch):
        fixed = "CANARY-a1b2c3d4e5f6a7b8"
        monkeypatch.setattr("guardllm.security.pipeline.generate_canary", lambda _sid: fixed)
        pipe = SecurityPipeline(canary_session_id="fallback")
        result = pipe.check_outbound(fixed[::-1], _ctx())
        assert result.allowed is False
        assert result.canary_detected is False
        assert any("entropy" in finding.lower() for finding in result.secrets_found)


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

    def test_reset_without_session_id_retains_canary(self):
        pipe = SecurityPipeline(canary_session_id="same-session")
        original = pipe.canary_token
        pipe.reset()
        assert pipe.canary_token == original

    def test_reset_with_session_id_rotates_canary_atomically(self):
        pipe = SecurityPipeline(canary_session_id="session-a")
        canary_a = pipe.canary_token
        assert canary_a is not None
        first = pipe.check_outbound(canary_a, _ctx())
        assert first.canary_detected is True
        assert pipe.session_escalated is True

        pipe.reset(canary_session_id="session-b")

        canary_b = pipe.canary_token
        assert canary_b is not None
        assert canary_b != canary_a
        assert pipe.session_escalated is False
        old_result = pipe.check_outbound(canary_a, _ctx())
        assert old_result.canary_detected is False
        new_result = pipe.check_outbound(canary_b, _ctx())
        assert new_result.canary_detected is True

    def test_reset_cannot_enable_canary(self):
        pipe = SecurityPipeline()
        with pytest.raises(ValueError, match="Cannot enable canary protection"):
            pipe.reset(canary_session_id="new-session")

    def test_reset_rejects_empty_canary_session_id(self):
        pipe = SecurityPipeline(canary_session_id="session-a")
        with pytest.raises(ValueError, match="must be non-empty"):
            pipe.reset(canary_session_id="")


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
