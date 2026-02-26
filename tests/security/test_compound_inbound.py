"""Tests for Guard.process_inbound_compound (compound ingress).

Covers:
- Basic: two trusted spans, both get ALLOW extraction
- Forwarded-from-external: trusted envelope + untrusted payload, contamination set
- All untrusted: both blocked by source gate, contamination set
- Single span: behaves identically to regular process_inbound
- compound_id carried through to audit
"""

from __future__ import annotations

from guardllm import Guard
from guardllm.security.audit import AuditLogger
from guardllm.security.source_gate import check_extraction_allowed
from guardllm.security.types import (
    ContentType,
    ExtractionPolicy,
    PolicyConfig,
    SecurityContext,
    TrustLevel,
)


def _trusted_user_ctx() -> SecurityContext:
    """Trusted user_input context (source gate: ALLOW)."""
    return SecurityContext(
        mode="client",
        source_type="user_input",
        source_id="user-1",
        source_trust=TrustLevel.TRUSTED,
    )


def _untrusted_email_ctx() -> SecurityContext:
    """Untrusted email_content context (source gate: BLOCK)."""
    return SecurityContext(
        mode="client",
        source_type="email_content",
        source_id="email-fwd-1",
        source_trust=TrustLevel.UNTRUSTED,
    )


def _untrusted_web_ctx() -> SecurityContext:
    """Untrusted web_content context (source gate: BLOCK)."""
    return SecurityContext(
        mode="client",
        source_type="web_content",
        source_id="web-1",
        source_trust=TrustLevel.UNTRUSTED,
    )


class TestCompoundBasicTrusted:
    """Two trusted spans: both get ALLOW extraction, no contamination."""

    def test_both_trusted_no_contamination(self):
        guard = Guard()
        ctx1 = _trusted_user_ctx()
        ctx2 = SecurityContext(
            mode="client",
            source_type="assistant_response",
            source_id="assistant-1",
            source_trust=TrustLevel.TRUSTED,
        )
        results = guard.process_inbound_compound([
            ("Hello from the user", ctx1),
            ("Response from assistant", ctx2),
        ])
        assert len(results) == 2
        assert "Hello from the user" in results[0].content
        assert "Response from assistant" in results[1].content
        # Neither span is untrusted, so no isolation wrapping
        assert results[0].isolated is False
        assert results[1].isolated is False
        # Session should not be contaminated
        assert guard._pipeline.context_contaminated is False

    def test_both_trusted_extraction_allowed(self):
        """Source gate returns ALLOW for both trusted spans."""
        ctx1 = _trusted_user_ctx()
        ctx2 = SecurityContext(
            mode="client",
            source_type="assistant_response",
            source_id="assistant-1",
            source_trust=TrustLevel.TRUSTED,
        )
        gate1 = check_extraction_allowed(ctx1.source_type, ctx1.source_id)
        gate2 = check_extraction_allowed(ctx2.source_type, ctx2.source_id)
        assert gate1.policy == ExtractionPolicy.ALLOW
        assert gate2.policy == ExtractionPolicy.ALLOW


class TestCompoundForwardedFromExternal:
    """Trusted envelope + untrusted forwarded payload."""

    def test_contamination_set(self):
        """Untrusted span sets session contamination flag."""
        guard = Guard()
        ctx_envelope = _trusted_user_ctx()
        ctx_payload = _untrusted_email_ctx()

        results = guard.process_inbound_compound([
            ("From: alice@corp.com\nSubject: FYI", ctx_envelope),
            ("Hey, check out http://evil.com/phish", ctx_payload),
        ])
        assert len(results) == 2
        # Trusted envelope is not isolated
        assert results[0].isolated is False
        # Untrusted payload is isolated (wrapped in untrusted_content tags)
        assert results[1].isolated is True
        # Session is contaminated because of the untrusted span
        assert guard._pipeline.context_contaminated is True

    def test_extraction_policy_per_span(self):
        """Source gate evaluates independently: envelope ALLOW, payload BLOCK."""
        ctx_envelope = _trusted_user_ctx()
        ctx_payload = _untrusted_email_ctx()

        gate_envelope = check_extraction_allowed(
            ctx_envelope.source_type, ctx_envelope.source_id,
        )
        gate_payload = check_extraction_allowed(
            ctx_payload.source_type, ctx_payload.source_id,
        )
        assert gate_envelope.policy == ExtractionPolicy.ALLOW
        assert gate_payload.policy == ExtractionPolicy.BLOCK

    def test_contamination_widens_egress(self):
        """After compound ingress with untrusted span, outbound DLP is widened."""
        guard = Guard()
        ctx_envelope = _trusted_user_ctx()
        ctx_payload = _untrusted_email_ctx()

        guard.process_inbound_compound([
            ("Envelope text", ctx_envelope),
            ("Secret payload with sensitive data", ctx_payload),
        ])
        # Now check outbound: trying to echo the untrusted content should be blocked
        outbound = guard.check_outbound(
            "Secret payload with sensitive data",
            ctx_envelope,
        )
        assert outbound.allowed is False


class TestCompoundAllUntrusted:
    """Two untrusted spans: both isolated, contamination set."""

    def test_both_untrusted_both_isolated(self):
        guard = Guard()
        ctx1 = _untrusted_email_ctx()
        ctx2 = _untrusted_web_ctx()

        results = guard.process_inbound_compound([
            ("Email body with instructions", ctx1),
            ("<div>Web content with payload</div>", ctx2),
        ])
        assert len(results) == 2
        assert results[0].isolated is True
        assert results[1].isolated is True
        assert guard._pipeline.context_contaminated is True

    def test_both_blocked_by_source_gate(self):
        """Both source types get BLOCK extraction policy."""
        ctx1 = _untrusted_email_ctx()
        ctx2 = _untrusted_web_ctx()

        gate1 = check_extraction_allowed(ctx1.source_type, ctx1.source_id)
        gate2 = check_extraction_allowed(ctx2.source_type, ctx2.source_id)
        assert gate1.policy == ExtractionPolicy.BLOCK
        assert gate2.policy == ExtractionPolicy.BLOCK


class TestCompoundSingleSpan:
    """Single-span compound call behaves identically to regular process_inbound."""

    def test_single_span_matches_regular(self):
        guard1 = Guard()
        guard2 = Guard()
        ctx = _untrusted_web_ctx()
        content = "<b>Hello world</b>"

        regular = guard1.process_inbound(content, ctx)
        compound = guard2.process_inbound_compound([(content, ctx)])

        assert len(compound) == 1
        assert compound[0].content == regular.content
        assert compound[0].isolated == regular.isolated
        assert compound[0].source_type == regular.source_type
        assert compound[0].source_id == regular.source_id
        assert guard1._pipeline.context_contaminated == guard2._pipeline.context_contaminated

    def test_single_trusted_span(self):
        guard = Guard()
        ctx = _trusted_user_ctx()
        results = guard.process_inbound_compound([("User says hello", ctx)])
        assert len(results) == 1
        assert results[0].isolated is False
        assert guard._pipeline.context_contaminated is False


class TestCompoundId:
    """compound_id is carried through to audit events."""

    def test_explicit_compound_id_in_audit(self):
        audit = AuditLogger()
        guard = Guard(audit_logger=audit)
        ctx = _trusted_user_ctx()

        guard.process_inbound_compound(
            [("Span A", ctx), ("Span B", ctx)],
            compound_id="test-compound-42",
        )

        events = audit.get_events(limit=50)
        compound_events = [
            e for e in events
            if e["event_type"] == "compound_inbound_processed"
        ]
        assert len(compound_events) == 1
        assert compound_events[0]["request_id"] == "test-compound-42"
        assert "2 spans" in compound_events[0]["action_summary"]

    def test_generated_compound_id_in_audit(self):
        """When compound_id is None, a hash-based ID is generated."""
        audit = AuditLogger()
        guard = Guard(audit_logger=audit)
        ctx = _trusted_user_ctx()

        guard.process_inbound_compound([("Content A", ctx)])

        events = audit.get_events(limit=50)
        compound_events = [
            e for e in events
            if e["event_type"] == "compound_inbound_processed"
        ]
        assert len(compound_events) == 1
        # Generated ID is a 16-char hex string
        generated_id = compound_events[0]["request_id"]
        assert isinstance(generated_id, str)
        assert len(generated_id) == 16
        assert all(c in "0123456789abcdef" for c in generated_id)

    def test_per_span_audit_events_also_emitted(self):
        """Each span emits its own inbound_processed audit event."""
        audit = AuditLogger()
        guard = Guard(audit_logger=audit)
        ctx1 = _trusted_user_ctx()
        ctx2 = _untrusted_email_ctx()

        guard.process_inbound_compound([
            ("Span A", ctx1),
            ("Span B", ctx2),
        ])

        events = audit.get_events(limit=50)
        inbound_events = [
            e for e in events if e["event_type"] == "inbound_processed"
        ]
        compound_events = [
            e for e in events
            if e["event_type"] == "compound_inbound_processed"
        ]
        # Two per-span events plus one compound summary
        assert len(inbound_events) == 2
        assert len(compound_events) == 1


class TestCompoundContaminationAggregation:
    """Contamination is OR'd across spans: any untrusted span contaminates the session."""

    def test_first_trusted_second_untrusted(self):
        """Processing trusted first, then untrusted, still contaminates."""
        guard = Guard()
        ctx_trusted = _trusted_user_ctx()
        ctx_untrusted = _untrusted_web_ctx()

        # Before compound: not contaminated
        assert guard._pipeline.context_contaminated is False

        guard.process_inbound_compound([
            ("Trusted content", ctx_trusted),
            ("Untrusted web content", ctx_untrusted),
        ])
        assert guard._pipeline.context_contaminated is True

    def test_first_untrusted_second_trusted(self):
        """Processing untrusted first, then trusted, still contaminated."""
        guard = Guard()
        ctx_untrusted = _untrusted_email_ctx()
        ctx_trusted = _trusted_user_ctx()

        guard.process_inbound_compound([
            ("Untrusted email", ctx_untrusted),
            ("Trusted user input", ctx_trusted),
        ])
        assert guard._pipeline.context_contaminated is True

    def test_contamination_persists_for_tool_calls(self):
        """Contamination from compound inbound affects tool call policy."""
        guard = Guard()
        ctx_trusted = _trusted_user_ctx()
        ctx_untrusted = _untrusted_web_ctx()

        guard.process_inbound_compound([
            ("Trusted content", ctx_trusted),
            ("Untrusted web content", ctx_untrusted),
        ])

        # With contaminated_tool_policy="deny", tool calls are blocked
        tool_ctx = Guard.context_mcp_server(
            server_id="s1",
            policy=PolicyConfig(contaminated_tool_policy="deny"),
        )
        result = guard.check_tool_call(
            tool="search_knowledge",
            args={"query": "test"},
            context=tool_ctx,
        )
        assert result.allowed is False
        assert "contaminated" in result.reason.lower()
