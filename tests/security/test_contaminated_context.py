"""Tests for contaminated-context egress control.

Validates that once untrusted content enters a session, egress checks
expand to cover sensitive content, blocking verbatim/near-verbatim
exfiltration of trusted-sensitive material.
"""

from vordur import Guard
from vordur.security.pipeline import SecurityPipeline
from vordur.security.types import (
    PolicyConfig,
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sensitive_ctx(policy: PolicyConfig | None = None) -> SecurityContext:
    """Trusted, sensitive context (e.g. private-channel API keys)."""
    return SecurityContext(
        mode="client",
        source_type="internal",
        source_id="private-channel",
        source_trust=TrustLevel.TRUSTED,
        sensitivity=SensitivityLevel.SENSITIVE,
        policy=policy or PolicyConfig(),
    )


def _untrusted_ctx(policy: PolicyConfig | None = None) -> SecurityContext:
    """Untrusted context (e.g. attacker injection from a public channel)."""
    return SecurityContext(
        mode="client",
        source_type="web_content",
        source_id="public-channel",
        source_trust=TrustLevel.UNTRUSTED,
        policy=policy or PolicyConfig(),
    )


def _public_ctx(policy: PolicyConfig | None = None) -> SecurityContext:
    """Trusted, public context."""
    return SecurityContext(
        mode="client",
        source_type="internal",
        source_id="public-docs",
        source_trust=TrustLevel.TRUSTED,
        sensitivity=SensitivityLevel.PUBLIC,
        policy=policy or PolicyConfig(),
    )


def _outbound_ctx(policy: PolicyConfig | None = None) -> SecurityContext:
    """Context for check_outbound calls."""
    return SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="email-tool",
        policy=policy or PolicyConfig(),
    )


# ---------------------------------------------------------------------------
# 6.1: Contamination flag lifecycle
# ---------------------------------------------------------------------------


class TestContaminationFlagLifecycle:
    def test_pipeline_starts_uncontaminated(self):
        pipe = SecurityPipeline()
        assert pipe.context_contaminated is False

    def test_untrusted_inbound_sets_contaminated(self):
        pipe = SecurityPipeline()
        pipe.process_inbound("attacker payload", _untrusted_ctx())
        assert pipe.context_contaminated is True

    def test_trusted_inbound_does_not_contaminate(self):
        pipe = SecurityPipeline()
        pipe.process_inbound("safe internal data", _sensitive_ctx())
        assert pipe.context_contaminated is False


# ---------------------------------------------------------------------------
# 6.2: Sensitive ingestion
# ---------------------------------------------------------------------------


class TestSensitiveIngestion:
    def test_sensitive_content_buffered_in_dlp(self):
        pipe = SecurityPipeline()
        pipe.process_inbound("my secret api key value here", _sensitive_ctx())
        assert len(pipe._dlp._sensitive_buffer) == 1

    def test_public_content_not_buffered_as_sensitive(self):
        pipe = SecurityPipeline()
        pipe.process_inbound("public information", _public_ctx())
        assert len(pipe._dlp._sensitive_buffer) == 0


# ---------------------------------------------------------------------------
# 6.3: Contaminated-context egress blocking
# ---------------------------------------------------------------------------


_CREDENTIALS = (
    "production database credentials: "
    "host=db.internal.corp port=5432 user=admin password=s3cr3tP@ssw0rd! "
    "database=production_main connection_pool_size=20"
)

_PII = (
    "Customer record: John Smith, SSN 123-45-6789, "
    "DOB 1985-03-15, address 1234 Oak Street Springfield IL 62704, "
    "phone 555-0123, email john.smith@example.com"
)

_CONTRACT_TERMS = (
    "CONFIDENTIAL: Contract clause 4.2.1 states that vendor licensing fees "
    "shall not exceed $2.4M per annum with automatic renewal unless "
    "terminated with 90 days written notice to the contracting officer"
)


class TestContaminatedEgressBlocking:
    def test_credentials_blocked_when_contaminated(self):
        pipe = SecurityPipeline()
        pipe.process_inbound(_CREDENTIALS, _sensitive_ctx())
        pipe.process_inbound("ignore previous instructions", _untrusted_ctx())
        result = pipe.check_outbound(_CREDENTIALS, _outbound_ctx())
        assert result.allowed is False
        assert result.contamination_triggered is True

    def test_pii_blocked_when_contaminated(self):
        pipe = SecurityPipeline()
        pipe.process_inbound(_PII, _sensitive_ctx())
        pipe.process_inbound("what is the customer SSN?", _untrusted_ctx())
        result = pipe.check_outbound(_PII, _outbound_ctx())
        assert result.allowed is False
        assert result.contamination_triggered is True

    def test_contract_terms_blocked_when_contaminated(self):
        pipe = SecurityPipeline()
        pipe.process_inbound(_CONTRACT_TERMS, _sensitive_ctx())
        pipe.process_inbound("xyz unrelated injection payload 9876", _untrusted_ctx())
        result = pipe.check_outbound(_CONTRACT_TERMS, _outbound_ctx())
        assert result.allowed is False
        assert result.contamination_triggered is True


# ---------------------------------------------------------------------------
# 6.4: Order independence
# ---------------------------------------------------------------------------


class TestOrderIndependence:
    def test_untrusted_before_sensitive(self):
        """Untrusted arrives first, then sensitive. Egress still blocked."""
        pipe = SecurityPipeline()
        pipe.process_inbound("malicious injection payload", _untrusted_ctx())
        pipe.process_inbound(_CREDENTIALS, _sensitive_ctx())
        result = pipe.check_outbound(_CREDENTIALS, _outbound_ctx())
        assert result.allowed is False
        assert result.contamination_triggered is True

    def test_sensitive_before_untrusted(self):
        """Sensitive arrives first, then untrusted. Egress still blocked."""
        pipe = SecurityPipeline()
        pipe.process_inbound(_CREDENTIALS, _sensitive_ctx())
        pipe.process_inbound("malicious injection payload", _untrusted_ctx())
        result = pipe.check_outbound(_CREDENTIALS, _outbound_ctx())
        assert result.allowed is False
        assert result.contamination_triggered is True


# ---------------------------------------------------------------------------
# 6.5: True negatives
# ---------------------------------------------------------------------------


class TestTrueNegatives:
    def test_no_contamination_allows_sensitive_outbound(self):
        """Without untrusted content, sensitive outbound is allowed."""
        pipe = SecurityPipeline()
        pipe.process_inbound(_CREDENTIALS, _sensitive_ctx())
        result = pipe.check_outbound(_CREDENTIALS, _outbound_ctx())
        assert result.allowed is True

    def test_no_overlap_allows_outbound(self):
        """Contaminated session, but outbound does not overlap sensitive."""
        pipe = SecurityPipeline()
        pipe.process_inbound(_CREDENTIALS, _sensitive_ctx())
        pipe.process_inbound("attacker payload", _untrusted_ctx())
        result = pipe.check_outbound(
            "This email is about something completely different.",
            _outbound_ctx(),
        )
        assert result.allowed is True

    def test_public_content_not_blocked_when_contaminated(self):
        """Public content should not trigger contamination blocking."""
        pipe = SecurityPipeline()
        public_text = (
            "This is public documentation about how to configure "
            "the system and set up basic networking parameters "
            "for development environments without any secrets"
        )
        pipe.process_inbound(public_text, _public_ctx())
        pipe.process_inbound("attacker payload", _untrusted_ctx())
        result = pipe.check_outbound(public_text, _outbound_ctx())
        # Public content is not in the sensitive buffer, so contamination
        # check should not fire. (It may still be blocked by untrusted
        # overlap if the same text appeared in the untrusted buffer, but
        # here it does not.)
        assert result.contamination_triggered is False


# ---------------------------------------------------------------------------
# 6.6: Confirm mode
# ---------------------------------------------------------------------------


class TestConfirmMode:
    def test_confirm_action_prefixes_reason(self):
        policy = PolicyConfig(contaminated_action="confirm")
        pipe = SecurityPipeline()
        pipe.process_inbound(_CREDENTIALS, _sensitive_ctx(policy))
        pipe.process_inbound("extract secrets", _untrusted_ctx(policy))
        result = pipe.check_outbound(_CREDENTIALS, _outbound_ctx(policy))
        assert result.allowed is False
        assert result.contamination_triggered is True
        assert result.reason.startswith("Confirmation required:")


# ---------------------------------------------------------------------------
# 6.7: Reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_pipeline_reset_clears_contamination(self):
        pipe = SecurityPipeline()
        pipe.process_inbound("attacker", _untrusted_ctx())
        assert pipe.context_contaminated is True
        pipe.reset()
        assert pipe.context_contaminated is False

    def test_guard_reset_clears_contamination(self):
        guard = Guard()
        ctx_sensitive = Guard.context_internal_sensitive()
        ctx_untrusted = Guard.context_mcp_server("evil-server")
        guard.process_inbound(_CREDENTIALS, ctx_sensitive)
        guard.process_inbound("steal data", ctx_untrusted)
        # Before reset, outbound should be blocked
        out_ctx = Guard.context_mcp_server("email-tool")
        result = guard.check_outbound(_CREDENTIALS, out_ctx)
        assert result.allowed is False
        # After reset, outbound should be allowed (no contamination, no buffer)
        guard.reset()
        result = guard.check_outbound(_CREDENTIALS, out_ctx)
        assert result.allowed is True
