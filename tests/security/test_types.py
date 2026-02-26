"""Tests for MCP security types: AuthorizationEvent, SecurityContext, Binding.

Covers:
- AuthorizationEvent creation with all fields
- binding_hash() determinism (same inputs -> same hash)
- Frozen dataclass immutability
- SecurityContext creation with defaults
- Binding.expired property
"""

import time

import pytest

from guardllm.security.types import (
    AuthorizationEvent,
    AuditEvent,
    Binding,
    ContentType,
    GateResult,
    OutboundResult,
    PolicyConfig,
    ProcessedContent,
    RateLimitResult,
    SanitizationResult,
    SecurityContext,
    TrustLevel,
    ValidationResult,
)


class TestAuthorizationEvent:
    """Tests for the AuthorizationEvent frozen dataclass."""

    def test_creates_with_all_fields(self):
        """AuthorizationEvent stores all required fields correctly."""
        event = AuthorizationEvent(
            action="gmail_send_email",
            scope={"to": "alice@example.com", "max_length": 500},
            message_hash="abc123def456",
            timestamp=1700000000.0,
            source="slash_command",
            session_id="session-42",
        )
        assert event.action == "gmail_send_email"
        assert event.scope == {"to": "alice@example.com", "max_length": 500}
        assert event.message_hash == "abc123def456"
        assert event.timestamp == 1700000000.0
        assert event.source == "slash_command"
        assert event.session_id == "session-42"

    def test_session_id_defaults_to_none(self):
        """session_id is optional and defaults to None."""
        event = AuthorizationEvent(
            action="tool_x",
            scope={},
            message_hash="hash1",
            timestamp=1.0,
            source="regex_directive",
        )
        assert event.session_id is None

    def test_binding_hash_deterministic(self):
        """binding_hash() returns the same value for identical inputs."""
        event1 = AuthorizationEvent(
            action="gmail_send_email",
            scope={"to": "bob@test.com"},
            message_hash="msg_hash_123",
            timestamp=1700000000.0,
            source="slash_command",
        )
        event2 = AuthorizationEvent(
            action="gmail_send_email",
            scope={"to": "bob@test.com"},
            message_hash="msg_hash_123",
            timestamp=9999999999.0,  # Different timestamp
            source="different_source",  # Different source
        )
        # binding_hash uses action, scope, message_hash only
        assert event1.binding_hash() == event2.binding_hash()

    def test_binding_hash_changes_with_action(self):
        """binding_hash() changes when action differs."""
        base = dict(
            scope={"to": "alice@test.com"},
            message_hash="hash1",
            timestamp=1.0,
            source="test",
        )
        event1 = AuthorizationEvent(action="gmail_send_email", **base)
        event2 = AuthorizationEvent(action="gmail_read_email", **base)
        assert event1.binding_hash() != event2.binding_hash()

    def test_binding_hash_changes_with_scope(self):
        """binding_hash() changes when scope differs."""
        base = dict(
            action="gmail_send_email",
            message_hash="hash1",
            timestamp=1.0,
            source="test",
        )
        event1 = AuthorizationEvent(scope={"to": "alice@test.com"}, **base)
        event2 = AuthorizationEvent(scope={"to": "bob@test.com"}, **base)
        assert event1.binding_hash() != event2.binding_hash()

    def test_binding_hash_changes_with_message_hash(self):
        """binding_hash() changes when message_hash differs."""
        base = dict(
            action="gmail_send_email",
            scope={"to": "alice@test.com"},
            timestamp=1.0,
            source="test",
        )
        event1 = AuthorizationEvent(message_hash="hash_a", **base)
        event2 = AuthorizationEvent(message_hash="hash_b", **base)
        assert event1.binding_hash() != event2.binding_hash()

    def test_binding_hash_is_hex_string(self):
        """binding_hash() returns a hex SHA-256 digest."""
        event = AuthorizationEvent(
            action="tool",
            scope={},
            message_hash="h",
            timestamp=1.0,
            source="s",
        )
        h = event.binding_hash()
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex digest is 64 chars
        assert all(c in "0123456789abcdef" for c in h)

    def test_frozen_cannot_mutate(self):
        """Frozen dataclass raises on attribute assignment."""
        event = AuthorizationEvent(
            action="tool",
            scope={},
            message_hash="h",
            timestamp=1.0,
            source="s",
        )
        with pytest.raises(AttributeError):
            event.action = "other_tool"

    def test_frozen_cannot_mutate_any_field(self):
        """No field on the frozen dataclass can be reassigned."""
        event = AuthorizationEvent(
            action="tool",
            scope={},
            message_hash="h",
            timestamp=1.0,
            source="s",
            session_id="sess",
        )
        for field_name in ("action", "scope", "message_hash", "timestamp", "source", "session_id"):
            with pytest.raises(AttributeError):
                setattr(event, field_name, "new_value")


class TestSecurityContext:
    """Tests for the SecurityContext dataclass."""

    def test_creates_with_required_fields(self):
        """SecurityContext creates with mode, source_type, source_id."""
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
        )
        assert ctx.mode == "client"
        assert ctx.source_type == "mcp_server"
        assert ctx.source_id == "server-1"

    def test_default_trust_levels(self):
        """Default source_trust and principal_trust are UNTRUSTED."""
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
        )
        assert ctx.source_trust == TrustLevel.UNTRUSTED
        assert ctx.principal_trust == TrustLevel.UNTRUSTED

    def test_default_content_type(self):
        """Default content_type is PLAINTEXT."""
        ctx = SecurityContext(
            mode="server",
            source_type="mcp_client",
            source_id="client-1",
        )
        assert ctx.content_type == ContentType.PLAINTEXT

    def test_default_policy(self):
        """Default policy is an empty PolicyConfig."""
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
        )
        assert isinstance(ctx.policy, PolicyConfig)
        assert ctx.policy.tool_allowlist is None
        assert ctx.policy.enable_destructive is False
        assert ctx.policy.dlp_verbatim_lcs_min == 14
        assert ctx.policy.dlp_ngram_overlap_min == 0.40
        assert ctx.policy.dlp_sensitive_lcs_min == 12
        assert ctx.policy.provenance_verbatim_lcs_min == 50
        assert ctx.policy.provenance_ngram_overlap_min == 0.30

    def test_default_confirmation_handler(self):
        """Default confirmation_handler is None."""
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
        )
        assert ctx.confirmation_handler is None

    def test_custom_source_trust(self):
        """SecurityContext accepts custom source_trust."""
        ctx = SecurityContext(
            mode="client",
            source_type="cli_user",
            source_id="user-1",
            source_trust=TrustLevel.TRUSTED,
        )
        assert ctx.source_trust == TrustLevel.TRUSTED

    def test_source_trust_rejects_semi_trusted(self):
        """source_trust=SEMI_TRUSTED raises ValueError."""
        with pytest.raises(ValueError, match="source_trust"):
            SecurityContext(
                mode="client",
                source_type="mcp_server",
                source_id="s1",
                source_trust=TrustLevel.SEMI_TRUSTED,
            )

    def test_custom_content_type(self):
        """SecurityContext accepts custom content_type."""
        ctx = SecurityContext(
            mode="server",
            source_type="mcp_client",
            source_id="c1",
            content_type=ContentType.HTML,
        )
        assert ctx.content_type == ContentType.HTML


class TestBinding:
    """Tests for the Binding dataclass and its expired property."""

    def test_creates_with_all_fields(self):
        """Binding stores all fields correctly."""
        now = time.time()
        b = Binding(
            tool_name="gmail_send",
            args_hash="aaa",
            message_hash="bbb",
            binding_hash="ccc",
            created_at=now,
            ttl=120.0,
        )
        assert b.tool_name == "gmail_send"
        assert b.args_hash == "aaa"
        assert b.message_hash == "bbb"
        assert b.binding_hash == "ccc"
        assert b.created_at == now
        assert b.ttl == 120.0

    def test_default_ttl(self):
        """Default TTL is 120 seconds."""
        b = Binding(
            tool_name="t",
            args_hash="a",
            message_hash="m",
            binding_hash="b",
            created_at=time.time(),
        )
        assert b.ttl == 120.0

    def test_not_expired_when_fresh(self):
        """A freshly-created binding is not expired."""
        b = Binding(
            tool_name="t",
            args_hash="a",
            message_hash="m",
            binding_hash="b",
            created_at=time.time(),
            ttl=120.0,
        )
        assert b.expired is False

    def test_expired_after_ttl(self):
        """A binding created long ago is expired."""
        b = Binding(
            tool_name="t",
            args_hash="a",
            message_hash="m",
            binding_hash="b",
            created_at=time.time() - 300,  # 300 seconds ago
            ttl=120.0,
        )
        assert b.expired is True

    def test_expired_boundary(self):
        """A binding exactly at the TTL boundary is expired."""
        # created_at is ttl+1 seconds ago, so it's just past expiry
        b = Binding(
            tool_name="t",
            args_hash="a",
            message_hash="m",
            binding_hash="b",
            created_at=time.time() - 121,
            ttl=120.0,
        )
        assert b.expired is True

    def test_not_expired_just_before_ttl(self):
        """A binding just under the TTL is not expired."""
        b = Binding(
            tool_name="t",
            args_hash="a",
            message_hash="m",
            binding_hash="b",
            created_at=time.time() - 119,
            ttl=120.0,
        )
        assert b.expired is False

    def test_custom_short_ttl(self):
        """Binding with short TTL expires quickly."""
        b = Binding(
            tool_name="t",
            args_hash="a",
            message_hash="m",
            binding_hash="b",
            created_at=time.time() - 5,
            ttl=2.0,
        )
        assert b.expired is True


class TestEnums:
    """Basic tests for TrustLevel and ContentType enums."""

    def test_trust_level_values(self):
        assert TrustLevel.TRUSTED.value == "trusted"
        assert TrustLevel.SEMI_TRUSTED.value == "semi_trusted"
        assert TrustLevel.UNTRUSTED.value == "untrusted"

    def test_content_type_values(self):
        assert ContentType.HTML.value == "html"
        assert ContentType.PLAINTEXT.value == "plaintext"
        assert ContentType.STRUCTURED.value == "structured"

    def test_trust_level_ordering(self):
        """UNTRUSTED < SEMI_TRUSTED < TRUSTED."""
        assert TrustLevel.UNTRUSTED < TrustLevel.SEMI_TRUSTED
        assert TrustLevel.SEMI_TRUSTED < TrustLevel.TRUSTED
        assert TrustLevel.UNTRUSTED < TrustLevel.TRUSTED
        assert not (TrustLevel.TRUSTED < TrustLevel.UNTRUSTED)
        assert TrustLevel.UNTRUSTED <= TrustLevel.UNTRUSTED
        assert TrustLevel.TRUSTED <= TrustLevel.TRUSTED

    def test_trust_level_ordering_non_trustlevel(self):
        """Comparison with non-TrustLevel returns NotImplemented."""
        assert TrustLevel.UNTRUSTED.__lt__("not_a_trustlevel") is NotImplemented
        assert TrustLevel.UNTRUSTED.__le__(42) is NotImplemented


class TestPolicyConfigValidation:
    """Tests for PolicyConfig new fields and validation."""

    def test_defaults_preserve_behavior(self):
        """New fields have safe defaults that don't change existing behavior."""
        p = PolicyConfig()
        assert p.source_gate_overrides == {}
        assert p.untrusted_deny_tools == frozenset()
        assert p.untrusted_require_auth is False
        assert p.confirm_all_below is None
        assert p.rate_limit_overrides == {}

    def test_rate_limit_overrides_valid_keys(self):
        """Valid rate_limit_overrides keys are accepted."""
        p = PolicyConfig(
            rate_limit_overrides={
                TrustLevel.UNTRUSTED: {"emails_per_hour": 5, "burst_threshold": 2},
            }
        )
        assert p.rate_limit_overrides[TrustLevel.UNTRUSTED]["emails_per_hour"] == 5

    def test_rate_limit_overrides_rejects_unknown_keys(self):
        """Unknown rate_limit_overrides keys raise ValueError."""
        with pytest.raises(ValueError, match="Unknown rate_limit_overrides keys"):
            PolicyConfig(
                rate_limit_overrides={
                    TrustLevel.UNTRUSTED: {"invalid_key": 5},
                }
            )
