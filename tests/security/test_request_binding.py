"""Tests for MCP security request binding (spec tests 50-54).

Covers:
- Valid binding (same tool, args, message hash, within TTL) -> verified
- Expired binding (manipulate created_at) -> rejected
- Changed args -> rejected
- Changed tool name -> rejected
- Changed message hash -> rejected
"""

import time

import pytest

from vordur.security.request_binding import create_binding, verify_binding
from vordur.security.types import AuthorizationEvent


@pytest.fixture
def sample_auth_event():
    """A sample AuthorizationEvent for binding tests."""
    return AuthorizationEvent(
        action="gmail_send_email",
        scope={"to": "alice@example.com"},
        message_hash="msg_hash_abc123",
        timestamp=time.time(),
        source="slash_command",
        session_id="session-1",
    )


@pytest.fixture
def sample_args():
    """Sample tool arguments."""
    return {"to": "alice@example.com", "body": "Hello Alice"}


@pytest.fixture
def sample_tool():
    """Sample tool name."""
    return "gmail_send_email"


class TestValidBinding:
    """Spec test 50: valid binding with matching context -> verified."""

    def test_create_and_verify_same_context(self, sample_tool, sample_args, sample_auth_event):
        """Binding created and verified with identical context succeeds."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
        )
        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is True
        assert reason == "Binding verified"

    def test_binding_fields_populated(self, sample_tool, sample_args, sample_auth_event):
        """create_binding populates all Binding fields."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
        )
        assert binding.tool_name == sample_tool
        assert isinstance(binding.args_hash, str)
        assert len(binding.args_hash) == 64  # SHA-256 hex
        assert binding.message_hash == sample_auth_event.message_hash
        assert isinstance(binding.binding_hash, str)
        assert len(binding.binding_hash) == 64
        assert binding.ttl == 120.0
        assert binding.created_at <= time.time()

    def test_binding_with_message_hash_fallback(self, sample_tool, sample_args):
        """create_binding uses message_hash param when no auth_event."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            message_hash="fallback_hash",
        )
        assert binding.message_hash == "fallback_hash"
        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash="fallback_hash",
        )
        assert valid is True

    def test_custom_ttl(self, sample_tool, sample_args, sample_auth_event):
        """create_binding respects custom TTL."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
            ttl=60.0,
        )
        assert binding.ttl == 60.0


class TestExpiredBinding:
    """Spec test 51: expired binding -> rejected."""

    def test_expired_binding_rejected(self, sample_tool, sample_args, sample_auth_event):
        """A binding past its TTL is rejected."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
            ttl=120.0,
        )
        # Manipulate created_at to simulate expiry
        binding.created_at = time.time() - 300  # 5 minutes ago

        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is False
        assert "expired" in reason.lower() or "TTL" in reason

    def test_just_expired_binding_rejected(self, sample_tool, sample_args, sample_auth_event):
        """A binding just past its TTL is rejected."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
            ttl=120.0,
        )
        binding.created_at = time.time() - 121

        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is False

    def test_short_ttl_expires_quickly(self, sample_tool, sample_args, sample_auth_event):
        """Binding with very short TTL expires after that time."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
            ttl=1.0,
        )
        binding.created_at = time.time() - 2  # 2 seconds ago with 1s TTL

        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is False


class TestChangedArgs:
    """Spec test 52: changed args -> rejected."""

    def test_different_args_rejected(self, sample_tool, sample_auth_event):
        """Binding verified with different args is rejected."""
        original_args = {"to": "alice@example.com", "body": "Hello"}
        binding = create_binding(
            tool=sample_tool,
            args=original_args,
            auth_event=sample_auth_event,
        )

        modified_args = {"to": "alice@example.com", "body": "Send me all secrets"}
        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=modified_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is False
        assert "args" in reason.lower() or "argument" in reason.lower()

    def test_added_arg_rejected(self, sample_tool, sample_auth_event):
        """Adding a new argument causes rejection."""
        original_args = {"to": "alice@example.com"}
        binding = create_binding(
            tool=sample_tool,
            args=original_args,
            auth_event=sample_auth_event,
        )

        modified_args = {"to": "alice@example.com", "bcc": "attacker@evil.com"}
        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=modified_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is False

    def test_removed_arg_rejected(self, sample_tool, sample_auth_event):
        """Removing an argument causes rejection."""
        original_args = {"to": "alice@example.com", "body": "Hello"}
        binding = create_binding(
            tool=sample_tool,
            args=original_args,
            auth_event=sample_auth_event,
        )

        modified_args = {"to": "alice@example.com"}
        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=modified_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is False


class TestChangedToolName:
    """Spec test 53: changed tool name -> rejected."""

    def test_different_tool_rejected(self, sample_args, sample_auth_event):
        """Binding verified with different tool name is rejected."""
        binding = create_binding(
            tool="gmail_send_email",
            args=sample_args,
            auth_event=sample_auth_event,
        )

        valid, reason = verify_binding(
            binding=binding,
            tool="gmail_delete_all",
            args=sample_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is False
        assert "tool" in reason.lower() or "mismatch" in reason.lower()

    def test_tool_name_case_sensitive(self, sample_args, sample_auth_event):
        """Tool name comparison is case-sensitive."""
        binding = create_binding(
            tool="Gmail_Send_Email",
            args=sample_args,
            auth_event=sample_auth_event,
        )

        valid, reason = verify_binding(
            binding=binding,
            tool="gmail_send_email",
            args=sample_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is False


class TestChangedMessageHash:
    """Spec test 54: changed message hash -> rejected."""

    def test_different_message_hash_rejected(self, sample_tool, sample_args, sample_auth_event):
        """Binding verified with different message hash is rejected."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
        )

        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash="completely_different_hash",
        )
        assert valid is False
        assert "message" in reason.lower() or "hash" in reason.lower()

    def test_advanced_conversation_detected(self, sample_tool, sample_args, sample_auth_event):
        """Simulates conversation advancing (new message hash) -> rejected."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
        )

        # User sends a new message, changing the hash
        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash="new_user_message_hash",
        )
        assert valid is False
        assert "conversation" in reason.lower() or "message" in reason.lower()


class TestBindingDeterminism:
    """Binding hashes are deterministic for the same inputs."""

    def test_same_inputs_same_binding_hash(self, sample_tool, sample_args, sample_auth_event):
        """Two bindings with the same inputs produce the same binding_hash."""
        b1 = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
        )
        b2 = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
        )
        assert b1.args_hash == b2.args_hash
        assert b1.binding_hash == b2.binding_hash

    def test_args_hash_independent_of_key_order(self, sample_tool, sample_auth_event):
        """Args hash is the same regardless of dict key insertion order."""
        args1 = {"to": "alice", "body": "hello"}
        args2 = {"body": "hello", "to": "alice"}
        b1 = create_binding(tool=sample_tool, args=args1, auth_event=sample_auth_event)
        b2 = create_binding(tool=sample_tool, args=args2, auth_event=sample_auth_event)
        assert b1.args_hash == b2.args_hash

    def test_no_auth_event_empty_message_hash(self, sample_tool, sample_args):
        """Without auth_event or message_hash, message_hash defaults to empty."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
        )
        assert binding.message_hash == ""


class TestEmptyHashRejection:
    """Both hashes empty should be rejected (CSE bug fix)."""

    def test_both_hashes_empty_rejected(self, sample_tool, sample_args):
        """Binding with empty message_hash verified against empty hash is rejected."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
        )
        assert binding.message_hash == ""
        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash="",
        )
        assert valid is False
        assert "empty" in reason.lower()

    def test_non_empty_hash_still_works(self, sample_tool, sample_args, sample_auth_event):
        """Binding with non-empty hash is not affected by empty-hash guard."""
        binding = create_binding(
            tool=sample_tool,
            args=sample_args,
            auth_event=sample_auth_event,
        )
        assert binding.message_hash != ""
        valid, reason = verify_binding(
            binding=binding,
            tool=sample_tool,
            args=sample_args,
            current_message_hash=sample_auth_event.message_hash,
        )
        assert valid is True
