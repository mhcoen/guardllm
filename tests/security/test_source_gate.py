"""Unit tests for Layer 3 source gate -- policy module in isolation (no DB)."""

import pytest

from guardllm.security.source_gate import (
    ExtractionPolicy,
    check_extraction_allowed,
)
from guardllm.security.types import TrustLevel


class TestSourceGatePolicy:
    """Test the source_type -> policy mapping."""

    def test_user_input_allowed(self):
        result = check_extraction_allowed("user_input")
        assert result.policy == ExtractionPolicy.ALLOW
        assert result.source_origin == "cli"

    def test_assistant_response_allowed(self):
        result = check_extraction_allowed("assistant_response")
        assert result.policy == ExtractionPolicy.ALLOW
        assert result.source_origin == "assistant_response"

    def test_cli_allowed(self):
        result = check_extraction_allowed("cli")
        assert result.policy == ExtractionPolicy.ALLOW
        assert result.source_origin == "cli"

    def test_email_content_blocked(self):
        result = check_extraction_allowed("email_content")
        assert result.policy == ExtractionPolicy.BLOCK
        assert "blocked" in result.reason.lower()

    def test_calendar_content_blocked(self):
        result = check_extraction_allowed("calendar_content")
        assert result.policy == ExtractionPolicy.BLOCK

    def test_web_content_blocked(self):
        result = check_extraction_allowed("web_content")
        assert result.policy == ExtractionPolicy.BLOCK

    def test_rag_content_blocked(self):
        result = check_extraction_allowed("rag_content")
        assert result.policy == ExtractionPolicy.BLOCK

    def test_tool_output_blocked(self):
        result = check_extraction_allowed("tool_output")
        assert result.policy == ExtractionPolicy.BLOCK

    def test_mcp_client_quarantined(self):
        result = check_extraction_allowed("mcp_client", source_id="test-client")
        assert result.policy == ExtractionPolicy.QUARANTINE
        assert result.source_origin == "mcp:test-client"
        assert "quarantine" in result.reason.lower()

    def test_mcp_client_no_source_id(self):
        result = check_extraction_allowed("mcp_client")
        assert result.policy == ExtractionPolicy.QUARANTINE
        assert result.source_origin == "mcp_client"

    def test_user_indexed_email_quarantined(self):
        result = check_extraction_allowed("user_indexed_email")
        assert result.policy == ExtractionPolicy.QUARANTINE

    def test_user_indexed_web_quarantined(self):
        result = check_extraction_allowed("user_indexed_web")
        assert result.policy == ExtractionPolicy.QUARANTINE

    def test_unknown_source_blocked(self):
        """Unknown source types default to BLOCK."""
        result = check_extraction_allowed("totally_unknown_source")
        assert result.policy == ExtractionPolicy.BLOCK

    def test_result_is_frozen(self):
        result = check_extraction_allowed("user_input")
        with pytest.raises(AttributeError):
            result.policy = ExtractionPolicy.BLOCK

    def test_quarantine_with_source_id_in_origin(self):
        result = check_extraction_allowed("mcp_client", source_id="claude-code")
        assert result.source_origin == "mcp:claude-code"

    def test_quarantine_user_indexed_with_source_id(self):
        result = check_extraction_allowed("user_indexed_email", source_id="sender@example.com")
        assert result.source_origin == "mcp:sender@example.com"

    def test_web_synthesis_quarantined(self):
        """Muse-mode web-synthesized responses require quarantine."""
        result = check_extraction_allowed("web_synthesis")
        assert result.policy == ExtractionPolicy.QUARANTINE
        assert "quarantine" in result.reason.lower()


class TestSourceGateOverrides:
    """Tests for PolicyConfig source_gate_overrides lookup."""

    def test_override_changes_policy(self):
        """Override table can promote a BLOCK source to ALLOW."""
        overrides = {
            ("email_content", TrustLevel.TRUSTED): ExtractionPolicy.ALLOW,
        }
        result = check_extraction_allowed(
            "email_content",
            source_id="msg-001",
            source_trust=TrustLevel.TRUSTED,
            source_gate_overrides=overrides,
        )
        assert result.policy == ExtractionPolicy.ALLOW

    def test_override_not_matched_falls_back(self):
        """When override key doesn't match, falls back to _SOURCE_POLICY."""
        overrides = {
            ("email_content", TrustLevel.TRUSTED): ExtractionPolicy.ALLOW,
        }
        result = check_extraction_allowed(
            "email_content",
            source_id="msg-001",
            source_trust=TrustLevel.UNTRUSTED,
            source_gate_overrides=overrides,
        )
        assert result.policy == ExtractionPolicy.BLOCK

    def test_no_overrides_uses_default(self):
        """Without overrides, behavior matches the static table."""
        result = check_extraction_allowed(
            "web_content",
            source_trust=TrustLevel.UNTRUSTED,
        )
        assert result.policy == ExtractionPolicy.BLOCK

    def test_unknown_source_type_blocks_even_with_overrides(self):
        """Unknown source types still default to BLOCK."""
        overrides = {
            ("known_type", TrustLevel.TRUSTED): ExtractionPolicy.ALLOW,
        }
        result = check_extraction_allowed(
            "totally_unknown",
            source_trust=TrustLevel.UNTRUSTED,
            source_gate_overrides=overrides,
        )
        assert result.policy == ExtractionPolicy.BLOCK


class TestRequireSourceIdFor:
    """Tests for require_source_id_for enforcement."""

    def test_required_type_empty_id_blocked(self):
        result = check_extraction_allowed(
            "mcp_client",
            source_id="",
            require_source_id_for=frozenset({"mcp_client"}),
        )
        assert result.policy == ExtractionPolicy.BLOCK
        assert "source_id required" in result.reason

    def test_required_type_valid_id_allowed(self):
        result = check_extraction_allowed(
            "mcp_client",
            source_id="client-42",
            require_source_id_for=frozenset({"mcp_client"}),
        )
        assert result.policy == ExtractionPolicy.QUARANTINE

    def test_default_empty_set_allows_empty_id(self):
        result = check_extraction_allowed(
            "mcp_client",
            source_id="",
            require_source_id_for=frozenset(),
        )
        assert result.policy == ExtractionPolicy.QUARANTINE

    def test_different_type_not_required_allows_empty(self):
        result = check_extraction_allowed(
            "user_input",
            source_id="",
            require_source_id_for=frozenset({"mcp_client"}),
        )
        assert result.policy == ExtractionPolicy.ALLOW
