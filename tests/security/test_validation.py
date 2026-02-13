"""Tests for MCP security validation (spec tests 93-94).

Covers:
- Oversized message (>50000 chars) -> invalid
- Pattern violation on source_name (special chars) -> invalid
- Path traversal in source_name (../../etc/passwd) -> invalid
- Valid arguments -> valid
- Unknown extra fields silently ignored
- Missing required field (provenance with too many fields) -> invalid
"""

import pytest

from guardllm.security.validation import (
    ARGUMENT_LIMITS,
    validate_arguments,
)
from guardllm.security.types import ValidationResult


class TestOversizedMessage:
    """Spec test 93: oversized message rejected."""

    def test_message_exceeds_50000_chars(self):
        """Message over 50000 chars is rejected."""
        result = validate_arguments("any_tool", {
            "message": "x" * 50_001,
        })
        assert result.valid is False
        assert len(result.errors) > 0
        assert any("message" in e.lower() for e in result.errors)

    def test_message_exactly_50000_chars_valid(self):
        """Message of exactly 50000 chars is valid."""
        result = validate_arguments("any_tool", {
            "message": "x" * 50_000,
        })
        assert result.valid is True

    def test_content_exceeds_500000_chars(self):
        """Content over 500000 chars is rejected."""
        result = validate_arguments("any_tool", {
            "content": "y" * 500_001,
        })
        assert result.valid is False
        assert any("content" in e.lower() for e in result.errors)

    def test_query_exceeds_1000_chars(self):
        """Query over 1000 chars is rejected."""
        result = validate_arguments("any_tool", {
            "query": "q" * 1_001,
        })
        assert result.valid is False


class TestPatternViolation:
    """Spec test 94: pattern violations on source_name."""

    def test_special_chars_rejected(self):
        """source_name with special characters fails pattern check."""
        result = validate_arguments("any_tool", {
            "source_name": "test<script>alert(1)</script>",
        })
        assert result.valid is False
        assert any("source_name" in e for e in result.errors)

    def test_semicolon_rejected(self):
        """source_name containing semicolons is rejected."""
        result = validate_arguments("any_tool", {
            "source_name": "test;drop table",
        })
        assert result.valid is False

    def test_backtick_rejected(self):
        """source_name containing backticks is rejected."""
        result = validate_arguments("any_tool", {
            "source_name": "test`whoami`",
        })
        assert result.valid is False

    def test_path_traversal_rejected(self):
        """source_name with path traversal (../../etc/passwd) is rejected."""
        result = validate_arguments("any_tool", {
            "source_name": "../../etc/passwd",
        })
        assert result.valid is False

    def test_path_traversal_with_dots(self):
        """source_name containing .. sequences is rejected by pattern."""
        result = validate_arguments("any_tool", {
            "source_name": "../../../secret/key",
        })
        assert result.valid is False

    def test_null_bytes_rejected(self):
        """source_name with null bytes fails pattern check."""
        result = validate_arguments("any_tool", {
            "source_name": "test\x00evil",
        })
        assert result.valid is False

    def test_valid_source_name(self):
        """Valid source_name with allowed characters passes."""
        result = validate_arguments("any_tool", {
            "source_name": "my-source/path_name.txt",
        })
        assert result.valid is True

    def test_source_name_with_spaces(self):
        """source_name with spaces is valid per the pattern."""
        result = validate_arguments("any_tool", {
            "source_name": "my source file.txt",
        })
        assert result.valid is True

    def test_source_name_exceeds_max_chars(self):
        """source_name over 200 chars is rejected."""
        result = validate_arguments("any_tool", {
            "source_name": "a" * 201,
        })
        assert result.valid is False


class TestThreadHandle:
    """Pattern validation for thread_handle."""

    def test_valid_thread_handle(self):
        """Alphanumeric thread handle with hyphens and underscores is valid."""
        result = validate_arguments("any_tool", {
            "thread_handle": "abc-DEF_123",
        })
        assert result.valid is True

    def test_thread_handle_with_spaces_rejected(self):
        """Thread handle with spaces fails pattern check."""
        result = validate_arguments("any_tool", {
            "thread_handle": "has space",
        })
        assert result.valid is False

    def test_thread_handle_with_special_chars_rejected(self):
        """Thread handle with special characters fails."""
        result = validate_arguments("any_tool", {
            "thread_handle": "handle@#$",
        })
        assert result.valid is False

    def test_thread_handle_exceeds_max_chars(self):
        """Thread handle over 100 chars is rejected."""
        result = validate_arguments("any_tool", {
            "thread_handle": "a" * 101,
        })
        assert result.valid is False


class TestValidArguments:
    """Valid arguments pass all checks."""

    def test_all_valid_arguments(self):
        """A request with valid values for all known fields passes."""
        result = validate_arguments("tool_x", {
            "message": "Hello, how are you?",
            "source_name": "my-source",
            "thread_handle": "handle-123",
            "query": "search query",
        })
        assert result.valid is True
        assert result.errors == []

    def test_empty_args_valid(self):
        """Empty args dict is valid (no arguments to validate)."""
        result = validate_arguments("tool_x", {})
        assert result.valid is True

    def test_message_at_limit(self):
        """Message exactly at the character limit is valid."""
        result = validate_arguments("tool_x", {
            "message": "a" * 50_000,
        })
        assert result.valid is True


class TestUnknownFields:
    """Unknown extra fields are silently ignored."""

    def test_unknown_field_ignored(self):
        """An unrecognized argument name does not cause rejection."""
        result = validate_arguments("tool_x", {
            "message": "valid message",
            "totally_unknown_field": "anything at all <script>evil</script>",
        })
        assert result.valid is True

    def test_multiple_unknown_fields(self):
        """Multiple unknown fields all ignored."""
        result = validate_arguments("tool_x", {
            "foo": "bar",
            "baz": 12345,
            "qux": {"nested": True},
        })
        assert result.valid is True

    def test_unknown_fields_do_not_leak(self):
        """Unknown field names do not appear in error messages."""
        result = validate_arguments("tool_x", {
            "unknown_secret_probe": "test",
        })
        assert result.valid is True
        assert result.errors == []


class TestProvenance:
    """Provenance field validation (structured dict)."""

    def test_provenance_too_many_fields(self):
        """Provenance dict with >10 fields is rejected."""
        prov = {f"field_{i}": f"value_{i}" for i in range(11)}
        result = validate_arguments("tool_x", {
            "provenance": prov,
        })
        assert result.valid is False
        assert any("provenance" in e for e in result.errors)

    def test_provenance_value_too_long(self):
        """Provenance dict with a value exceeding 500 chars is rejected."""
        result = validate_arguments("tool_x", {
            "provenance": {"key": "v" * 501},
        })
        assert result.valid is False

    def test_provenance_valid(self):
        """Provenance dict within limits is valid."""
        result = validate_arguments("tool_x", {
            "provenance": {"source": "user", "action": "send"},
        })
        assert result.valid is True

    def test_provenance_exactly_10_fields(self):
        """Provenance dict with exactly 10 fields is valid."""
        prov = {f"field_{i}": f"value_{i}" for i in range(10)}
        result = validate_arguments("tool_x", {
            "provenance": prov,
        })
        assert result.valid is True

    def test_provenance_non_dict_skipped(self):
        """Non-dict provenance value is not validated (skipped)."""
        result = validate_arguments("tool_x", {
            "provenance": "just a string",
        })
        # The string form is not a dict, so dict-specific validation is skipped,
        # then the string check would apply max_chars/pattern if present.
        # Since provenance has no max_chars or pattern, it should pass.
        assert result.valid is True


class TestValidationResult:
    """Tests for the ValidationResult structure on failure."""

    def test_field_name_set_on_error(self):
        """field_name is populated from the first error message."""
        result = validate_arguments("tool_x", {
            "message": "x" * 50_001,
        })
        assert result.valid is False
        assert result.field_name is not None

    def test_multiple_errors(self):
        """Multiple invalid arguments produce multiple errors."""
        result = validate_arguments("tool_x", {
            "message": "x" * 50_001,
            "source_name": "<script>evil</script>",
        })
        assert result.valid is False
        assert len(result.errors) >= 2

    def test_non_string_values_skipped(self):
        """Non-string values for string-validated fields are skipped."""
        result = validate_arguments("tool_x", {
            "message": 12345,  # Not a string
            "source_name": None,  # Not a string
        })
        assert result.valid is True
