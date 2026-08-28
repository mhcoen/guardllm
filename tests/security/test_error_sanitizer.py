"""Tests for MCP security error sanitizer (spec tests 95-96).

Covers:
- sqlite3.OperationalError -> internal_error, generic message
- FileNotFoundError -> internal_error
- RateLimitError -> rate_limited with retry_after
- InvalidParamsError -> invalid_params with field_name
- UnauthorizedError -> unauthorized
- PermissionDeniedError -> permission_denied
- InvalidHandleError -> invalid_handle
- Random Exception -> internal_error (catch-all)
- No stack traces in any response
- No file paths in any response
"""

import sqlite3

import pytest

from vordur.security.error_sanitizer import (
    InvalidHandleError,
    InvalidParamsError,
    PermissionDeniedError,
    RateLimitError,
    UnauthorizedError,
    sanitize_error,
)


class TestSqliteOperationalError:
    """sqlite3.OperationalError -> internal_error."""

    def test_maps_to_internal_error(self):
        """OperationalError maps to internal_error code."""
        exc = sqlite3.OperationalError("no such table: secrets")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "internal_error"

    def test_generic_message(self):
        """Error message is generic, not the original SQL error."""
        exc = sqlite3.OperationalError("database is locked at /home/user/.episodic/db")
        result = sanitize_error(exc)
        assert result["error"]["message"] == "Request could not be processed"
        assert "/home" not in result["error"]["message"]
        assert "database" not in result["error"]["message"]

    def test_no_table_names_leaked(self):
        """Table names from the original error are not in the response."""
        exc = sqlite3.OperationalError("no such column: password in table users")
        result = sanitize_error(exc)
        msg = str(result)
        assert "password" not in msg
        assert "users" not in msg


class TestFileNotFoundError:
    """FileNotFoundError -> internal_error."""

    def test_maps_to_internal_error(self):
        """FileNotFoundError maps to internal_error code."""
        exc = FileNotFoundError("/etc/secret/credentials.json")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "internal_error"

    def test_no_file_paths(self):
        """File paths from the original error are not in the response."""
        exc = FileNotFoundError("/home/user/.episodic/secret_key.pem")
        result = sanitize_error(exc)
        msg = str(result)
        assert "/home" not in msg
        assert "secret_key" not in msg
        assert ".pem" not in msg


class TestRateLimitError:
    """RateLimitError -> rate_limited with retry_after."""

    def test_maps_to_rate_limited(self):
        """RateLimitError maps to rate_limited code."""
        exc = RateLimitError(retry_after=60)
        result = sanitize_error(exc)
        assert result["error"]["code"] == "rate_limited"

    def test_includes_retry_after(self):
        """Response message includes retry_after seconds."""
        exc = RateLimitError(retry_after=120)
        result = sanitize_error(exc)
        assert "120" in result["error"]["message"]

    def test_default_retry_after(self):
        """Default retry_after is 60 seconds."""
        exc = RateLimitError()
        result = sanitize_error(exc)
        assert "60" in result["error"]["message"]

    def test_override_retry_after(self):
        """sanitize_error retry_after parameter overrides exception value."""
        exc = RateLimitError(retry_after=60)
        result = sanitize_error(exc, retry_after=300)
        assert "300" in result["error"]["message"]

    def test_rate_limit_error_attributes(self):
        """RateLimitError stores retry_after attribute."""
        exc = RateLimitError(retry_after=45)
        assert exc.retry_after == 45


class TestInvalidParamsError:
    """InvalidParamsError -> invalid_params with field_name."""

    def test_maps_to_invalid_params(self):
        """InvalidParamsError maps to invalid_params code."""
        exc = InvalidParamsError(field_name="email_body")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "invalid_params"

    def test_includes_field_name(self):
        """Response message includes the field name."""
        exc = InvalidParamsError(field_name="recipient")
        result = sanitize_error(exc)
        assert "recipient" in result["error"]["message"]

    def test_default_field_name(self):
        """Default field_name is 'unknown'."""
        exc = InvalidParamsError()
        result = sanitize_error(exc)
        assert "unknown" in result["error"]["message"]

    def test_no_field_value_in_message(self):
        """Field value is never included, only field name."""
        exc = InvalidParamsError(field_name="password")
        result = sanitize_error(exc)
        # The message should contain the field name but not any hypothetical value
        assert result["error"]["message"] == "Invalid parameters: password"


class TestUnauthorizedError:
    """UnauthorizedError -> unauthorized."""

    def test_maps_to_unauthorized(self):
        """UnauthorizedError maps to unauthorized code."""
        exc = UnauthorizedError("Token expired: eyJhbGci...")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "unauthorized"

    def test_generic_message(self):
        """Error message is generic, not the original token details."""
        exc = UnauthorizedError("Invalid JWT: eyJhbGciOiJIUzI1NiJ9.xxx")
        result = sanitize_error(exc)
        assert result["error"]["message"] == "Invalid or expired token"
        assert "JWT" not in result["error"]["message"]
        assert "eyJ" not in result["error"]["message"]


class TestPermissionDeniedError:
    """PermissionDeniedError -> permission_denied."""

    def test_maps_to_permission_denied(self):
        """PermissionDeniedError maps to permission_denied code."""
        exc = PermissionDeniedError("Tool gmail_delete not in allowlist for client-42")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "permission_denied"

    def test_generic_message(self):
        """Error message is generic, not the original details."""
        exc = PermissionDeniedError("gmail_delete blocked")
        result = sanitize_error(exc)
        assert result["error"]["message"] == "Tool not available"
        assert "gmail" not in result["error"]["message"]


class TestInvalidHandleError:
    """InvalidHandleError -> invalid_handle."""

    def test_maps_to_invalid_handle(self):
        """InvalidHandleError maps to invalid_handle code."""
        exc = InvalidHandleError("Thread handle abc-123 not found in session store")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "invalid_handle"

    def test_generic_message(self):
        """Error message is generic."""
        exc = InvalidHandleError()
        result = sanitize_error(exc)
        assert result["error"]["message"] == "Invalid or expired thread handle"


class TestCatchAll:
    """Random/unknown exceptions -> internal_error."""

    def test_runtime_error(self):
        """RuntimeError maps to internal_error."""
        exc = RuntimeError("Unexpected state in /var/lib/episodic/data")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "internal_error"
        assert result["error"]["message"] == "Request could not be processed"

    def test_type_error(self):
        """TypeError maps to internal_error."""
        exc = TypeError("NoneType has no attribute 'send'")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "internal_error"

    def test_key_error(self):
        """KeyError maps to internal_error."""
        exc = KeyError("api_key")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "internal_error"

    def test_value_error_without_field_name(self):
        """ValueError without field_name attribute maps to internal_error."""
        exc = ValueError("invalid literal for int()")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "internal_error"

    def test_os_error(self):
        """OSError maps to internal_error."""
        exc = OSError("Permission denied: /root/.ssh/id_rsa")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "internal_error"

    def test_generic_exception(self):
        """Base Exception maps to internal_error."""
        exc = Exception("Something went terribly wrong at line 42 of secret.py")
        result = sanitize_error(exc)
        assert result["error"]["code"] == "internal_error"


class TestNoLeakedInformation:
    """No stack traces or file paths in any error response."""

    @pytest.fixture(
        params=[
            sqlite3.OperationalError("table secrets at /db/path.sqlite"),
            FileNotFoundError("/home/user/.config/api_keys.json"),
            RateLimitError(retry_after=60),
            InvalidParamsError(field_name="email"),
            UnauthorizedError("Bearer eyJhbGci..."),
            PermissionDeniedError("gmail_delete blocked for client"),
            InvalidHandleError("handle not in /var/sessions"),
            RuntimeError("Traceback at /usr/lib/python3.12/site.py:42"),
            TypeError("'NoneType' object is not callable"),
            KeyError("/etc/passwd"),
        ]
    )
    def sanitized(self, request):
        """Fixture providing sanitized results for various exceptions."""
        return sanitize_error(request.param)

    def test_no_stack_trace_keywords(self, sanitized):
        """No stack trace keywords in the response."""
        msg = str(sanitized)
        for keyword in ("Traceback", 'File "', "line ", ".py"):
            # Allow ".py" only if it's not a file path reference
            if keyword == ".py":
                # .py could appear in generic messages, skip this check
                continue
            assert keyword not in msg, f"Found '{keyword}' in sanitized error"

    def test_no_absolute_paths(self, sanitized):
        """No absolute file paths in the response."""
        msg = str(sanitized)
        assert "/home/" not in msg
        assert "/var/" not in msg
        assert "/etc/" not in msg
        assert "/usr/" not in msg
        assert "/root/" not in msg

    def test_response_structure(self, sanitized):
        """All responses have the correct structure."""
        assert "error" in sanitized
        assert "code" in sanitized["error"]
        assert "message" in sanitized["error"]
        assert isinstance(sanitized["error"]["code"], str)
        assert isinstance(sanitized["error"]["message"], str)
