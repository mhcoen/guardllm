"""Server-mode error sanitization (spec §12.6).

Maps internal exceptions to generic error responses that leak no
internal state (no stack traces, file paths, SQL, or model names).
"""

from __future__ import annotations

import sqlite3
from typing import Any


class RateLimitError(Exception):
    """Raised when rate limits are exceeded."""

    def __init__(self, retry_after: int = 60):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded, retry after {retry_after}s")


class InvalidHandleError(Exception):
    """Raised when a thread handle is invalid or expired."""


class InvalidParamsError(Exception):
    """Raised when request parameters are invalid."""

    def __init__(self, field_name: str = "unknown"):
        self.field_name = field_name
        super().__init__(f"Invalid parameters: {field_name}")


class PermissionDeniedError(Exception):
    """Raised when a tool is not available to the client."""


class UnauthorizedError(Exception):
    """Raised when the capability token is invalid."""


# Error code mapping: exception type → (code, message template)
_ERROR_MAP: dict[type, tuple[str, str]] = {
    UnauthorizedError: ("unauthorized", "Invalid or expired token"),
    PermissionDeniedError: ("permission_denied", "Tool not available"),
    InvalidHandleError: ("invalid_handle", "Invalid or expired thread handle"),
    sqlite3.OperationalError: ("internal_error", "Request could not be processed"),
    FileNotFoundError: ("internal_error", "Request could not be processed"),
}


def sanitize_error(
    exception: Exception,
    retry_after: int | None = None,
) -> dict[str, Any]:
    """Map an exception to a sanitized error response.

    Rules (spec §12.6):
    1. No stack traces in any error response.
    2. No file paths, table names, column names, or SQL fragments.
    3. No model names, provider names, or API keys.
    4. invalid_params may include field name but never field value.
    5. Uncaught exceptions map to internal_error.
    6. Rate limit errors include retry_after.

    Args:
        exception: The caught exception.
        retry_after: Override retry_after for rate limit errors.

    Returns:
        Dict with {"error": {"code": ..., "message": ...}}.
    """
    # Rate limit errors
    if isinstance(exception, RateLimitError):
        seconds = retry_after if retry_after is not None else exception.retry_after
        return {
            "error": {
                "code": "rate_limited",
                "message": f"Rate limit exceeded, retry after {seconds}s",
            }
        }

    # Invalid params (may include field name)
    if isinstance(exception, InvalidParamsError):
        return {
            "error": {
                "code": "invalid_params",
                "message": f"Invalid parameters: {exception.field_name}",
            }
        }

    # Validation failures with field info
    if isinstance(exception, ValueError) and hasattr(exception, "field_name"):
        return {
            "error": {
                "code": "invalid_params",
                "message": f"Parameter {exception.field_name} exceeds limits",  # type: ignore[attr-defined]
            }
        }

    # Known exception types
    for exc_type, (code, message) in _ERROR_MAP.items():
        if isinstance(exception, exc_type):
            return {"error": {"code": code, "message": message}}

    # Catch-all: internal_error with no details
    return {
        "error": {
            "code": "internal_error",
            "message": "Request could not be processed",
        }
    }
