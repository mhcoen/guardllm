"""Demonstrate input validation + sanitized error responses before dispatch."""

from __future__ import annotations

from _bootstrap import ROOT  # noqa: F401

from guardllm.security.error_sanitizer import (
    InvalidParamsError,
    PermissionDeniedError,
    sanitize_error,
)
from guardllm.security.validation import validate_arguments


def checked_dispatch(tool: str, args: dict) -> dict:
    """Small dispatcher showing how to compose validation + error sanitization."""
    try:
        validation = validate_arguments(tool, args)
        if not validation.valid:
            field = validation.field_name or "unknown"
            raise InvalidParamsError(field_name=field)

        # Simulate policy failure from downstream subsystem.
        if tool == "gmail_delete_email":
            raise PermissionDeniedError("destructive action denied")

        return {"ok": True, "tool": tool, "args": args}
    except Exception as exc:  # sanitize all exceptions before returning
        return sanitize_error(exc)


def main() -> None:
    bad_args = {"thread_handle": "bad@#$"}
    result_invalid = checked_dispatch("search_knowledge", bad_args)
    print("[validation] invalid args sanitized response:", result_invalid)

    blocked_tool = checked_dispatch("gmail_delete_email", {"thread_handle": "ok_handle"})
    print("[error] permission denied sanitized response:", blocked_tool)


if __name__ == "__main__":
    main()
