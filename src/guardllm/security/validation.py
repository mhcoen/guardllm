"""Server-mode input validation (spec §12.2).

Validates tool arguments before any security layer processes them.
Rejects the entire request if any argument fails validation.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from guardllm.security.types import ValidationResult

# Argument limits from spec §12.2
ARGUMENT_LIMITS: Dict[str, Dict[str, Any]] = {
    "message": {"max_chars": 50_000, "strip_unicode": True},
    "content": {"max_chars": 500_000, "strip_unicode": True},
    "query": {"max_chars": 1_000, "strip_unicode": True},
    "source_name": {"max_chars": 200, "pattern": r"^[\w\-. /]+$"},
    "thread_handle": {"max_chars": 100, "pattern": r"^[A-Za-z0-9_\-]+$"},
    "provenance": {"max_fields": 10, "max_value_chars": 500},
}


def validate_arguments(tool: str, args: Dict[str, Any]) -> ValidationResult:
    """Validate all arguments for a tool invocation.

    No partial acceptance: if any argument fails, the entire request is
    rejected. Validation runs before any security layer.

    Args:
        tool: Tool name (for context in error messages).
        args: Argument dict from the MCP request.

    Returns:
        ValidationResult with valid=True if all checks pass.
    """
    errors: list[str] = []

    for arg_name, value in args.items():
        limits = ARGUMENT_LIMITS.get(arg_name)
        if limits is None:
            # Unknown fields silently ignored (defense against schema probing)
            continue

        if arg_name == "provenance":
            # Special handling for structured provenance field
            if isinstance(value, dict):
                max_fields = limits.get("max_fields", 10)
                max_val = limits.get("max_value_chars", 500)
                if len(value) > max_fields:
                    errors.append(
                        f"Parameter {arg_name} exceeds maximum fields "
                        f"({len(value)} > {max_fields})"
                    )
                for k, v in value.items():
                    if isinstance(v, str) and len(v) > max_val:
                        errors.append(
                            f"Parameter {arg_name}.{k} exceeds maximum size"
                        )
            continue

        if not isinstance(value, str):
            continue

        # Check max_chars
        max_chars = limits.get("max_chars")
        if max_chars is not None and len(value) > max_chars:
            errors.append(
                f"Parameter {arg_name} exceeds maximum size"
            )

        # Check for path traversal sequences
        if ".." in value:
            errors.append(
                f"Parameter {arg_name} contains path traversal"
            )

        # Check pattern
        pattern = limits.get("pattern")
        if pattern is not None and not re.match(pattern, value):
            errors.append(
                f"Parameter {arg_name} exceeds limits"
            )

    if errors:
        return ValidationResult(
            valid=False,
            errors=errors,
            field_name=errors[0].split()[1] if errors else None,
        )

    return ValidationResult(valid=True)
