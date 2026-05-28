"""Layer 11: Request binding (Part 9b).

Binds tool calls to the authorizing user message. Prevents deferred
execution replay attacks where a tool call approved in one context is
replayed after the conversation has advanced.
"""

from __future__ import annotations

import hashlib
import json
import time

from guardllm.security.types import AuthorizationEvent, Binding


def _canonical_args(args: dict) -> str:
    """Produce a canonical string representation of tool args for hashing."""
    return json.dumps(args, sort_keys=True, separators=(",", ":"))


def create_binding(
    tool: str,
    args: dict,
    auth_event: AuthorizationEvent | None = None,
    message_hash: str | None = None,
    ttl: float = 120.0,
) -> Binding:
    """Create a binding for a proposed tool execution.

    Args:
        tool: Tool name.
        args: Tool arguments.
        auth_event: Authorization event (preferred source of message_hash).
        message_hash: Fallback message hash if no auth_event.
        ttl: Time-to-live in seconds (default 120s from spec).

    Returns:
        Binding object with hashes for later verification.
    """
    msg_hash = auth_event.message_hash if auth_event else (message_hash or "")
    args_hash = hashlib.sha256(_canonical_args(args).encode()).hexdigest()
    binding_payload = f"{tool}:{args_hash}:{msg_hash}"
    b_hash = hashlib.sha256(binding_payload.encode()).hexdigest()

    return Binding(
        tool_name=tool,
        args_hash=args_hash,
        message_hash=msg_hash,
        binding_hash=b_hash,
        created_at=time.time(),
        ttl=ttl,
    )


def verify_binding(
    binding: Binding,
    tool: str,
    args: dict,
    current_message_hash: str,
) -> tuple[bool, str]:
    """Verify a binding matches the current execution context.

    Checks (spec Part 9b):
    1. Tool name matches
    2. Args hash matches (args haven't been tampered with)
    3. Message hash matches (conversation hasn't advanced)
    4. TTL hasn't expired

    Args:
        binding: The binding created at proposal time.
        tool: Tool being executed.
        args: Args being executed.
        current_message_hash: Hash of the current user message.

    Returns:
        (valid, reason) tuple.
    """
    # Check TTL first (cheapest check)
    if binding.expired:
        return False, "Binding expired (TTL exceeded)"

    # Reject empty hashes: a binding with no message hash is not a valid binding
    if not binding.message_hash and not current_message_hash:
        return False, "Empty binding hashes (no message context)"

    # Check tool name
    if binding.tool_name != tool:
        return False, f"Tool mismatch: bound={binding.tool_name}, executing={tool}"

    # Check args hash
    args_hash = hashlib.sha256(_canonical_args(args).encode()).hexdigest()
    if binding.args_hash != args_hash:
        return False, "Args hash mismatch (arguments changed since proposal)"

    # Check message hash (conversation hasn't advanced)
    if binding.message_hash != current_message_hash:
        return False, "Message hash mismatch (conversation advanced)"

    return True, "Binding verified"
