"""The gateway core: inspect one chat-completion request and its response.

No HTTP here. This takes a parsed request body and a Guard, decides what to
send upstream, and inspects what comes back, so every rule is testable without
a socket. The HTTP shell in ``server.py`` calls exactly these functions.

The OpenAI chat-completions shape is the surface, because an OpenAI-compatible
gateway sees tool calls anyway through function calling, so it costs no
capability over an MCP proxy, only provenance quality that config-declared
trust recovers.

Where each check maps onto the message array:

- A ``tool`` role message is a tool RESULT re-entering the context. It is
  content of non-operator origin, so it is run through ``process_inbound`` and
  contaminates the session exactly as an ingested document does.
- The model's reply carries tool CALLS and final text. Tool-call arguments go
  through ``check_tool_call`` and the text through ``check_outbound``, both
  reading the session state the inbound pass just wrote.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from guardllm import Guard
from guardllm.security.types import PolicyConfig, SecurityContext, TrustLevel


class GatewayRefused(Exception):
    """A request or response was blocked. Carries the reason and which stage.

    The gateway fails closed and loud: this becomes an HTTP error the client
    sees, never a silently altered completion, because a security product must
    not degrade its own guarantee without saying so.
    """

    def __init__(self, stage: str, reason: str, *, status: int = 403) -> None:
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason
        self.status = status


@dataclass
class GatewayConfig:
    """How the gateway maps channel structure onto trust.

    ``tool_result_trust`` is the config-declared provenance the strategy calls
    for: an operator statement, moved from code into configuration, about where
    a channel's bytes come from. Nothing is inferred from what a message says.
    """

    upstream_base_url: str = "https://api.openai.com/v1"
    #: Trust for each message role that re-enters the context. Only ``tool``
    #: results are treated as untrusted ingest by default; ``system`` and
    #: ``user`` are operator-originated. A deployment that pipes untrusted text
    #: into user turns declares that here.
    tool_result_trust: TrustLevel = TrustLevel.UNTRUSTED
    #: Applied to every session's Guard. None means library defaults.
    policy: PolicyConfig | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tool_result_trust, TrustLevel):
            raise ValueError("tool_result_trust must be a TrustLevel")


def _tool_result_context(cfg: GatewayConfig, name: str) -> SecurityContext:
    """Provenance for a tool result, keyed on the tool name (a channel fact)."""
    return Guard.context_mcp_server(
        server_id=name or "tool",
        source_trust=cfg.tool_result_trust,
        policy=cfg.policy,
    )


def _egress_context(cfg: GatewayConfig) -> SecurityContext:
    """Provenance for the model's own output on the way back to the client."""
    return Guard.context_mcp_server(server_id="model", policy=cfg.policy)


def _message_text(message: dict[str, Any]) -> str:
    """The text of a chat message, whether it is a string or a content-part list.

    OpenAI accepts ``content`` as a string or as a list of typed parts. A tool
    result may arrive either way, and a part this does not recognise is skipped
    rather than guessed at.
    """
    content = message.get("content")
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return ""


def inspect_request(body: dict[str, Any], guard: Guard, cfg: GatewayConfig) -> None:
    """Run every tool-result message through inbound ingest.

    Mutates session state (contamination, provenance) and raises
    ``GatewayRefused`` if ingest blocks. The request body is not rewritten:
    tool results are host-supplied, and rewriting them would change what the
    model sees without the client's knowledge. Blocking is the honest action.
    """
    messages = body.get("messages")
    if not isinstance(messages, list):
        raise GatewayRefused("request", "body has no 'messages' array", status=400)

    for message in messages:
        if not isinstance(message, dict):
            raise GatewayRefused("request", "a message is not an object", status=400)
        if message.get("role") != "tool":
            continue
        text = _message_text(message)
        if not text:
            continue
        name = message.get("name") or "tool"
        ctx = _tool_result_context(cfg, name)
        result = guard.process_inbound(text, ctx)
        if result.blocked:
            raise GatewayRefused(
                "ingest",
                f"tool result from {name!r} withheld: "
                + "; ".join(result.warnings or ["de-identification failed"]),
            )


def inspect_response(completion: dict[str, Any], guard: Guard, cfg: GatewayConfig) -> None:
    """Check the model's tool calls and final text against session state.

    Raises ``GatewayRefused`` on the first block. Runs after
    ``inspect_request``, so contamination and escalation written by an
    untrusted tool result are already in force here, which is the whole point
    of doing both in one pass.
    """
    choices = completion.get("choices")
    if not isinstance(choices, list):
        return  # nothing to inspect; an error body upstream is passed through

    egress = _egress_context(cfg)
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            continue

        for call in message.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") or {}
            name = fn.get("name") or "tool"
            raw_args = fn.get("arguments")
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
            except json.JSONDecodeError:
                args = {"_raw": raw_args}
            if not isinstance(args, dict):
                args = {"_value": args}
            gate = guard.check_tool_call(name, args, egress)
            if not gate.allowed:
                raise GatewayRefused("tool_call", f"{name}: {gate.reason}")

        text = _message_text(message)
        if text:
            out = guard.check_outbound(text, egress)
            if not out.allowed:
                raise GatewayRefused("egress", out.reason)


@dataclass
class _Decision:
    """Result of guarding a full request/response cycle, for the HTTP layer."""

    session_id: str
    completion: dict[str, Any]
    refusal: GatewayRefused | None = field(default=None)


def guard_chat_completion(
    body: dict[str, Any],
    *,
    session_id: str | None,
    store: Any,
    cfg: GatewayConfig,
    call_upstream: Callable[[dict[str, Any]], dict[str, Any]],
) -> _Decision:
    """Guard one chat-completion round trip.

    ``call_upstream`` is injected: the core does not own the HTTP client, so a
    test drives it with a stub and the server passes a real one. Inbound is
    checked BEFORE the upstream call, so a blocked tool result never reaches
    the model; the response is checked after.
    """
    resolved_id, guard = store.get(session_id)
    inspect_request(body, guard, cfg)
    completion = call_upstream(body)
    inspect_response(completion, guard, cfg)
    return _Decision(session_id=resolved_id, completion=completion)
