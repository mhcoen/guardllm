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

from vordur import Guard
from vordur.api import _string_leaves, joined_call_payload
from vordur.security.types import PolicyConfig, SecurityContext, TrustLevel


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
    #: The trust level a ``tool`` result is ingested under. ``system`` and
    #: ``user`` turns are operator-originated and are not ingested at all.
    #:
    #: This sets the trust of the one channel the gateway ingests; it does not
    #: add channels. A deployment that pipes untrusted text into *user* turns
    #: cannot declare that here, and this comment used to say it could. Doing
    #: so needs a role-to-provenance map rather than a single trust level, and
    #: until there is one the honest statement is that the gateway ingests tool
    #: results and nothing else. A host with untrusted text arriving on another
    #: role calls ``process_inbound`` for it in library mode.
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


def _record(chain: Any, stage: str, detail: str, outcome: str, reason: str, guard: Guard) -> None:
    """Append to the decision chain if one is being kept.

    Optional so the core stays usable without a viewer attached, and so a
    recording failure can never turn into a security decision.
    """
    if chain is not None:
        chain.record(stage=stage, detail=detail, outcome=outcome, reason=reason, guard=guard)


def inspect_request(
    body: dict[str, Any], guard: Guard, cfg: GatewayConfig, chain: Any = None
) -> None:
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
            reason = f"tool result from {name!r} withheld: " + "; ".join(
                result.warnings or ["de-identification failed"]
            )
            _record(chain, "ingest", name, "blocked", reason, guard)
            raise GatewayRefused("ingest", reason)
        # Recorded even when nothing was blocked, because THIS is the step a
        # later refusal points back to: the moment the session was labelled.
        _record(chain, "ingest", name, "recorded", "untrusted content ingested", guard)


def inspect_response(
    completion: dict[str, Any], guard: Guard, cfg: GatewayConfig, chain: Any = None
) -> None:
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
                _record(chain, "tool_call", name, "blocked", gate.reason, guard)
                raise GatewayRefused("tool_call", f"{name}: {gate.reason}")
            # Argument content is an outbound channel, and the gate above does
            # not read it: check_tool_call decides whether the ACTION is
            # permitted (policy, rate limit, binding) and says so in
            # docs/production_checklist.md. In library mode that is A-AS9, a
            # host obligation, because only the host knows which arguments
            # carry a payload. The gateway has no host to delegate it to, and
            # docs/threat_model.md says the proxy removes A-AS9 as something
            # the application can forget -- so the proxy has to do it.
            #
            # Measured before this existed: a credential lifted out of an
            # ingested tool result and placed in a send_email body was allowed
            # as a tool argument, while the same bytes as assistant text were
            # refused. That is the exfiltration path the layer exists for.
            #
            # Every string leaf, keys included, exactly as prepare_tool_call
            # does: checking one designated field would miss a canary in a
            # subject line or a credential in a filename.
            # check_outbound_content, not check_outbound: one tool call is one
            # outbound action, and check_outbound records an action against the
            # hourly quota every time it is called. Looping that over the leaves
            # charged a single send once per string, so the second tool call in
            # any session was refused with "Hourly limit exceeded (10/10)" and
            # stayed refused for the window. Escalation still fires from here.
            for leaf in _string_leaves(args):
                out = guard.check_outbound_content(leaf, egress)
                if not out.allowed:
                    reason = f"{name} arguments: {out.reason}"
                    _record(chain, "tool_call", name, "blocked", reason, guard)
                    raise GatewayRefused("egress", reason)
            # Then the whole call as one payload. A per-field scan sees each
            # argument alone, so a secret cut across two fields passed both
            # halves: {"left": "AKIA", "right": "IOSFODNN7EXAMPLE"} was allowed
            # while the same twenty characters in one field were blocked. What
            # leaves the boundary is the call, so the call is checked too. See
            # vordur.api.joined_call_payload for what this does not reach.
            joined = joined_call_payload(args)
            if joined:
                out = guard.check_outbound_content(joined, egress)
                if not out.allowed:
                    reason = f"{name} arguments (across fields): {out.reason}"
                    _record(chain, "tool_call", name, "blocked", reason, guard)
                    raise GatewayRefused("egress", reason)
            _record(chain, "tool_call", name, "allowed", gate.reason, guard)

        text = _message_text(message)
        if text:
            out = guard.check_outbound(text, egress)
            outcome = "allowed" if out.allowed else "blocked"
            _record(chain, "egress", "model", outcome, out.reason, guard)
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
    resolved_id, guard, chain = store.get(session_id)
    # One session is a sequence, and a Guard has no internal synchronization.
    # Held across the upstream call as well as the two inspections: see
    # SessionStore.lock_for for why releasing it over the network would break
    # the session-risk loop rather than merely racing a data structure.
    with store.lock_for(resolved_id):
        inspect_request(body, guard, cfg, chain)
        completion = call_upstream(body)
        inspect_response(completion, guard, cfg, chain)
    return _Decision(session_id=resolved_id, completion=completion)
