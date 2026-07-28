# Integration Templates

Copy-paste templates for quickly integrating guardllm into LLM applications.

## Template: MCP Server Request Guard

Use this in your server tool-dispatch path.

```python
import threading

from guardllm import Guard
from guardllm.security.error_sanitizer import InvalidParamsError
from guardllm.security.types import PolicyConfig


# One Guard per session, never one per process. A Guard owns contamination,
# egress escalation, provenance, DLP buffers, the remembered canary, and rate
# counters. Sharing one across clients leaks all of that between them.
#
# The pipeline does not synchronize internally, so each session's Guard is
# handed out under a lock together with that session's own lock, and callers
# hold the session lock for the whole guarded sequence.
_guards: dict[str, tuple[Guard, threading.Lock]] = {}
_registry_lock = threading.Lock()


def guard_for(session_key: str) -> tuple[Guard, threading.Lock]:
    """Look up this session's Guard and its lock.

    `session_key` MUST come from authenticated session or transport identity.
    Never take it from the request body: a caller who can name another user's
    session gets that user's Guard, and can contaminate it, escalate it, and
    consume its rate budget.
    """
    with _registry_lock:
        entry = _guards.get(session_key)
        if entry is None:
            entry = (Guard(canary_session_id=session_key), threading.Lock())
            _guards[session_key] = entry
        return entry


def end_session(session_key: str) -> None:
    with _registry_lock:
        _guards.pop(session_key, None)


def handle_request(request: dict, dispatch_tool, *, session_key: str) -> dict:
    # session_key is supplied by the caller from authenticated identity, not
    # read out of `request`.
    tool = request["tool"]
    args = dict(request.get("args", {}))
    client_id = request.get("client_id", "unknown-client")
    guard, session_lock = guard_for(session_key)
    with session_lock:
        ctx = Guard.context_mcp_client(
            client_id=client_id,
            policy=PolicyConfig(
                capability_scopes={"search_knowledge": {}, "get_topics": {}},
                enable_destructive=False,
            ),
        )

        validation = guard.validate_tool_args(tool, args)
        if not validation.valid:
            return guard.sanitize_exception(InvalidParamsError(validation.field_name or "unknown"))

        for key, value in list(args.items()):
            if isinstance(value, str):
                args[key] = guard.process_inbound(value, ctx).content

        gate = guard.check_tool_call(tool=tool, args=args, context=ctx)
        if not gate.allowed:
            return {"error": {"code": "permission_denied", "message": gate.reason}}

        result = dispatch_tool(tool, args)

        out = guard.check_outbound(str(result), ctx)
        if not out.allowed:
            return {"error": {"code": "blocked", "message": out.reason}}

        return result
```

## Template: MCP Client Tool Invocation Guard

Use this before calling remote MCP tools.

```python
import dataclasses
import time

from guardllm import Guard
from guardllm.security.types import PolicyConfig


class CliConfirmation:
    """Ask the operator. Without a handler, require_confirmation always denies.

    `require_confirmation=True` with no `confirmation_handler` on the context is
    not "prompt the user": there is nothing to prompt with, so the gate fails
    closed on every destructive call. Install a handler or do not ask for
    confirmation.
    """

    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        answer = input(f"Allow {tool} with {args}? [y/N] ")
        return answer.strip().lower() == "y"


async def guarded_call(guard: Guard, transport, tool: str, args: dict, user_message: str):
    # guard.canary_token belongs in private system context before the model is
    # invoked, so a leaked copy is identifiable at egress.
    ctx = Guard.context_mcp_server(
        server_id="mcp-gsuite",
        policy=PolicyConfig(enable_destructive=True),
    )
    # The handler rides on the context. require_confirmation=True below is only
    # meaningful because this is set; without it the call is denied every time.
    ctx = dataclasses.replace(ctx, confirmation_handler=CliConfirmation())

    # Authorize, bind, gate, and dispatch the EXACT SAME args object. Never
    # gate a subset (e.g. just {"to": ...}) and dispatch a superset: fields
    # outside the authorized scope (bcc, body, attachments, provider options)
    # would otherwise bypass scope, binding, validation, and confirmation.
    # The authorization scope encodes what the user actually approved; any arg
    # key not covered by it is rejected by guard_tool_call.
    auth = Guard.authorize(
        action=tool,
        scope=args,
        user_message=user_message,
        timestamp=time.time(),
    )
    binding = Guard.bind_request(tool=tool, args=args, authorization=auth)

    gate = await guard.guard_tool_call(
        tool=tool,
        args=args,
        context=ctx,
        authorization=auth,
        binding=binding,
        user_message=user_message,
        require_confirmation=True,
        summary=f"Execute {tool}",
        validate=True,
    )
    if not gate.allowed:
        return {"error": gate.reason}

    out = guard.check_outbound(str(args), ctx)
    if not out.allowed:
        return {"error": out.reason}

    return transport.call_tool(tool, args)
```

## Template: Unknown-Provenance Ingestion

Use this before passing external content to your LLM.

```python
from guardllm import Guard
from guardllm.security.types import ContentType, SecurityContext, TrustLevel


def ingest_email(guard: Guard, raw_email_html: str) -> str:
    """The Guard is supplied by the session manager, as everywhere on this page.

    It holds the provenance and DLP state that later egress checks compare
    against, so it must be the same Guard those checks will use.
    """
    email_ctx = SecurityContext(
        mode="client",
        source_type="email_content",
        source_id="msg-123",
        source_trust=TrustLevel.UNTRUSTED,
        content_type=ContentType.HTML,
    )

    processed = guard.process_inbound(raw_email_html, email_ctx)
    # processed.content includes the <untrusted_content ...> wrapper
    return processed.content
```
