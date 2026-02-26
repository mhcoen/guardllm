# Integration Templates

Copy-paste templates for quickly integrating guardllm into LLM applications.

## Template: MCP Server Request Guard

Use this in your server tool-dispatch path.

```python
from guardllm import Guard
from guardllm.security.error_sanitizer import InvalidParamsError
from guardllm.security.types import PolicyConfig


guard = Guard()


def handle_request(request: dict, dispatch_tool) -> dict:
    tool = request["tool"]
    args = dict(request.get("args", {}))
    client_id = request.get("client_id", "unknown-client")

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
import time
from guardllm import Guard
from guardllm.security.types import PolicyConfig


guard = Guard(canary_session_id="session-1")


async def guarded_call(transport, tool: str, args: dict, user_message: str):
    ctx = Guard.context_mcp_server(
        server_id="mcp-gsuite",
        policy=PolicyConfig(enable_destructive=True),
    )

    auth = Guard.authorize(
        action=tool,
        scope={"to": args.get("to")},
        user_message=user_message,
        timestamp=time.time(),
    )
    binding = Guard.bind_request(tool=tool, args={"to": args.get("to")}, authorization=auth)

    gate = await guard.guard_tool_call(
        tool=tool,
        args={"to": args.get("to")},
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

guard = Guard()

email_ctx = SecurityContext(
    mode="client",
    source_type="email_content",
    source_id="msg-123",
    source_trust=TrustLevel.UNTRUSTED,
    content_type=ContentType.HTML,
)

processed = guard.process_inbound(raw_email_html, email_ctx)
safe_text = processed.content
# safe_text includes <untrusted_content ...> wrapper
```
