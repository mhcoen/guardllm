# OAuth Integration

This guide shows how to combine OAuth/OIDC with GuardLLM so tool execution is constrained by user-granted scopes.

Important boundary:
- GuardLLM is application-layer hardening.
- OAuth token issuance, validation, and least-privilege credentialing remain host-application responsibilities.

## Architecture

1. User authenticates with OAuth provider (Google, Microsoft, etc.).
2. Host app validates token/session and stores user scopes server-side.
3. Host app maps scopes to allowed tools/actions.
4. Host app builds GuardLLM `PolicyConfig` and `AuthorizationEvent` from that mapping.
5. GuardLLM enforces policy + binding + optional confirmation before tool execution.

## Scope Mapping Pattern

Example mapping:

- `gmail.readonly` -> `gmail_list_messages`, `gmail_get_message`
- `gmail.send` -> `gmail_send_email`
- `calendar.readonly` -> `calendar_list_events`
- `calendar.events` -> `calendar_create_event`, `calendar_update_event`

Keep mappings explicit and deny-by-default.

## End-to-End Example

```python
from guardllm import Guard
from guardllm.security.types import PolicyConfig


def scopes_to_tool_allowlist(scopes: set[str]) -> dict:
    allow = {}

    if "gmail.readonly" in scopes:
        allow[("gmail_list_messages", "implicit")] = {"required_fields": []}
        allow[("gmail_get_message", "implicit")] = {"required_fields": ["message_id"]}

    if "gmail.send" in scopes:
        allow[("gmail_send_email", "explicit")] = {
            "required_fields": ["to", "subject", "body"]
        }

    if "calendar.readonly" in scopes:
        allow[("calendar_list_events", "implicit")] = {"required_fields": []}

    if "calendar.events" in scopes:
        allow[("calendar_create_event", "explicit")] = {
            "required_fields": ["title", "start_time"]
        }
        allow[("calendar_update_event", "explicit")] = {
            "required_fields": ["event_id"]
        }

    return allow


def check_tool_with_oauth(
    user_id: str,
    oauth_scopes: set[str],
    tool: str,
    args: dict,
    user_message: str,
) -> bool:
    guard = Guard()

    policy = PolicyConfig(
        tool_allowlist=scopes_to_tool_allowlist(oauth_scopes),
        enable_destructive=True,
    )
    ctx = Guard.context_mcp_server(server_id=f"user:{user_id}", policy=policy)

    auth = Guard.authorize(
        action=tool,
        scope={"oauth_scopes": sorted(oauth_scopes), "user_id": user_id},
        user_message=user_message,
        source="oauth_intent_adapter",
        session_id=user_id,
    )
    binding = Guard.bind_request(
        tool=tool,
        args=args,
        authorization=auth,
        user_message=user_message,
    )

    result = guard.check_tool_call(
        tool=tool,
        args=args,
        context=ctx,
        authorization=auth,
        binding=binding,
        user_message=user_message,
    )
    return result.allowed
```

## Required Host-Side Controls

- Validate OAuth token signature/issuer/audience/expiry before GuardLLM checks.
- Use per-user tokens, not shared global API credentials.
- Keep token refresh and secret storage outside model/tool runtime.
- Re-check scopes on each sensitive action.
- Log scope set + decision outcome for auditability.

## Recommended Policy Rules

- Deny-by-default when scope is missing or ambiguous.
- Separate read and write tools by distinct scopes.
- Require explicit authorization (`confidence="explicit"`) for write/destructive tools.
- Use `bind_request` for all write-capable tools to prevent replay.
- Use `confirm_action` or `guard_tool_call(..., require_confirmation=True)` for high-impact operations.

## What GuardLLM Does Not Replace

- OAuth/OIDC login flows
- token storage and rotation
- provider-side least-privilege app registration
- network/runtime isolation and system IAM
