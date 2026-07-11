# Tutorial 03: Safe Tool Call Pipeline

Script:
- `tutorials/03_safe_tool_call_pipeline.py`

What it demonstrates:
1. Validate tool arguments.
2. Require explicit authorization (`AuthorizationEvent`).
3. Bind execution to request context (`Binding`).
4. Require L12 confirmation before destructive execution.
5. Run outbound checks before sending content externally.
6. Anti-replay message binding (`PolicyConfig(require_message_binding="destructive")`): the same authorization replayed after the conversation advances to a different user message is denied.
7. Egress feedback escalation: a DLP hard block at egress (e.g. a secret pattern in outbound content) tightens subsequent tool calls in the same session. With the default `escalated_tool_policy="require_auth"`, a later tool call without an authorization event is denied, and the reason names the trigger (`egress escalated=require_auth`).

Isolation note:
- This tutorial focuses on tool gating. In a full pipeline, any unknown-provenance inbound content should first be passed through `guard.process_inbound(...)`, which wraps it in `<untrusted_content ...>` blocks before it can influence tool arguments.

Run:

```bash
python tutorials/03_safe_tool_call_pipeline.py
```
