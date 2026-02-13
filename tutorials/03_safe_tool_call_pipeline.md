# Tutorial 03: Safe Tool Call Pipeline

Script:
- `tutorials/03_safe_tool_call_pipeline.py`

What it demonstrates:
1. Validate tool arguments.
2. Require explicit authorization (`AuthorizationEvent`).
3. Bind execution to request context (`Binding`).
4. Require L2 confirmation before destructive execution.
5. Run outbound checks before sending content externally.

Isolation note:
- This tutorial focuses on tool gating. In a full pipeline, any unknown-provenance inbound content should first be passed through `guard.process_inbound(...)`, which wraps it in `<untrusted_content ...>` blocks before it can influence tool arguments.

Run:

```bash
python tutorials/03_safe_tool_call_pipeline.py
```
