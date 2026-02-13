# Tutorial 03: Safe Tool Call Pipeline

Script:
- `tutorials/03_safe_tool_call_pipeline.py`

What it demonstrates:
1. Validate tool arguments.
2. Require explicit authorization (`AuthorizationEvent`).
3. Bind execution to request context (`Binding`).
4. Require L2 confirmation before destructive execution.
5. Run outbound checks before sending content externally.

Run:

```bash
/Users/mhcoen/proj/episodic/.venv/bin/python tutorials/03_safe_tool_call_pipeline.py
```
