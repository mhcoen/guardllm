# Integration: FastAPI

Use this pattern to guard inbound/outbound flows in a FastAPI service.

A `Guard` owns mutable session state: contamination, egress escalation,
provenance spans, DLP buffers, the remembered canary, and rate counters. One
module-level `Guard` shared by every request would leak all of that between
users, and concurrent requests would mutate it without synchronization. Hold
one per session instead, and serialize the calls that belong to it.

```python
from fastapi import FastAPI
from guardllm import Guard
from guardllm.security.types import PolicyConfig

app = FastAPI()

# One Guard per session, not one per process. Replace this dict with whatever
# already owns session lifetime in your service; the point is that the Guard
# lives and dies with the session rather than with the worker.
_guards: dict[str, Guard] = {}


def guard_for(session_id: str) -> Guard:
    guard = _guards.get(session_id)
    if guard is None:
        guard = Guard(canary_session_id=session_id)
        _guards[session_id] = guard
    return guard


def end_session(session_id: str) -> None:
    """Drop the session's state when the session ends, so it cannot be reused."""
    _guards.pop(session_id, None)


@app.post("/generate")
async def generate(payload: dict):
    session_id = payload["session_id"]
    guard = guard_for(session_id)
    ctx = Guard.context_web(source_id="http-client")

    # Inbound hardening
    text = payload.get("text", "")
    processed = guard.process_inbound(text, ctx)

    # Model call (placeholder)
    model_output = f"answer: {processed.content}"

    # Outbound hardening
    out = guard.check_outbound(model_output, ctx)
    if not out.allowed:
        return {"error": out.reason}

    return {"result": model_output}
```

Add authentication, structured logging, and domain-specific validation as needed.
