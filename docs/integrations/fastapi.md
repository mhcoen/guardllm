# Integration: FastAPI

Use this pattern to guard inbound/outbound flows in a FastAPI service.

A `Guard` owns mutable session state: contamination, egress escalation,
provenance spans, DLP buffers, the remembered canary, and rate counters. One
module-level `Guard` shared by every request would leak all of that between
users, and concurrent requests would mutate it without synchronization. Hold
one per session instead, and serialize the calls that belong to it.

```python
import threading

from fastapi import Depends, FastAPI, Request
from guardllm import Guard

app = FastAPI()

# One Guard per session, not one per process, and a lock per session because
# the pipeline does not synchronize internally. Replace this registry with
# whatever already owns session lifetime in your service.
_guards: dict[str, tuple[Guard, threading.Lock]] = {}
_registry_lock = threading.Lock()


def authenticated_session_key(request: Request) -> str:
    """Derive the key from authenticated identity, never from the request body.

    A caller who can name another user's session gets that user's Guard, and
    can contaminate it, escalate it, and consume its rate budget. Replace this
    with your real auth dependency.
    """
    session_key = getattr(request.state, "session_key", None)
    if not session_key:
        raise PermissionError("unauthenticated request")
    return session_key


def guard_for(session_key: str) -> tuple[Guard, threading.Lock]:
    with _registry_lock:
        entry = _guards.get(session_key)
        if entry is None:
            entry = (Guard(canary_session_id=session_key), threading.Lock())
            _guards[session_key] = entry
        return entry


def end_session(session_key: str) -> None:
    """Drop the session's state when the session ends, so it cannot be reused."""
    with _registry_lock:
        _guards.pop(session_key, None)


@app.post("/generate")
async def generate(payload: dict, session_key: str = Depends(authenticated_session_key)):
    guard, session_lock = guard_for(session_key)
    ctx = Guard.context_web(source_id="http-client")

    # Hold the session lock for the whole guarded sequence: ingress, the model
    # call, and egress all read and mutate this session's state.
    with session_lock:
        text = payload.get("text", "")
        processed = guard.process_inbound(text, ctx)

        model_output = f"answer: {processed.content}"

        out = guard.check_outbound(model_output, ctx)
        if not out.allowed:
            return {"error": out.reason}

    return {"result": model_output}
```

Add authentication, structured logging, and domain-specific validation as needed.
