# Integration: FastAPI

Use this pattern to guard inbound/outbound flows in a FastAPI service.

```python
from fastapi import FastAPI
from guardllm import Guard
from guardllm.security.types import PolicyConfig

app = FastAPI()
guard = Guard()

@app.post("/generate")
async def generate(payload: dict):
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
