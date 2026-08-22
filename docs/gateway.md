# Gateway

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

An OpenAI-compatible proxy that runs the GuardLLM checks itself. An application
changes one line and makes no GuardLLM calls at all:

```python
client = OpenAI(base_url="http://localhost:8080/v1")  # was api.openai.com
```

Everything the library inspects already crosses that connection: tool results
inbound, and the model's tool calls and final text outbound.

## Running it

```bash
docker build -t guardllm/gateway .
docker run -p 8080:8080 -e GUARDLLM_UPSTREAM=https://api.openai.com/v1 guardllm/gateway
```

Or without the container:

```bash
pip install 'guardllm[yaml]'
python -m guardllm.gateway --upstream https://api.openai.com/v1
```

The client's `Authorization` header is forwarded to the model API verbatim.
**The gateway never has an upstream API key of its own**, so deploying it does
not mean handing a proxy your OpenAI credentials.

## What it enforces

The checks are the same ones the library runs, mapped onto the chat-completions
message array:

- A `tool` role message is a tool result re-entering the context. It is
  ingested and can contaminate the session, exactly as a retrieved document
  does in code.
- The model's reply is checked on the way back: tool-call arguments through the
  authorization gate, final text through the outbound DLP and provenance
  checks.

Because both happen against one session, the session-risk loop holds across
requests: an untrusted tool result in one call tightens tool authorization in
the next, under `contaminated_tool_policy`. A `X-GuardLLM-Session` request
header names the session; the gateway returns it on the response so the client
can send it back. A request with no session header gets a fresh, isolated
session rather than sharing one.

Provenance comes from the channel, never the content: a message's role and a
tool's name are structural facts about where bytes came from, so the library's
rule that nothing is inferred from content survives the move into a proxy. A
deployment that pipes untrusted text through a different channel declares that
in configuration.

## Configuration

| Environment variable | Flag | Default |
| --- | --- | --- |
| `GUARDLLM_UPSTREAM` | `--upstream` | `https://api.openai.com/v1` |
| `GUARDLLM_HOST` | `--host` | `0.0.0.0` |
| `GUARDLLM_PORT` | `--port` | `8080` |
| `GUARDLLM_POLICY` | `--policy` | none |

`GUARDLLM_POLICY` points at a YAML policy file; see
[configuration.md](configuration.md) for its shape.

## Failure behaviour

The gateway fails closed and loud. A blocked request or response becomes an
HTTP error the client sees, never a silently altered completion, because a
security proxy must never forward traffic it could not inspect. Audit events
are written to stdout as JSON lines, one per decision, for whatever log
collector the deployment runs.

`GET /healthz` returns the live session count for an orchestrator's health
check.

## What it is not, yet

This is the single-instance tier. Session state is in memory, so multiple
replicas do not share it, and streaming responses are not yet inspected
incrementally. Both are recorded in the strategy notes as later work.

## Related

- [configuration.md](configuration.md): the policy file the gateway loads.
- [security.md](security.md): the checks it runs, in library terms.
