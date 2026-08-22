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

## Seeing the decision chain

`GET /forensics` lists live sessions; `GET /forensics/<session-id>` shows one
session's decisions in order, with the state each left behind:

```
1. ingest     web_search   recorded  [contaminated]  untrusted content ingested
2. egress     model        allowed   [contaminated]  clean
3. tool_call  wire_funds   BLOCKED   [contaminated]  Tool call denied: session contaminated=deny
```

Step 3 is only explicable by step 1, and they arrived in different requests.
That is the thing a per-request log cannot show and the reason this view
exists: a content filter produces a list of independent verdicts, while the
fact that carries forward is what GuardLLM adds.

The same data is available as JSON at `GET /sessions` and
`GET /sessions/<session-id>` for scripting.

The page holds no content: a step names the stage, the tool or source it
concerned, and the verdict. It fetches nothing, has no JavaScript, and renders
offline. Sessions are in memory and lost on restart; retention, search and
history across restarts are the console, not this.

## Diagnostics

`GET /support` returns a diagnostic bundle as JSON, and
`GET /support/<session-id>` includes that session's decision chain. It is the
whole of what a support ticket needs from a deployment nobody outside your
network can reach: the resolved policy with the settings that differ from the
default named, versions, and whether the optional extras can actually be
imported. It carries no message content, reports `GUARDLLM_*` variables by name
and never by value, and is scanned for credentials before it is returned. A
credential it recognizes but cannot replace exactly makes the endpoint answer
`409` rather than return a file that looks cleaned and is not. See
[support.md](support.md).

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
