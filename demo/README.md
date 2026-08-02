# GuardLLM generated demos

These self-contained pages combine results generated from the shipped library with reviewed
explanatory text. The fixture tests execute each displayed scenario exactly. Conceptual prose
and threat mappings remain reviewable documentation claims rather than library outputs. Open
`guardllm_surface_map.html` or any card directly with `file://`; no server or external asset is
required.

- `guardllm_demos.html`: primary cross-stage narrative
- `guardllm_surface_map.html`: shared architecture map and portfolio index
- `guardllm_security_context_demo.html`: what the host declares on each flow
- `guardllm_pipeline_demo.html`: instrumented ingress call order
- `guardllm_mcp_demo.html`: a third-party MCP tool surface, where a record asks in prose and only a user directive authorizes
- `guardllm_rag_demos.html`: provenance and lexical-overlap boundary
- `guardllm_tool_feedback_demo.html`: host feedback-loop obligation
- `guardllm_canary_demos.html`: DLP, entropy, decoding, and remembered canary
- `guardllm_policy_matrix_demo.html`: scoped policy lanes
- `guardllm_rate_limit_demo.html`: anomaly versus hard cap
- `guardllm_request_binding_demo.html`: argument-integrity binding

`guardllm_demo_fixtures.json` is the canonical generated data. Each page embeds its fixture
at build time, so no runtime fetch is used.

Every scenario declares the objects it ran against under `pipelines`, and every step names the
one it used. Each step also states how it relates to the steps before it: `independent` is a
fresh object standing alone, `branch` is a fresh object created to contrast with a named earlier
one, `sequential` is a further call on an object an earlier step already used, and `nested` is an
instrumented call site inside a single enclosing call. Only `sequential` steps carry state
forward, so four independent demonstrations are never displayed as one escalating session. Each
step reports `finding_layer` (the layer that produced its finding) separately from
`terminal_layer` (the last layer the call reached), because a permitted egress check continues
past provenance to the rate limiter.

Step metadata is the only authority. A scenario names the step its page leads with through
`headline_step_id` rather than restating that step's finding and layers at the top, which would
put one step's attribution next to whole-run state. The ingress scenario additionally records
`enclosing_call`, because each of its steps is an instrumented call site inside a single
`process_inbound` call that no step represents on its own.

Regenerate with:

```bash
.venv/bin/python scripts/build_demos.py
```

Verify checked-in fixtures and pages without modifying them:

```bash
.venv/bin/python scripts/build_demos.py --check
```
