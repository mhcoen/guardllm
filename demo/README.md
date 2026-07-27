# GuardLLM generated demos

These self-contained pages are executable documentation generated from the shipped library.
Open `guardllm_surface_map.html` or any card directly with `file://`; no server or external
asset is required.

- `guardllm_demos.html`: primary cross-stage narrative
- `guardllm_surface_map.html`: shared architecture map and portfolio index
- `guardllm_pipeline_demo.html`: actual ingress order
- `guardllm_rag_demos.html`: provenance and lexical-overlap boundary
- `guardllm_tool_feedback_demo.html`: host feedback-loop obligation
- `guardllm_canary_demos.html`: DLP, entropy, decoding, and remembered canary
- `guardllm_policy_matrix_demo.html`: scoped policy lanes
- `guardllm_rate_limit_demo.html`: anomaly versus hard cap
- `guardllm_request_binding_demo.html`: argument-integrity binding

`guardllm_demo_fixtures.json` is the canonical generated data. Each page embeds its fixture
at build time, so no runtime fetch is used. Regenerate with:

```bash
.venv/bin/python scripts/build_demos.py
```

Verify checked-in fixtures and pages without modifying them:

```bash
.venv/bin/python scripts/build_demos.py --check
```
