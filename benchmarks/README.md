# Benchmarks

This directory provides an offline benchmark harness for evaluating guardllm against known threat patterns inspired by:
- PINT-style prompt-injection cases
- BIPIA-style indirect prompt-injection cases
- AgentDojo-style agent/tool security cases
- OWASP LLM Top 10-style threat profiles
- garak-style probe cases
- promptfoo red-team style cases
- MCP protocol abuse scenarios
- RAG poisoning scenarios
- secrets exfiltration scenarios
- multistep agent attack chains
- Unicode evasion attacks

## What this is

- A reproducible local regression suite for guardllm controls.
- A starter threat library in JSONL format under `benchmarks/cases/`.
- Versioned upstream-derived fixture snapshots under `benchmarks/upstream/`.
- A report generator writing to `benchmarks/results/latest.json`.

## Run

```bash
python benchmarks/run_benchmarks.py
```

Run a single suite:

```bash
python benchmarks/run_benchmarks.py --suite pint_style
```

## Case format

Each line in `benchmarks/cases/*.jsonl` is one JSON object with:
- `id`: stable case identifier
- `suite`: suite name (`pint_style`, `bipia_style`, `agentdojo_style`)
- `kind`: evaluator type (`inbound_sanitize`, `tool_gate`, `tool_gate_auth`, `outbound_check`, `validation`, `error_sanitize`, `binding_replay`, `action_gate`, `source_gate`, `canary_check`, `rate_limit`)
- additional fields required by that `kind`

## Current Suites

- `pint_style`
- `bipia_style`
- `agentdojo_style`
- `owasp_llm_top10_style`
- `garak_style`
- `promptfoo_redteam_style`
- `mcp_protocol_abuse_style`
- `rag_poisoning_style`
- `secrets_exfil_style`
- `multistep_agent_attack_style`
- `unicode_evasion_style`
- `upstream_pint`
- `upstream_bipia`
- `upstream_agentdojo`

## Notes

- These are local benchmark profiles and not a full mirror of upstream benchmark repos.
- The harness is designed to be extended with official benchmark exports/checkpoints as your next step.
- Upstream fixture provenance metadata is tracked in `benchmarks/upstream/manifest.json`.
