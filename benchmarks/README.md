# Benchmarks

This directory provides an offline benchmark harness for evaluating guardllm against known threat patterns inspired by:
- PINT-style prompt-injection cases
- BIPIA-style indirect prompt-injection cases
- AgentDojo-style agent/tool security cases

## What this is

- A reproducible local regression suite for guardllm controls.
- A starter threat library in JSONL format under `benchmarks/cases/`.
- A report generator writing to `benchmarks/results/latest.json`.

## Run

```bash
/Users/mhcoen/proj/episodic/.venv/bin/python benchmarks/run_benchmarks.py
```

Run a single suite:

```bash
/Users/mhcoen/proj/episodic/.venv/bin/python benchmarks/run_benchmarks.py --suite pint_style
```

## Case format

Each line in `benchmarks/cases/*.jsonl` is one JSON object with:
- `id`: stable case identifier
- `suite`: suite name (`pint_style`, `bipia_style`, `agentdojo_style`)
- `kind`: evaluator type (`inbound_sanitize`, `tool_gate`, `outbound_check`, `validation`, `error_sanitize`, `binding_replay`, `action_gate`)
- additional fields required by that `kind`

## Notes

- These are local benchmark profiles and not a full mirror of upstream benchmark repos.
- The harness is designed to be extended with official benchmark exports/checkpoints as your next step.
