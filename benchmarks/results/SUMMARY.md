# Benchmark Summary

Snapshot source files:
- `benchmarks/results/latest.json`
- `benchmarks/results/comparison.json`
- `benchmarks/upstream/manifest.json`

## Overall GuardLLM Regression

- Total: `10146`
- Passed: `9927`
- Failed: `219`
- Pass rate: `97.84%`

Local suites:
- `82/82` (`100%`)

Upstream suites:
- `9845/10064` (`97.82%`)

## Text Comparison (Expanded Corpus)

- Record count: `3823` (prompt-injection text scope)
- `guardllm`: accuracy `93.17%`, precision `99.10%`, recall `75.12%`
- `bedrock_guardrails (HIGH)`: accuracy `78.50%`, precision `100.0%`, recall `19.49%`
- `regex_rule_based`: accuracy `73.37%`, precision `100.0%`, recall `0.29%`
- `no_defense`: accuracy `73.29%`, precision `0.0%`, recall `0.0%`
- Note: this summary reflects the latest `comparison.json` run configuration. Provider-enabled rows (OpenAI/Anthropic/Azure) are tracked in the main `README.md` table from provider-enabled runs on the same text scope.
- Full-suite benign correctness and text-only precision are different denominators: full suite includes non-text and out-of-scope benign cases.

| Strategy | Accuracy | F1 | Avg Latency |
|---|---:|---:|---:|
| GuardLLM | 93.17% | 85.46 | 0.07ms |
| Bedrock Guardrails (`HIGH`) | 78.50% | 32.62 | 748.27ms |
| Regex rule baseline | 73.37% | 0.58 | 0.00ms |
| No defense | 73.29% | 0.00 | 0.00ms |

## Non-Text Comparison

All non-text cases:
- Count: `5230`
- `guardllm_non_text`: `100.0%`
- `casbin_rbac`: `86.98%`
- `policy_opa`: `48.32%`
- `non_text_stack`: `61.17%`

Non-text excluding `source_gate`:
- Count: `4061`
- `guardllm_non_text`: `100.0%`
- `strict_schema_stack`: `99.95%`
- `casbin_rbac`: `83.23%`
- `non_text_stack`: `49.99%`
- `policy_opa`: `33.44%`

Non-text kind distribution:
- `tool_gate`: `679`
- `tool_gate_auth`: `674`
- `binding_replay`: `676`
- `validation`: `674`
- `action_gate`: `678`
- `rate_limit`: `674`
- `error_sanitize`: `6`
- `source_gate`: `1169`

## Pinned Upstream Inputs

- `pint` @ `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8`
- `bipia` @ `a004b69ec0dd446e0afd461d98cb5e96e120a5d0`
- `agentdojo` @ `462c88ddf596cb745882702f9999c8aeb5fe467f`
- `jailbreakbench` @ `886acc352a31533ffbcf4ef22c744658688086fc`
- `harmbench` @ `8e1604d1171fe8a48d8febecd22f600e462bdcdd`
- `injecagent` @ `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`
- `mcpbench` @ `5f397445370e6cb44dfdfc5680a48f128a75d349`
- `mcp_bench` @ `7a8eaeae83a842a2949080acc5473f65e1569daf`
- `wainjectbench` @ `4a5b7a5d4e393983d7105aed3485014b7206d205`
