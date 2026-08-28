# Troubleshooting and FAQ

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

## My tool call was blocked. What should I check first?

1. Check `GateResult.reason` from `check_tool_call(...)` or `guard_tool_call(...)`.
2. Confirm `PolicyConfig.enable_destructive=True` for destructive tools.
3. Confirm authorization action/scope exactly matches tool + args.
4. If using binding, confirm same message hash/context (no replay mismatch).
5. If `require_confirmation=True`, ensure `context.confirmation_handler` is set and approves.

## Outbound content is blocked by DLP/provenance

Common causes:
- too much overlap with ingested untrusted content
- secret-like token patterns in output
- canary token leakage

What to do:
- summarize or transform untrusted source text instead of copying verbatim
- avoid passing raw secrets into model output paths
- if intentional quotation is needed, pass `has_quoting_directive=True` to `check_outbound(...)`

## Why are confirmations always denied?

L12 is fail-closed:
- If `confirmation_handler` is not set in `SecurityContext`, confirmation returns deny.

Fix:
- attach a handler implementation to `context.confirmation_handler`.

## Validation failed with `thread_handle` or `source_name`

Validation enforces format and path-traversal protections.

Fixes:
- ensure `thread_handle` uses allowed characters (`[A-Za-z0-9_-]`)
- avoid `..` and invalid symbols in controlled fields

## Benchmark case failures after code changes

1. Run: `python benchmarks/run_benchmarks.py`
2. Inspect: `benchmarks/runs/<run_id>/latest.json` (or run id in `benchmarks/runs/LATEST.txt`)
3. Use failing case IDs to reproduce in unit tests.

## FAQ

### Do I need to use MCP to use Vörður?
No. Vörður hardens LLM applications generally; MCP is one common integration surface.

### Can I bypass L12 manual confirmation?
Yes, by setting `require_confirmation=False` (or using `check_tool_call(...)` directly), but this reduces safety for high-impact actions.

### Should I always treat inbound content as untrusted?
For external or mixed provenance, yes. Start with `UNTRUSTED` and tighten only when provenance is strong and auditable.
