# guardllm Documentation

This directory contains architecture and integration documentation for using guardllm to harden MCP servers, MCP clients, and unknown-provenance input sources (web search, email, documents, calendar data, and other untrusted content).

## Documents

- [quick_start.md](quick_start.md): simple, interaction-focused setup for first integration.
- [security.md](security.md): Defense-in-depth architecture and layer-by-layer controls.
- [threat_model.md](threat_model.md): adversaries, trust boundaries, threats, and the assumptions each mitigation rests on.
- [api.md](api.md): Stable public API (`Guard`) and usage contract.
- [api_spec.md](api_spec.md): exhaustive API contract (full signatures, defaults, return types, and error semantics).
- [integration.md](integration.md): Practical integration patterns for MCP server/client systems.
- [oauth_integration.md](oauth_integration.md): mapping OAuth scopes to Guard policy and tool-gating decisions.
- [integration_templates.md](integration_templates.md): copy-paste templates for MCP server/client and untrusted-input ingestion.
- [gateway.md](gateway.md): the OpenAI-compatible proxy that runs the checks itself, so an application changes only its `base_url`.
- [rego.md](rego.md): writing an access policy in Rego against the session facts GuardLLM computes, evaluated locally.
- [privacy.md](privacy.md): pseudonymization at the model boundary, and the two policies that decide where a real value may be restored.
- [support.md](support.md): the diagnostic bundle a customer-hosted deployment produces for a support ticket, and what it refuses to carry.
- [configuration.md](configuration.md): Policy controls and deployment guidance.
- [policy_tuning.md](policy_tuning.md): guidance for safely tuning policy strictness.
- [troubleshooting.md](troubleshooting.md): common failure modes, fixes, and FAQ.
- [production_checklist.md](production_checklist.md): deployment checklist for production hardening and operations.

## Visual mechanism guide

Six illustrated explanations, one mechanism each, for readers meeting the
architecture for the first time. They are normative about mechanism and carry no
measurements: the Markdown documents above remain the authoritative specification.

- [All six strips](mechanisms/index.html), with a map of how they interlock.
- [01 What the Guard Remembers](mechanisms/01-session-risk.html): a fact recorded at
  ingest denies a tool call two turns later, and why four point tools cannot.
- [02 A Marker Only the Model Sees](mechanisms/02-canary.html): canary tokens, and
  what a match proves.
- [03 The Call That Came Back](mechanisms/03-request-binding.html): request binding
  and deferred-execution replay.
- [04 Nothing Crosses By Name](mechanisms/04-privacy-vault.html): substitution at the
  model boundary and the two gates on the way back.
- [05 The Path Around the Guard](mechanisms/05-mediated-paths.html): why installed is
  not the same as in the way, and what the gateway does about it.
- [06 One Call, Two Questions](mechanisms/06-two-questions.html): the tool gate rules
  on the action, egress rules on the bytes, and passing one is not passing the other.

## Runnable material

- [Executable demos](../demo/README.md): self-contained pages generated from the
  shipped library. Every displayed result carries the metadata that produced it
  and names the exact test that reproduces it. Start at the
  [system map](../demo/guardllm_surface_map.html).
- [Tutorials](../tutorials/README.md): step-by-step end-to-end integrations, each
  with a script you can run from the repo root.
- [Benchmarks](../benchmarks/methodology.md): evaluation methodology and
  [results](../benchmarks/results.md).

## Framework Integrations

See the [integrations index](integrations/README.md), or go directly to:

- [integrations/fastapi.md](integrations/fastapi.md)
- [integrations/mcp_sdk.md](integrations/mcp_sdk.md)
- [integrations/langchain_llamaindex.md](integrations/langchain_llamaindex.md)
