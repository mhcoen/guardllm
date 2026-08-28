# Examples

Runnable examples for hardening MCP servers/clients and unknown-provenance content.

Run from repo root:

```bash
python examples/01_mcp_server_hardening.py
python examples/02_mcp_client_hardening.py
python examples/03_web_search_untrusted_input.py
python examples/04_email_untrusted_input.py
python examples/05_document_untrusted_input.py
python examples/06_calendar_untrusted_input.py
python examples/07_other_untrusted_inputs.py
python examples/08_action_gate_l12.py
python examples/09_audit_logging.py
python examples/10_validation_and_error_sanitization.py
python examples/11_full_guard_flow.py
```

What each example demonstrates:
- `01_mcp_server_hardening.py`: sanitize untrusted MCP client input and enforce server capability scopes.
- `02_mcp_client_hardening.py`: require explicit authorization + binding before destructive MCP tool calls.
- `03_web_search_untrusted_input.py`: sanitize web HTML and enforce source-gate restrictions.
- `04_email_untrusted_input.py`: treat email as untrusted; sanitize and block KG extraction.
- `05_document_untrusted_input.py`: sanitize document text and block unsafe outbound copying.
- `06_calendar_untrusted_input.py`: sanitize calendar notes and block KG extraction.
- `07_other_untrusted_inputs.py`: handle generic unknown sources (webhooks/tool outputs) with trust controls.
- `08_action_gate_l12.py`: apply L12 confirmation gate with enhanced confirmation when web-derived context is present.
- `09_audit_logging.py`: record structured audit events for inbound/outbound security decisions.
- `10_validation_and_error_sanitization.py`: validate tool args pre-dispatch and sanitize errors for safe outward responses.
- `11_full_guard_flow.py`: run the unified Guard API flow (validation + policy + confirmation + audit + sanitized errors).

## Local LLM Demo

`demo_local_llm.py` runs a real LLM (Qwen2.5-3B-Instruct) through the same pipeline twice to demonstrate the full attack-and-defense cycle:

1. **Without Vörður**: raw untrusted web content (with a hidden injection payload) is passed directly to the model alongside a sensitive CRM record. The model may follow the injection and exfiltrate the account number via a markdown link.
2. **With Vörður**: the web content is sanitized (hidden div stripped, injection flagged), content is isolated with trust metadata, and the egress gate blocks outbound content that mixes sensitive data with untrusted context.

```bash
pip install transformers torch accelerate
python examples/demo_local_llm.py
```

The model (~6 GB) downloads automatically on first run. Runs in under 5 minutes on a Mac M3 Max (128 GB) or equivalent. No API keys required.
