"""Demonstrate hardening for other unknown-provenance sources."""

from __future__ import annotations

from _bootstrap import ROOT  # noqa: F401
from guardllm import Guard
from guardllm.security.source_gate import check_extraction_allowed
from guardllm.security.types import ContentType, SecurityContext, TrustLevel


def main() -> None:
    guard = Guard(canary_session_id="misc-session")

    # Example: third-party webhook payload / copied paste from unknown origin.
    unknown_ctx = SecurityContext(
        mode="client",
        source_type="tool_output",
        source_id="third-party-webhook",
        trust_level=TrustLevel.UNTRUSTED,
        content_type=ContentType.STRUCTURED,
    )

    payload = "{\"summary\":\"ok\",\"note\":\"CANARY-ffffffffffffffff\"}"
    processed = guard.process_inbound(payload, unknown_ctx)
    print("[other] cleaned content:", processed.content)
    print("[other] warnings:", processed.warnings)

    sg = check_extraction_allowed("tool_output", source_id="third-party-webhook")
    print("[other] KG extraction policy:", sg.policy.value, "|", sg.reason)


if __name__ == "__main__":
    main()
