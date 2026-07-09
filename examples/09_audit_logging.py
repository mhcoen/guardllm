"""Demonstrate audit logging for security decisions."""

from __future__ import annotations

from _bootstrap import ROOT  # noqa: F401

from guardllm import Guard
from guardllm.security.audit import AuditLogger
from guardllm.security.types import AuditEvent


def main() -> None:
    audit = AuditLogger()  # in-memory logger for demo
    guard = Guard(audit_logger=audit)

    ctx = Guard.context_web(source_id="duckduckgo")
    inbound = "<div>Result</div><div style='display:none'>inject me</div>"
    processed = guard.process_inbound(inbound, ctx)

    audit.log(
        AuditEvent(
            event_type="inbound_processed",
            action_summary="Processed untrusted web search result",
            warnings=processed.warnings,
            session_id="demo-l11",
        )
    )

    outbound = guard.check_outbound(inbound, ctx)
    audit.log(
        AuditEvent(
            event_type="outbound_checked",
            action_summary="Checked outbound response",
            dlp_result={"allowed": outbound.allowed, "reason": outbound.reason},
            session_id="demo-l11",
        )
    )

    print("[audit] outbound allowed:", outbound.allowed, "|", outbound.reason)
    print("[audit] recent events:")
    events = audit.get_events(limit=10)
    for event in events:
        print("  -", event["event_type"], "|", event.get("action_summary"))

    # Both decisions were recorded to the audit trail.
    event_types = {e["event_type"] for e in events}
    assert {"inbound_processed", "outbound_checked"} <= event_types


if __name__ == "__main__":
    main()
