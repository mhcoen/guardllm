"""Layer 11: Audit logging (Part 11).

Structured event logging for all security-relevant actions. Default
backend writes JSON to a file; interface allows SQLite backend later.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardllm.security.types import AuditEvent


class AuditLogger:
    """Security audit logger.

    Writes structured JSON events. Every gated action (proposal,
    approval, cancellation), every block by any layer, canary events,
    sanitization warnings, DLP triggers, provenance blocks, and rate
    limit events are logged.

    What is NOT logged: raw email content, raw action content (only
    hash), user input text.
    """

    def __init__(self, log_path: Optional[str | Path] = None):
        """Initialize the audit logger.

        Args:
            log_path: Path to audit log file. If None, events are
                stored in memory only (useful for testing).
        """
        self._log_path = Path(log_path) if log_path else None
        self._events: List[Dict[str, Any]] = []

    def log(self, event: AuditEvent) -> str:
        """Log a security event.

        Args:
            event: The audit event to log.

        Returns:
            The request_id assigned to this event.
        """
        request_id = event.request_id or str(uuid.uuid4())
        record = {
            "request_id": request_id,
            "timestamp": event.timestamp or time.time(),
            "event_type": event.event_type,
            "tool_name": event.tool_name,
            "action_summary": event.action_summary,
            "content_hash": event.content_hash,
            "user_confirmed": event.user_confirmed,
            "firewall_result": event.firewall_result,
            "dlp_result": event.dlp_result,
            "provenance_result": event.provenance_result,
            "rate_limit_result": event.rate_limit_result,
            "binding_result": event.binding_result,
            "warnings": event.warnings,
            "session_id": event.session_id,
        }

        self._events.append(record)

        if self._log_path:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a") as f:
                f.write(json.dumps(record, default=str) + "\n")

        return request_id

    def log_quick(
        self,
        event_type: str,
        tool_name: Optional[str] = None,
        session_id: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Convenience method for common logging patterns.

        Args:
            event_type: Event type string.
            tool_name: Optional tool name.
            session_id: Optional session ID.
            **kwargs: Additional AuditEvent fields.

        Returns:
            The request_id assigned to this event.
        """
        event = AuditEvent(
            event_type=event_type,
            tool_name=tool_name,
            session_id=session_id,
            **kwargs,
        )
        return self.log(event)

    def get_events(
        self,
        event_type: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve logged events (most recent first).

        Args:
            event_type: Filter by event type.
            session_id: Filter by session.
            limit: Maximum events to return.

        Returns:
            List of event dicts, most recent first.
        """
        events = self._events
        if event_type:
            events = [e for e in events if e["event_type"] == event_type]
        if session_id:
            events = [e for e in events if e["session_id"] == session_id]
        return list(reversed(events[-limit:]))

    def clear(self) -> None:
        """Clear in-memory event store (for testing)."""
        self._events.clear()
