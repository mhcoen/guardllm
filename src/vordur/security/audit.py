"""Audit logging (cross-cutting observer).

Structured event logging for all security-relevant actions. One JSON object per
line, to a file, to a stream, or to both; interface allows SQLite backend later.

Emitting is where this ends. Storing, searching and retaining the events is the
host's, which is why the stream sink exists: a container writes to stdout and
whatever collector the deployment already runs picks it up, with no file to
mount, rotate or ship.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, TextIO

from vordur.security.types import AuditEvent


class AuditLogger:
    """Security audit logger.

    Writes structured JSON events. Every gated action (proposal,
    approval, cancellation), every block by any layer, canary events,
    sanitization warnings, DLP triggers, provenance blocks, and rate
    limit events are logged.

    What is NOT logged: raw email content, raw action content (only
    hash), user input text.
    """

    def __init__(self, log_path: str | Path | None = None, stream: TextIO | None = None):
        """Initialize the audit logger.

        Args:
            log_path: Path to audit log file. If None, no file is written.
            stream: An open text stream to write events to, one JSON object
                per line. ``sys.stdout`` is the intended argument in a
                container, where the collector reads the process's output and
                there is no file worth writing. Any writable text stream works,
                which is also what makes it testable.

        Both are independent and either may be omitted. Events are kept in
        memory regardless, which is what ``get_events`` reads.
        """
        self._log_path = Path(log_path) if log_path else None
        self._stream = stream
        self._events: list[dict[str, Any]] = []

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

        # Serialized once so the two sinks cannot disagree about what was
        # recorded, which is the only thing worse than losing a record.
        line = json.dumps(record, default=str) + "\n"

        if self._log_path:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a") as f:
                f.write(line)

        if self._stream is not None:
            self._stream.write(line)
            # Flushed per record, deliberately. Python block-buffers a stream
            # that is not a terminal, and under a collector stdout is always a
            # pipe, so without this the events sit in a 8KB buffer: invisible
            # while the process runs and gone if it dies, which is exactly when
            # the audit trail is worth having. A security event is rare enough
            # that the syscall does not matter.
            self._stream.flush()

        return request_id

    def log_quick(
        self,
        event_type: str,
        tool_name: str | None = None,
        session_id: str | None = None,
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
        event_type: str | None = None,
        session_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
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
