"""Security pipeline types: contexts, events, and result dataclasses.

All types used across the security library are defined here to avoid
circular imports. No dependencies outside stdlib.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TrustLevel(Enum):
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"


class ContentType(Enum):
    HTML = "html"
    PLAINTEXT = "plaintext"
    STRUCTURED = "structured"


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthorizationEvent:
    """Structured proof that a user authorized a specific action.

    Produced by an adapter (regex parser, slash command parser, GUI
    button, etc.) outside the security library. Consumed by the
    library's policy engine as the sole basis for allowing tool
    execution.

    The library never parses natural language. It validates these
    events.
    """

    action: str                    # Tool name, e.g. "gmail_send_email"
    scope: dict                    # Action-specific constraints
    message_hash: str              # SHA-256 of the user message
    timestamp: float               # time.time() when event was created
    source: str                    # "regex_directive", "slash_command", etc.
    session_id: Optional[str] = None

    def binding_hash(self) -> str:
        """Hash for request binding verification."""
        payload = f"{self.action}:{sorted(self.scope.items())}:{self.message_hash}"
        return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Security context
# ---------------------------------------------------------------------------

@dataclass
class PolicyConfig:
    """Policy configuration for a security context."""

    # Client mode
    tool_allowlist: Dict[tuple, Any] = field(default_factory=dict)
    directive_patterns: Dict[str, Any] = field(default_factory=dict)
    enable_destructive: bool = False

    # Server mode
    capability_scopes: Dict[str, Any] = field(default_factory=dict)
    client_id: Optional[str] = None

    # Shared
    rate_limits: Dict[str, Any] = field(default_factory=dict)
    argument_limits: Dict[str, Any] = field(default_factory=dict)
    escalation_gate_enabled: bool = True
    # Tunable overlap thresholds (defaults preserve current behavior)
    dlp_verbatim_lcs_min: int = 100
    dlp_ngram_overlap_min: float = 0.40
    provenance_verbatim_lcs_min: int = 50
    provenance_ngram_overlap_min: float = 0.30


class ConfirmationHandler:
    """Protocol for user confirmation. Implemented by Episodic's CLI."""

    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        raise NotImplementedError


@dataclass
class SecurityContext:
    """Configures the security pipeline for a specific data flow."""

    mode: str                      # "client" or "server"
    source_type: str               # "mcp_server", "mcp_client", "cli_user"
    source_id: str                 # server_id or client_id
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    content_type: ContentType = ContentType.PLAINTEXT
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    confirmation_handler: Optional[ConfirmationHandler] = None


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class SanitizationResult:
    """Output of the sanitizer (Layer 0)."""

    cleaned_text: str
    warnings: List[str] = field(default_factory=list)
    sanitization_summary: Optional[str] = None
    chars_stripped: int = 0
    class_hiding_possible: bool = False
    encoded_detected: bool = False
    mixed_script_words: List[str] = field(default_factory=list)


@dataclass
class ProcessedContent:
    """Output of the full inbound pipeline."""

    content: str
    sanitization: Optional[SanitizationResult] = None
    isolated: bool = False
    source_type: str = ""
    source_id: str = ""
    warnings: List[str] = field(default_factory=list)


@dataclass
class GateResult:
    """Output of policy engine / tool execution check."""

    allowed: bool
    reason: str
    matched_directive: Optional[str] = None
    confidence: str = "none"  # "explicit" | "implicit" | "none"


@dataclass
class OutboundResult:
    """Output of outbound DLP check."""

    allowed: bool
    reason: str
    overlap_pct: float = 0.0
    secrets_found: List[str] = field(default_factory=list)
    provenance_blocked: bool = False


@dataclass
class RateLimitResult:
    """Output of rate limiter check."""

    allowed: bool
    reason: str
    anomalies: List[str] = field(default_factory=list)
    remaining: Optional[int] = None
    retry_after: Optional[int] = None


@dataclass
class ValidationResult:
    """Output of argument validation."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    field_name: Optional[str] = None


@dataclass
class Binding:
    """Request binding for tool execution (Part 9b)."""

    tool_name: str
    args_hash: str
    message_hash: str
    binding_hash: str
    created_at: float
    ttl: float = 120.0

    @property
    def expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl


@dataclass
class AuditEvent:
    """Structured audit log event (Part 11)."""

    event_type: str
    tool_name: Optional[str] = None
    action_summary: Optional[str] = None
    content_hash: Optional[str] = None
    user_confirmed: Optional[bool] = None
    firewall_result: Optional[Dict[str, Any]] = None
    dlp_result: Optional[Dict[str, Any]] = None
    provenance_result: Optional[Dict[str, Any]] = None
    rate_limit_result: Optional[Dict[str, Any]] = None
    binding_result: Optional[Dict[str, Any]] = None
    warnings: Optional[List[str]] = None
    session_id: Optional[str] = None
    timestamp: Optional[float] = None
    request_id: Optional[str] = None
