"""Security pipeline types: contexts, events, and result dataclasses.

All types used across the security library are defined here to avoid
circular imports. No dependencies outside stdlib.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TrustLevel(Enum):
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, TrustLevel):
            return NotImplemented
        return _TRUST_RANK[self] < _TRUST_RANK[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, TrustLevel):
            return NotImplemented
        return _TRUST_RANK[self] <= _TRUST_RANK[other]


_TRUST_RANK: dict[TrustLevel, int] = {
    TrustLevel.UNTRUSTED: 0,
    TrustLevel.SEMI_TRUSTED: 1,
    TrustLevel.TRUSTED: 2,
}


# SourceTrust: only TRUSTED or UNTRUSTED allowed (no SEMI_TRUSTED on source axis)
SourceTrust = TrustLevel

# PrincipalTrust: all three values allowed (per-session caller identity)
PrincipalTrust = TrustLevel


class ContentType(Enum):
    HTML = "html"
    PLAINTEXT = "plaintext"
    STRUCTURED = "structured"


class ExtractionPolicy(Enum):
    """KG extraction policy for a source type (Layer 2)."""

    ALLOW = "allow"  # Extract normally, no quarantine
    QUARANTINE = "quarantine"  # Extract but quarantine all triples
    BLOCK = "block"  # Do not extract


class SensitivityLevel(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"


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

    action: str  # Tool name, e.g. "gmail_send_email"
    scope: dict  # Action-specific constraints
    message_hash: str  # SHA-256 of the user message
    timestamp: float  # time.time() when event was created
    source: str  # "regex_directive", "slash_command", etc.
    session_id: str | None = None

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

    # Client mode (None = no allowlist; dict including {} = deny unless listed)
    tool_allowlist: dict[tuple, Any] | None = None
    # RESERVED / not yet wired. The field is accepted for forward compatibility
    # but is not consulted by the policy engine today: authorization-event
    # origin authenticity is a host obligation, not something the library
    # validates (see A-AS8 in docs/threat_model.md). Its disposition
    # (deprecate vs. wire as a source-string consistency check) is undecided;
    # kept as a constructor field to avoid a breaking change post-2.0.0.
    directive_patterns: dict[str, Any] = field(default_factory=dict)
    enable_destructive: bool = False

    # Server mode (None = no allowlist, {} = deny all tools)
    capability_scopes: dict[str, Any] | None = None
    client_id: str | None = None
    # Server mode: when True, a missing capability_scopes (None) denies all
    # tools instead of allowing by default. Fail-closed opt-in so a forgotten
    # capability_scopes config does not silently allow every non-destructive
    # tool for an untrusted client.
    server_default_deny: bool = False

    # Shared
    rate_limits: dict[str, Any] = field(default_factory=dict)
    argument_limits: dict[str, Any] = field(default_factory=dict)
    escalation_gate_enabled: bool = True
    contaminated_action: str = "block"
    # Tunable overlap thresholds
    dlp_verbatim_lcs_min: int = 14  # untrusted-echo LCS threshold
    dlp_ngram_overlap_min: float = 0.40
    dlp_sensitive_lcs_min: int = 12  # sensitive-leak LCS threshold (lower)
    provenance_verbatim_lcs_min: int = 50
    provenance_ngram_overlap_min: float = 0.30

    # Two-axis trust model fields (Phase 1 scaffolding, Phase 2 consumers)
    # Override source gate policy keyed by (source_type, source_trust)
    source_gate_overrides: dict[tuple[str, TrustLevel], ExtractionPolicy] = field(
        default_factory=dict
    )
    # Tools denied when principal_trust == UNTRUSTED
    untrusted_deny_tools: frozenset[str] = frozenset()
    # Require auth event when principal_trust == UNTRUSTED
    untrusted_require_auth: bool = False
    # Require confirmation for all tools when principal_trust <= this level
    confirm_all_below: TrustLevel | None = None
    # Per-principal_trust rate limit overrides, merged over DEFAULT_LIMITS
    rate_limit_overrides: dict[TrustLevel, dict[str, int]] = field(default_factory=dict)
    # Contamination-aware tool gating: "allow" | "require_auth" | "deny"
    contaminated_tool_policy: str = "allow"
    # Egress-feedback escalation: tool gating once a DLP block has fired at
    # egress in this session. Same option set as contaminated_tool_policy.
    # Default "require_auth": a confirmed egress leak block is a stronger
    # signal than mere contamination, so it tightens subsequent tool calls.
    escalated_tool_policy: str = "require_auth"
    # L12: auto-require confirmation for destructive tool calls
    auto_confirm_destructive: bool = False
    # Source types that require non-empty source_id
    require_source_id_for: frozenset[str] = frozenset()
    # L11 anti-replay: require tool authorizations to be bound to the current
    # user message (auth_event.message_hash must match the message hash
    # supplied at execution time). A mismatch is always denied; this flag
    # controls whether a *missing* current message hash fails closed.
    #   "off"          - legacy: no hard requirement (backward compatible)
    #   "destructive"  - destructive tools must carry a current message hash
    #   "all"          - every authorized tool call must carry one
    require_message_binding: str = "off"

    def __post_init__(self) -> None:
        _VALID_CONTAMINATED_TOOL_POLICIES = {"allow", "require_auth", "deny"}
        if self.contaminated_tool_policy not in _VALID_CONTAMINATED_TOOL_POLICIES:
            raise ValueError(
                f"Invalid contaminated_tool_policy: '{self.contaminated_tool_policy}'. "
                f"Valid values: {sorted(_VALID_CONTAMINATED_TOOL_POLICIES)}"
            )
        if self.escalated_tool_policy not in _VALID_CONTAMINATED_TOOL_POLICIES:
            raise ValueError(
                f"Invalid escalated_tool_policy: '{self.escalated_tool_policy}'. "
                f"Valid values: {sorted(_VALID_CONTAMINATED_TOOL_POLICIES)}"
            )
        _VALID_MESSAGE_BINDING = {"off", "destructive", "all"}
        if self.require_message_binding not in _VALID_MESSAGE_BINDING:
            raise ValueError(
                f"Invalid require_message_binding: '{self.require_message_binding}'. "
                f"Valid values: {sorted(_VALID_MESSAGE_BINDING)}"
            )
        _VALID_RATE_LIMIT_KEYS = {
            "emails_per_hour",
            "burst_threshold",
            "burst_window_seconds",
            "novel_recipient_flag",
        }
        for trust_level, overrides in self.rate_limit_overrides.items():
            unknown = set(overrides.keys()) - _VALID_RATE_LIMIT_KEYS
            if unknown:
                raise ValueError(
                    f"Unknown rate_limit_overrides keys for {trust_level}: "
                    f"{sorted(unknown)}. Valid keys: {sorted(_VALID_RATE_LIMIT_KEYS)}"
                )


class ConfirmationHandler:
    """Protocol for user confirmation. Implemented by Episodic's CLI."""

    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        raise NotImplementedError


@dataclass
class SecurityContext:
    """Configures the security pipeline for a specific data flow."""

    mode: str  # "client" or "server"
    source_type: str  # "mcp_server", "mcp_client", "cli_user"
    source_id: str  # server_id or client_id
    source_trust: TrustLevel = TrustLevel.UNTRUSTED
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED
    sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC
    content_type: ContentType = ContentType.PLAINTEXT
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    confirmation_handler: ConfirmationHandler | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("client", "server"):
            # Without this guard a typo (e.g. "sever") silently falls through to
            # the client implicit-allow path, bypassing server_default_deny.
            raise ValueError(f"mode must be 'client' or 'server', got {self.mode!r}")
        if self.source_trust == TrustLevel.SEMI_TRUSTED:
            raise ValueError("source_trust does not allow SEMI_TRUSTED; use TRUSTED or UNTRUSTED")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class SanitizationResult:
    """Output of the sanitizer (Layer 0)."""

    cleaned_text: str
    warnings: list[str] = field(default_factory=list)
    sanitization_summary: str | None = None
    chars_stripped: int = 0
    class_hiding_possible: bool = False
    encoded_detected: bool = False
    mixed_script_words: list[str] = field(default_factory=list)


@dataclass
class ProcessedContent:
    """Output of the full inbound pipeline."""

    content: str
    sanitization: SanitizationResult | None = None
    isolated: bool = False
    source_type: str = ""
    source_id: str = ""
    warnings: list[str] = field(default_factory=list)


@dataclass
class GateResult:
    """Output of policy engine / tool execution check."""

    allowed: bool
    reason: str
    matched_directive: str | None = None
    confidence: str = "none"  # "explicit" | "implicit" | "none"
    # Non-blocking rate-limit anomaly signals (burst, novel recipient)
    anomalies: list[str] = field(default_factory=list)


@dataclass
class OutboundResult:
    """Output of outbound DLP check."""

    allowed: bool
    reason: str
    overlap_pct: float = 0.0
    secrets_found: list[str] = field(default_factory=list)
    provenance_blocked: bool = False
    contamination_triggered: bool = False
    echo_detected: bool = False
    echo_lcs: int = 0
    # Non-blocking rate-limit anomaly signals (burst, novel recipient)
    anomalies: list[str] = field(default_factory=list)


@dataclass
class RateLimitResult:
    """Output of rate limiter check."""

    allowed: bool
    reason: str
    anomalies: list[str] = field(default_factory=list)
    remaining: int | None = None
    retry_after: int | None = None


@dataclass
class ValidationResult:
    """Output of argument validation."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    field_name: str | None = None


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
    tool_name: str | None = None
    action_summary: str | None = None
    content_hash: str | None = None
    user_confirmed: bool | None = None
    firewall_result: dict[str, Any] | None = None
    dlp_result: dict[str, Any] | None = None
    provenance_result: dict[str, Any] | None = None
    rate_limit_result: dict[str, Any] | None = None
    binding_result: dict[str, Any] | None = None
    warnings: list[str] | None = None
    session_id: str | None = None
    timestamp: float | None = None
    request_id: str | None = None
