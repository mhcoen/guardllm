"""Security pipeline types: contexts, events, and result dataclasses.

All types used across the security library are defined here to avoid
circular imports. No dependencies outside stdlib.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

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
        """Hash for request binding verification.

        RESERVED / not read by the verify path. ``verify_binding`` recomputes and
        compares the args hash, message hash, and TTL directly and never calls
        this method; ``create_binding`` derives its own hash. Retained for
        forward compatibility (removing it is a breaking change post-2.0.0);
        disposition is deferred. Request binding is an intra-process consistency
        check, not a keyed/cryptographic binding (see the Integrity boundary in
        docs/threat_model.md).
        """
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
    # Egress-feedback escalation: tool gating once a high-confidence DLP or
    # remembered-canary block has fired. Same option set as
    # contaminated_tool_policy. Default "require_auth".
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
    #: L13 findings. Carries classes, offsets, and tokens, never values.
    pii_findings: list = field(default_factory=list)
    #: True when de-identification failed and ``content`` was withheld rather
    #: than returned as plaintext. Hosts must not forward blocked content.
    blocked: bool = False
    #: A registered tier-3 detector did not run, so coverage is unknown rather
    #: than clean. Typed so a host can adopt the stricter posture without
    #: parsing warning text.
    detection_incomplete: bool = False
    #: True when a tier-3 detector was loaded. The documented sub-millisecond,
    #: no-ML, no-network characteristics describe the built-in tiers only.
    inference_used: bool = False


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
    # True when the primary block was the session's remembered canary.
    canary_detected: bool = False


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
    # RESERVED / not read by verify_binding. create_binding computes this
    # SHA-256 over (tool, args_hash, message_hash), but verification checks the
    # tool name, args hash, message hash, and TTL directly, so binding_hash is
    # never consulted. Retained for forward compatibility (removing it is a
    # breaking change post-2.0.0); disposition deferred. Request binding is an
    # intra-process consistency check, not a keyed/cryptographic binding (see
    # the Integrity boundary in docs/threat_model.md).
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


# ---------------------------------------------------------------------------
# L13: privacy vault
# ---------------------------------------------------------------------------


class PIIClass(Enum):
    """Classes of direct identifier the vault recognizes.

    PERSON and ADDRESS are reachable only through host-seeded values or a
    registered tier-3 ``Detector``: the built-in tiers do not attempt them, because
    finding a name in free text means inferring a label from content, which
    this library does not do (see the two-input model in docs/threat_model.md).
    """

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IBAN = "iban"
    ROUTING_NUMBER = "routing_number"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC = "mac"
    DATE_OF_BIRTH = "date_of_birth"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    NATIONAL_ID = "national_id"
    MEDICAL_RECORD = "medical_record"
    PERSON = "person"
    ADDRESS = "address"
    URL = "url"
    #: API keys, tokens, and private keys. Always DENY: a model has no
    #: legitimate use for a credential, and tokenizing one implies it can come
    #: back, which is the wrong affordance entirely.
    CREDENTIAL = "credential"


class ClassPolicy(Enum):
    """What happens to a class at the model boundary."""

    DENY = "deny"  # must not cross in any form
    TOKENIZE = "tokenize"  # substitute, restorable per field policy
    ALLOW = "allow"  # cross unchanged (explicit host opt-in)


class Destination(Enum):
    """Where restored content is headed. Governs what may be re-identified."""

    USER = "user"
    TOOL = "tool"
    EXTERNAL = "external"
    LOG = "log"


#: Sentinel for a field policy that deliberately withholds a value. Distinct
#: from having no rule at all: silence means the policy does not cover the
#: schema, which fails the call, while REDACT is a decision the author made.
REDACT = "REDACT"


#: Credential classes never cross the model boundary in any form. Tokenizing a
#: credential implies it can come back, which is the wrong affordance: a model
#: has no legitimate use for an API key. Driven by the same patterns L3 already
#: scans for at egress (outbound_dlp._GRAMMARS) rather than a second
#: list that drifts from it.
DEFAULT_DENY_CLASSES: frozenset[PIIClass] = frozenset({PIIClass.CREDENTIAL})

DEFAULT_TOKENIZE_CLASSES: frozenset[PIIClass] = frozenset(
    {
        PIIClass.EMAIL,
        PIIClass.PHONE,
        PIIClass.SSN,
        PIIClass.CREDIT_CARD,
        PIIClass.IBAN,
        PIIClass.ROUTING_NUMBER,
        PIIClass.MEDICAL_RECORD,
        PIIClass.PASSPORT,
        PIIClass.DRIVERS_LICENSE,
        PIIClass.NATIONAL_ID,
        PIIClass.DATE_OF_BIRTH,
        PIIClass.PERSON,
        PIIClass.ADDRESS,
    }
)


@dataclass(frozen=True)
class PIIFinding:
    """One detected identifier. Carries no plaintext.

    ``start``/``end`` locate the span in the text that was scanned, and
    ``token`` is what replaced it. The original value lives only in the vault.
    Keeping it off this object is deliberate: findings are returned to the
    host and may be logged, and a finding that quoted its own value would
    reintroduce the disclosure the substitution just prevented.
    """

    pii_class: PIIClass
    start: int
    end: int
    token: str
    inferred: bool = False  # True when a registered detector produced it


@dataclass(frozen=True)
class DetectedSpan:
    """What a tier-3 detector returns: a located class, before substitution.

    Distinct from ``PIIFinding``, which is what the library returns to the host
    *after* substitution and therefore carries a ``token``. A detector runs
    before any token exists, so the two cannot be the same type.

    Carries no plaintext, for the same reason ``PIIFinding`` does not: a
    detector's output reaches warnings and audit, and a span that quoted its own
    value would reintroduce the disclosure substitution is about to prevent.
    """

    start: int
    end: int
    pii_class: PIIClass
    #: Advisory only. Nothing gates on it; see the vault design, §7.2.3.
    confidence: float | None = None


@runtime_checkable
class Detector(Protocol):
    """Tier 3: host-supplied inference over free text.

    The library ships tiers 1 and 2 (structural and host-seeded) and declines
    to build a free-text name model. Any deployment needing person or address
    coverage in free text registers a detector here.

    Two conditions of registration, neither of which the library can enforce:

    1. **A detector must not be a network client.** It receives raw plaintext,
       before substitution, at every insertion point, which defeats every
       provider-safe surface the vault otherwise maintains.
    2. **A detector must not hang.** Detection sits on the path of every prompt,
       so a detector that blocks forever is an availability failure in the
       security layer. There is no enforced wall clock in v1: enforcing one on
       synchronous in-process code requires a thread per call, and shipping an
       unenforced budget described as enforced would be worse than shipping
       none.

    ``id`` appears in warnings and audit so an operator can see what was loaded.
    ``classes`` is declared up front; a span naming a class outside it is
    dropped, so a detector cannot widen its own remit at runtime.
    """

    id: str
    classes: frozenset[PIIClass]

    def find(self, text: str) -> Sequence[DetectedSpan]: ...


# Resolution outcomes. Observable properties of a returned token, never claims
# about intent: a string inside the correction radius of an issued codeword
# resolves whether it was damaged or crafted, and once an entry is gone an
# expired token is indistinguishable from one never issued.
EXACT = "exact"
CORRECTED = "corrected"
UNKNOWN_VALID = "unknown_valid"  # well-formed codeword, not in the vault
UNRESOLVABLE = "unresolvable"  # fails decode beyond the correction radius


@dataclass
class DeidentifyResult:
    """Output of a de-identification pass.

    ``content`` is safe to send to a model provider. The plaintext-to-token
    map is deliberately absent: it aggregates every value detected in the call
    and is more sensitive than the content it came from, so one traced result
    object would defeat the feature. The map never leaves the vault.
    """

    content: str
    findings: list[PIIFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    denied: list[PIIClass] = field(default_factory=list)
    allowed: bool = True
    reason: str = "clean"
    #: A registered tier-3 detector did not run, so coverage is unknown rather
    #: than clean. Set on the untrusted-ingest path, which warns and continues;
    #: the host-assembled path fails the call instead. A host that wants the
    #: stricter posture on ingest escalates on this flag.
    detection_incomplete: bool = False
    #: True when any tier-3 detector ran. The documented sub-millisecond,
    #: no-ML, no-network characteristics describe the built-in tiers only, and
    #: do not hold for a deployment that registered a detector.
    inference_used: bool = False


@dataclass
class ReidentifyResult:
    """Output of a re-identification pass.

    ``content`` holds restored plaintext, so it is excluded from ``repr`` and
    must not be serialized into a log or trace (see the provider-safe surface
    rules in the design notes).
    """

    allowed: bool
    content: str = field(default="", repr=False)
    reason: str = "clean"
    restored: list[PIIClass] = field(default_factory=list)
    withheld: list[PIIClass] = field(default_factory=list)
    outcomes: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class PreparedCall:
    """A tool call whose tokens have been resolved, before authorization.

    Stage 1 of the guarded flow. ``args`` holds fully restored plaintext and is
    excluded from ``repr``. The host must build its ``AuthorizationEvent`` and
    ``Binding`` over *these* arguments, because both bind exactly: a scope
    authorized over a token fails against the restored value, and the binding
    hash mismatches.
    """

    allowed: bool
    tool: str
    args: dict = field(default_factory=dict, repr=False)
    reason: str = "prepared"
    restored: list[PIIClass] = field(default_factory=list)
    withheld: list[PIIClass] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class PrivacyConfig:
    """L13 configuration. ``Guard(privacy=None)`` leaves the layer off."""

    #: Classes eligible for tokenization at the model boundary.
    classes: frozenset[PIIClass] = DEFAULT_TOKENIZE_CLASSES
    #: Per-class override of the model-boundary decision.
    class_policy: dict[PIIClass, ClassPolicy] = field(default_factory=dict)
    #: tool name -> {JSON-pointer-ish field path -> frozenset[PIIClass] | REDACT}
    #: Lookup is per token occurrence: a field holding no token needs no rule.
    restore_policy: dict[str, dict[str, object]] = field(default_factory=dict)
    #: Destination -> classes restorable there. Every destination defaults to
    #: nothing, including USER: a channel does not establish entitlement.
    destination_policy: dict[Destination, frozenset[PIIClass]] = field(default_factory=dict)
    #: Token resolution failures tolerated in one call before failing closed.
    #: A damper on probing within a completion, not the security control: it
    #: does not bound probing across completions. Payload entropy carries that.
    max_unresolvable: int = 3
    #: Hard capacity. Reaching it FAILS de-identification rather than evicting:
    #: eviction would break resolution for tokens still live in the transcript,
    #: turning a capacity problem into a correctness problem. Coupled to
    #: token_codec.PAYLOAD_BITS, since the forgery bound is ~N/2^b.
    vault_max_entries: int = 10_000
    #: De-identify inbound content the host labelled SENSITIVE.
    deidentify_sensitive_ingest: bool = True
    #: Tier-3 detectors (§7.2). Registration order does not affect the outcome:
    #: findings are unioned and then resolved structurally, so adding a detector
    #: can never remove a finding another one produced.
    detectors: tuple[Detector, ...] = ()

    def scanned_classes(self) -> frozenset[PIIClass]:
        """Every class detection must look for.

        The union of ``classes`` and any class named in ``class_policy``.
        Detecting only ``classes`` would make an override such as
        ``class_policy={PIIClass.IPV4: ClassPolicy.TOKENIZE}`` a no-op: the
        policy is consulted, but nothing is ever found to consult it about.
        """
        extra = {c for c, p in self.class_policy.items() if p is not ClassPolicy.ALLOW}
        return frozenset(self.classes | extra | DEFAULT_DENY_CLASSES)

    def policy_for(self, pii_class: PIIClass) -> ClassPolicy:
        """Resolve the model-boundary policy for one class."""
        override = self.class_policy.get(pii_class)
        if override is not None:
            return override
        if pii_class in DEFAULT_DENY_CLASSES:
            return ClassPolicy.DENY
        if pii_class in self.classes:
            return ClassPolicy.TOKENIZE
        return ClassPolicy.ALLOW
