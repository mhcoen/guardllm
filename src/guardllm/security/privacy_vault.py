"""L13 privacy vault: substitution at the model boundary and scoped restoration.

The model runs at a third party in the common deployment, so every byte of
every prompt crosses an organizational boundary. The vault replaces direct
identifiers with random tokens before that crossing and resolves them
afterwards, under a policy that says which destinations may see which classes.

Three properties this module holds, each of which has a way of going wrong
that is worse than not having the feature at all:

**Plaintext never leaves through a result object.** Fields holding restored
values are excluded from ``repr``, and the plaintext-to-token map is never
exposed: it aggregates every value detected in a call and is more sensitive
than the content it came from, so one traced result would defeat the feature.
Scrubbing reads the map internally and returns nothing that quotes a value.

**Restoration is scoped by destination and by field.** Blind restoration puts
a real SSN into an email body the model happened to mention it in, which is
worse than never tokenizing: L3 sees a token where the payload will carry
plaintext, so the vault would launder the value past the egress checks. Every
destination defaults to restoring nothing, and a token in a field with no
matching rule fails the call rather than silently becoming a marker.

**A token that was never issued never resolves.** The defensible invariant is
narrower than it first looks: strings inside the bounded correction radius of
an issued codeword do resolve, and they were never issued. What the vault can
promise is that only exact issued codewords, and strings within that explicit
radius, resolve at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from guardllm.security import token_codec as codec
from guardllm.security.pii_detect import SeededValues, detect
from guardllm.security.types import (
    CORRECTED,
    EXACT,
    REDACT,
    UNKNOWN_VALID,
    UNRESOLVABLE,
    ClassPolicy,
    DeidentifyResult,
    Destination,
    PIIClass,
    PIIFinding,
    PreparedCall,
    PrivacyConfig,
    ReidentifyResult,
    SanitizationResult,
)

# ---------------------------------------------------------------------------
# Token text form
# ---------------------------------------------------------------------------

#: ``[[GL:EMAIL:7QX4M2KPZ3T8W9F]]``
#:
#: Colons are load-bearing, not decoration: they break the token into runs of
#: at most 15 characters, so L3's ``[A-Za-z0-9+/\-_]{20,}`` entropy scanner
#: never sees a candidate and cannot misattribute a token as a leaked secret.
#: Any future format change must preserve that, and a test asserts it.
_TOKEN_PREFIX = "[[GL:"

#: Tolerant matcher for resolution. Models mangle tokens in predictable ways:
#: markdown-escaped brackets, interior whitespace, a line break mid-body. What
#: this does NOT accept is a partial token, which is counted against the
#: unresolvable budget rather than ignored, because a near miss is as likely to
#: be a probe as a typo.
_TOKEN_RE = re.compile(
    r"\\?\[\s*\\?\[\s*GL\s*:\s*(?P<cls>[A-Za-z_]+)\s*:\s*"
    r"(?P<body>[0-9A-Za-z\s\-]{15,60}?)\s*\\?\]\s*\\?\]"
)

#: A ``[[GL:`` opener that never parses. Counted, not ignored.
_TOKEN_OPENER_RE = re.compile(r"\\?\[\s*\\?\[\s*GL\s*:")

#: Fixed, per-class, and compressible. A reader understands what was withheld,
#: where a raw token tells them nothing and deleting the span tells them less.
#: Structurally distinct from a real token so it is never re-resolved.
_MARKER_RE = re.compile(r"\[redacted:[a-z_]+\]")


def marker_for(pii_class: PIIClass) -> str:
    return f"[redacted:{pii_class.value}]"


def render_token(pii_class: PIIClass, body: str) -> str:
    return f"{_TOKEN_PREFIX}{pii_class.name}:{body}]]"


# ---------------------------------------------------------------------------
# Field-path policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldDecision:
    """Outcome of resolving one token occurrence against the restore policy."""

    action: str  # "restore" | "redact" | "fail"
    reason: str = ""


def _path_of(segments: list[str]) -> str:
    return "/" + "/".join(segments)


def _rule_matches(rule: str, segments: list[str]) -> int | None:
    """Return specificity if ``rule`` matches ``segments``, else None.

    ``*`` matches exactly one segment and never descends, so ``/to/*`` does not
    reach ``/to/0/address``. Specificity is the count of literal segments, so
    an exact segment beats a wildcard at the same depth.
    """
    parts = [p for p in rule.split("/") if p != ""]
    if len(parts) != len(segments):
        return None
    specificity = 0
    for want, got in zip(parts, segments, strict=True):
        if want == "*":
            continue
        if want != got:
            return None
        specificity += 1
    return specificity


def resolve_field(
    rules: dict[str, object],
    segments: list[str],
    pii_class: PIIClass,
) -> FieldDecision:
    """Decide what happens to one token occurrence at one field path.

    Lookup is per token occurrence, not per field. A field holding no token is
    copied through untouched and needs no rule at all; only an occurrence needs
    one. Without that, an ordinary token-free ``/subject`` would fail every
    call and each integration would need an exhaustive policy for every
    argument it ever sends.
    """
    best: tuple[int, str, object] | None = None
    tied = False
    for rule, allowed in rules.items():
        spec = _rule_matches(rule, segments)
        if spec is None:
            continue
        if best is None or spec > best[0]:
            best, tied = (spec, rule, allowed), False
        elif spec == best[0] and rule != best[1]:
            tied = True

    path = _path_of(segments)
    if best is None:
        # Silence means the policy does not cover this schema. A marker here
        # would be a syntactically valid string that L10 accepts, L9
        # authorizes, and L12 shows the operator as a recipient, so a stale
        # rule would dispatch a corrupted argument instead of refusing.
        return FieldDecision("fail", f"no restoration rule for field '{path}'")
    if tied:
        return FieldDecision("fail", f"ambiguous restoration rules for field '{path}'")

    allowed = best[2]
    if allowed == REDACT:
        return FieldDecision("redact")
    if isinstance(allowed, (frozenset, set, list, tuple)):
        if pii_class in allowed:
            return FieldDecision("restore")
        return FieldDecision(
            "fail",
            f"field '{path}' does not permit class '{pii_class.value}'",
        )
    return FieldDecision("fail", f"malformed restoration rule for field '{path}'")


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


@dataclass
class _Entry:
    value: str
    pii_class: PIIClass
    token: str


class VaultCapacityError(RuntimeError):
    """Raised when the vault is full.

    Reaching capacity fails de-identification rather than evicting. Eviction
    would silently break resolution for tokens still live in the transcript,
    turning a capacity problem into a correctness problem at the worst moment.
    """


class PrivacyVault:
    """Session-scoped store mapping identifiers to tokens and back.

    In-memory, cleared by ``reset``, never persisted by this library. A shared
    or persistent vault is a re-identification database and a different
    security object; it needs encryption at rest, TTL, and access control that
    are not provided here.
    """

    def __init__(self, config: PrivacyConfig) -> None:
        self._config = config
        self._by_value: dict[tuple[PIIClass, str], _Entry] = {}
        self._by_payload: dict[str, _Entry] = {}
        self.seeded = SeededValues()

    # -- lifecycle ------------------------------------------------------

    def clear(self) -> None:
        """Drop every entry. Invalidates every token in the host's transcript."""
        self._by_value.clear()
        self._by_payload.clear()

    def __len__(self) -> int:
        return len(self._by_payload)

    @property
    def config(self) -> PrivacyConfig:
        return self._config

    def seed(self, values: dict[str, PIIClass]) -> None:
        self.seeded.add(values)

    # -- issuance -------------------------------------------------------

    @staticmethod
    def _normalize(pii_class: PIIClass, value: str) -> str:
        v = value.strip()
        if pii_class is PIIClass.EMAIL:
            return v.casefold()
        if pii_class in (PIIClass.PHONE, PIIClass.SSN, PIIClass.CREDIT_CARD):
            return "".join(ch for ch in v if ch.isdigit())
        if pii_class in (PIIClass.PERSON, PIIClass.ADDRESS):
            return " ".join(v.casefold().split())
        return v

    def token_for(self, pii_class: PIIClass, value: str) -> str:
        """Return the session-stable token for a value, issuing one if needed."""
        key = (pii_class, self._normalize(pii_class, value))
        existing = self._by_value.get(key)
        if existing is not None:
            return existing.token
        if len(self._by_payload) >= self._config.vault_max_entries:
            raise VaultCapacityError(
                f"privacy vault is full ({self._config.vault_max_entries} entries)"
            )
        # Collisions are astronomically unlikely at 60 bits but cost nothing to
        # exclude, and a silent collision would alias two people's values.
        for _ in range(8):
            body = codec.encode_text(codec.random_payload())
            payload = body[: codec.PAYLOAD_SYMBOLS]
            if payload not in self._by_payload:
                break
        else:  # pragma: no cover - requires 8 consecutive 60-bit collisions
            raise VaultCapacityError("could not draw a unique token payload")
        entry = _Entry(value=value, pii_class=pii_class, token=render_token(pii_class, body))
        self._by_value[key] = entry
        self._by_payload[payload] = entry
        return entry.token

    def lookup(self, payload: str) -> _Entry | None:
        return self._by_payload.get(payload)

    def contains_issued_token(self, text: str) -> bool:
        """Exact membership test, not a pattern match.

        The library mints every token and holds the registry, so asking whether
        content carries one is precise and cannot produce a false positive on
        real content.
        """
        for m in _TOKEN_RE.finditer(text):
            result = codec.decode_text(m.group("body"))
            if result.ok and codec.payload_key(result.payload) in self._by_payload:
                return True
        return False

    # -- ingress scrub --------------------------------------------------

    def scrub_tokens(self, text: str) -> tuple[str, int, int]:
        """Strip token-shaped content arriving from an untrusted source.

        Returns ``(cleaned, shaped, issued)``. The two counts are reported
        separately because they mean different things. Token *shape* is not
        evidence of anything: an attacker can type ``[[GL:...]]`` without
        knowing a single issued value, and so can a benign page, since this
        project's own documentation contains example tokens. An exact match to
        a live issued token cannot be guessed, so it means a token from this
        session's prompt reached an untrusted source and came back.
        """
        shaped = 0
        issued = 0

        def _sub(m: re.Match[str]) -> str:
            nonlocal shaped, issued
            shaped += 1
            result = codec.decode_text(m.group("body"))
            if result.ok and codec.payload_key(result.payload) in self._by_payload:
                issued += 1
            return ""

        cleaned = _TOKEN_RE.sub(_sub, text)
        return cleaned, shaped, issued

    # -- de-identification ----------------------------------------------

    def _masked_spans(self, text: str) -> list[tuple[int, int]]:
        spans = [(m.start(), m.end()) for m in _TOKEN_RE.finditer(text)]
        spans.extend((m.start(), m.end()) for m in _MARKER_RE.finditer(text))
        return spans

    def deidentify(self, text: str, *, deny_action: str = "marker") -> DeidentifyResult:
        """Replace identifiers with tokens.

        ``deny_action`` selects what happens to a DENY class. ``"marker"``
        replaces it and warns, which is right for untrusted content the
        application merely read: a credential on a web page is the page's
        problem, not a reason to discard it. ``"fail"`` refuses the call, which
        is right for content the host assembled itself, because a credential in
        a prompt the host built is a bug in the host and should be loud.
        """
        cfg = self._config
        found = detect(
            text,
            classes=cfg.classes,
            seeded=self.seeded,
            recognizer=cfg.recognizer,
            masked_spans=self._masked_spans(text),
        )

        warnings: list[str] = []
        if found.ambiguous:
            # Partial overlap without containment is genuinely ambiguous.
            # Inventing a precedence rule to break it is how a detector quietly
            # substitutes the wrong span, so refuse instead.
            first = found.ambiguous[0]
            return DeidentifyResult(
                content=text,
                allowed=False,
                reason=(
                    f"Ambiguous overlapping identifiers at offset {first[0].start} "
                    f"({first[0].pii_class.value} vs {first[1].pii_class.value})"
                ),
            )

        findings: list[PIIFinding] = []
        denied: list[PIIClass] = []
        pieces: list[str] = []
        cursor = 0

        for match in found.matches:
            policy = cfg.policy_for(match.pii_class)
            if policy is ClassPolicy.ALLOW:
                continue
            pieces.append(text[cursor : match.start])
            if policy is ClassPolicy.DENY:
                if deny_action == "fail":
                    return DeidentifyResult(
                        content=text,
                        allowed=False,
                        reason=(
                            f"Class '{match.pii_class.value}' must not cross the "
                            "model boundary"
                        ),
                        denied=[match.pii_class],
                    )
                if match.pii_class not in denied:
                    denied.append(match.pii_class)
                    warnings.append(
                        f"Withheld a '{match.pii_class.value}' value from the model boundary"
                    )
                pieces.append(marker_for(match.pii_class))
                cursor = match.end
                continue
            try:
                token = self.token_for(match.pii_class, match.value)
            except VaultCapacityError as exc:
                return DeidentifyResult(content=text, allowed=False, reason=str(exc))
            pieces.append(token)
            findings.append(
                PIIFinding(
                    pii_class=match.pii_class,
                    start=match.start,
                    end=match.end,
                    token=token,
                    inferred=match.inferred,
                )
            )
            cursor = match.end

        pieces.append(text[cursor:])
        return DeidentifyResult(
            content="".join(pieces),
            findings=findings,
            warnings=warnings,
            denied=denied,
        )

    # -- diagnostics scrubbing -----------------------------------------

    def _redact_known(self, s: str) -> str:
        """Replace vaulted values in a diagnostic string with their tokens.

        The map is the only rule that separates the two cases correctly. A word
        that was vaulted is replaced; a word that was not is left alone,
        because it is already present verbatim in the model-visible content, so
        removing it from a warning degrades a genuine L0 signal while
        disclosing exactly as much as before.
        """
        out = s
        for entry in self._by_payload.values():
            if entry.value and entry.value in out:
                out = out.replace(entry.value, entry.token)
        return out

    def scrub_diagnostics(
        self,
        san: SanitizationResult | None,
        warnings: list[str],
    ) -> tuple[SanitizationResult | None, list[str]]:
        """Substitute vaulted values in every string-bearing public field.

        ``cleaned_text`` alone is not enough. ``mixed_script_words`` holds the
        offending words verbatim, ``sanitization_summary`` joins up to five of
        them into its text, the same words appear in ``warnings``, and the
        pipeline copies those warnings onto ``ProcessedContent``. One homoglyph
        in an address puts it in all of them, and that path fires precisely on
        adversarial input.
        """
        scrubbed_warnings = [self._redact_known(w) for w in warnings]
        if san is None:
            return None, scrubbed_warnings
        san = replace(
            san,
            warnings=[self._redact_known(w) for w in san.warnings],
            sanitization_summary=(
                self._redact_known(san.sanitization_summary)
                if san.sanitization_summary
                else san.sanitization_summary
            ),
            mixed_script_words=[self._redact_known(w) for w in san.mixed_script_words],
        )
        return san, scrubbed_warnings

    # -- re-identification ----------------------------------------------

    def _resolve_one(self, body: str) -> tuple[str, _Entry | None]:
        result = codec.decode_text(body)
        if not result.ok:
            return UNRESOLVABLE, None
        entry = self._by_payload.get(codec.payload_key(result.payload))
        if entry is None:
            return UNKNOWN_VALID, None
        return (EXACT if result.status == codec.EXACT else CORRECTED), entry

    def reidentify(
        self,
        text: str,
        *,
        destination: Destination,
        allowed_classes: frozenset[PIIClass] | None = None,
    ) -> ReidentifyResult:
        """Resolve tokens in free text for a destination.

        Every destination defaults to restoring nothing, including ``USER``: a
        channel does not establish the viewer's entitlement, and a multi-tenant
        support desk is the counterexample a permissive default mishandles
        silently.
        """
        cfg = self._config
        permitted = (
            allowed_classes
            if allowed_classes is not None
            else cfg.destination_policy.get(destination, frozenset())
        )
        outcomes: dict[str, int] = {}
        restored: list[PIIClass] = []
        withheld: list[PIIClass] = []
        warnings: list[str] = []
        unresolvable = 0

        def _count(status: str) -> None:
            outcomes[status] = outcomes.get(status, 0) + 1

        def _sub(m: re.Match[str]) -> str:
            nonlocal unresolvable
            status, entry = self._resolve_one(m.group("body"))
            _count(status)
            if entry is None:
                unresolvable += 1
                return ""
            if status == CORRECTED:
                warnings.append("Recovered a mangled token by error correction")
            if entry.pii_class not in permitted:
                if entry.pii_class not in withheld:
                    withheld.append(entry.pii_class)
                return marker_for(entry.pii_class)
            if entry.pii_class not in restored:
                restored.append(entry.pii_class)
            # The class label in the token text is decoration for the model and
            # never reaches this decision: policy reads the class recorded at
            # issuance. Otherwise relabelling an SSN token as EMAIL would be a
            # straightforward policy bypass.
            return entry.value

        content = _TOKEN_RE.sub(_sub, text)

        stray = len(_TOKEN_OPENER_RE.findall(content))
        if stray:
            unresolvable += stray
            _count(UNRESOLVABLE)

        if unresolvable > cfg.max_unresolvable:
            return ReidentifyResult(
                allowed=False,
                reason=(
                    f"{unresolvable} unresolvable tokens exceed the per-call "
                    f"budget of {cfg.max_unresolvable}"
                ),
                outcomes=outcomes,
                warnings=warnings,
            )

        return ReidentifyResult(
            allowed=True,
            content=content,
            restored=restored,
            withheld=withheld,
            outcomes=outcomes,
            warnings=warnings,
        )

    # -- tool arguments -------------------------------------------------

    def prepare_args(self, tool: str, args: dict) -> PreparedCall:
        """Resolve tokens in a tool argument tree, per field policy.

        Walks every string leaf. Restoration has to happen here, before the
        host builds its ``AuthorizationEvent`` and ``Binding``, because both
        bind exactly: a scope authorized over a token fails against the
        restored value, and the binding hash mismatches.
        """
        cfg = self._config
        rules = cfg.restore_policy.get(tool, {})
        restored: list[PIIClass] = []
        withheld: list[PIIClass] = []
        warnings: list[str] = []
        failure: str | None = None
        unresolvable = 0

        def _walk(node: object, segments: list[str]) -> object:
            nonlocal failure, unresolvable
            if failure is not None:
                return node
            if isinstance(node, str):
                return _resolve_leaf(node, segments)
            if isinstance(node, dict):
                return {k: _walk(v, [*segments, str(k)]) for k, v in node.items()}
            if isinstance(node, list):
                return [_walk(v, [*segments, str(i)]) for i, v in enumerate(node)]
            return node

        def _resolve_leaf(value: str, segments: list[str]) -> str:
            nonlocal failure, unresolvable

            def _sub(m: re.Match[str]) -> str:
                nonlocal failure, unresolvable
                status, entry = self._resolve_one(m.group("body"))
                if entry is None:
                    unresolvable += 1
                    if failure is None:
                        failure = (
                            f"Unresolvable token in field '{_path_of(segments)}' ({status})"
                        )
                    return ""
                if status == CORRECTED:
                    warnings.append("Recovered a mangled token by error correction")
                decision = resolve_field(rules, segments, entry.pii_class)
                if decision.action == "fail":
                    if failure is None:
                        failure = decision.reason
                    return ""
                if decision.action == "redact":
                    if entry.pii_class not in withheld:
                        withheld.append(entry.pii_class)
                    return marker_for(entry.pii_class)
                if entry.pii_class not in restored:
                    restored.append(entry.pii_class)
                return entry.value

            return _TOKEN_RE.sub(_sub, value)

        new_args = _walk(args, [])

        if failure is not None:
            return PreparedCall(allowed=False, tool=tool, reason=failure, warnings=warnings)
        if unresolvable > cfg.max_unresolvable:
            return PreparedCall(
                allowed=False,
                tool=tool,
                reason=f"{unresolvable} unresolvable tokens exceed the per-call budget",
                warnings=warnings,
            )

        return PreparedCall(
            allowed=True,
            tool=tool,
            args=new_args if isinstance(new_args, dict) else args,
            reason="prepared",
            restored=restored,
            withheld=withheld,
            warnings=warnings,
        )
