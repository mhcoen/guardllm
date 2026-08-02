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

import hmac
import re
import secrets
import threading
from collections.abc import Iterator
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
    r"(?P<body>[0-9A-Za-z\s\-./\\_,]{15,60}?)\s*\\?\]\s*\\?\]"
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


def _iter_strings(node: object):
    """Yield every string leaf of an argument tree."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                yield k
            yield from _iter_strings(v)
    elif isinstance(node, (list, tuple, set)):
        for v in node:
            yield from _iter_strings(v)


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


#: Class names as they appear in a rendered token, for distinguishing a
#: damaged GuardLLM token from unrelated text that merely looks similar.
_CLASS_NAMES = frozenset(c.name for c in PIIClass)

#: Crockford folding for the fast scan: case-insensitive, with I/L to 1 and
#: O to 0, matching what the decoder does before it looks at anything else.
_CROCKFORD_FOLD_TABLE = str.maketrans("ILOilo", "110110")


def _within_edits(a: str, b: str, limit: int) -> bool:
    """Bounded Levenshtein, exiting as soon as every cell exceeds ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if cur[j] < best:
                best = cur[j]
        if best > limit:
            return False
        prev = cur
    return prev[-1] <= limit


def _trigrams(text: str) -> set[str]:
    return {text[i : i + 3] for i in range(len(text) - 2)}


def _crockford_fold(body: str) -> str:
    return body.upper().translate(str.maketrans("ILO", "110"))


_STRIP_SEPARATORS_TABLE = str.maketrans("", "", " \t\r\n-./\\_,")


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
        # Issuance is a compound of lookup, capacity check, collision
        # exclusion, and two map writes. Unlocked, two threads can both pass a
        # capacity check of one and both write, which breaks the N/2^b forgery
        # bound, and can mint two tokens for the same value, which breaks
        # session co-reference. RateLimiter in this package already takes a
        # lock for the same reason.
        self._lock = threading.RLock()
        self._sources: dict[tuple[str, str], str] = {}
        self._issued_bodies: set[str] = set()
        self._body_trigrams: dict[str, set[str]] = {}
        self._source_key = secrets.token_bytes(32)
        self._STRIP_SEPARATORS = _STRIP_SEPARATORS_TABLE
        self.seeded = SeededValues()

    # -- lifecycle ------------------------------------------------------

    def clear(self) -> None:
        """Drop every entry. Invalidates every token in the host's transcript."""
        with self._lock:
            self._by_value.clear()
            self._by_payload.clear()
            self._issued_bodies.clear()
            self._body_trigrams.clear()
            self._sources.clear()
            # Seeded values are session state too. A Guard reused between
            # tenants otherwise keeps applying the previous tenant's labels.
            self.seeded.clear()
            # Rotating the key is what makes derived handles unlinkable across
            # sessions; without it a provider can join overflow handles from
            # before and after a reset.
            self._source_key = secrets.token_bytes(32)

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
        with self._lock:
            return self._issue_locked(key, pii_class, value)

    def _issue_locked(self, key, pii_class: PIIClass, value: str) -> str:
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
        # Canonical full codeword bodies, for the O(1) scan in
        # _has_stray_issued_payload. An intact body is an exact lookup and
        # never needs decoding.
        folded_body = _crockford_fold(body)
        self._issued_bodies.add(folded_body)
        for gram in _trigrams(folded_body):
            self._body_trigrams.setdefault(gram, set()).add(folded_body)
        return entry.token

    #: Source handles live outside the value vault. Deriving them from
    #: len(_by_value) leaked how many protected values a session had seen
    #: before each new source, and storing them in _by_value let a crawler or
    #: mailbox session grow unbounded despite the advertised hard capacity.
    #: 128 bits for both stored and derived handles. Eight hex characters gave
    #: 32 bits, which collides at roughly 1% by 10,000 sources and 25% by
    #: 50,000, presenting unrelated documents to the model as one source.
    _SOURCE_HANDLE_MAX = 4096

    def source_handle(self, source_type: str, source_id: str) -> str:
        """Stable opaque label for a source, safe to put in a prompt.

        ``wrap_untrusted`` interpolates the caller's ``source_id`` into the
        isolation tag, which is model-visible, and ``source_gate`` documents
        that field as "e.g., client_id, email sender". So the library's own
        suggested usage puts an address in front of the provider. L13 runs
        before L1 precisely so the detectors do not scan wrapper attributes,
        which is what leaves this value untouched.

        The real identifier stays in provenance, the DLP buffers, and audit.
        The handle is derived, not detected: deciding whether a source_id
        "looks sensitive" would be inferring a label from content, and would
        fail on exactly the identifiers no detector covers.
        """
        key = (source_type, source_id)
        with self._lock:
            existing = self._sources.get(key)
            if existing is not None:
                return existing
            if len(self._sources) >= self._SOURCE_HANDLE_MAX:
                # Past the cache cap, derive the handle instead of storing it.
                # Returning one shared literal aliased every later source, so a
                # large RAG or mailbox session lost model-visible attribution
                # between documents. Keyed by a per-session secret, so handles
                # stay unlinkable across sessions and memory stays bounded.
                digest = hmac.new(
                    self._source_key, f"{source_type}\x00{source_id}".encode(), "sha256"
                ).hexdigest()[:32]
                return f"src-{digest}"
            handle = f"src-{secrets.token_hex(16)}"
            self._sources[key] = handle
            return handle

    def issue_batch(self, wanted: list[tuple[PIIClass, str]]) -> dict[tuple[PIIClass, str], str]:
        """Issue tokens for a whole document, or none of them.

        Issuing inside the substitution loop made a capacity failure
        destructive rather than recoverable: entries from the first half of a
        document stayed stored while no tokenized document was returned, so
        retrying the same document failed permanently and only a reset, which
        invalidates every token in the transcript, could recover the session.

        Capacity is checked once against the count of genuinely new keys, then
        every entry is committed under the same lock.
        """
        with self._lock:
            issued: dict[tuple[PIIClass, str], str] = {}
            new_keys: list[tuple[PIIClass, str, str]] = []
            # Set-backed. The previous linear scan of new_keys per candidate was
            # quadratic, costing seconds on a contact export or roster
            # approaching the supported capacity.
            pending: set[tuple[PIIClass, str]] = set()
            for pii_class, value in wanted:
                key = (pii_class, self._normalize(pii_class, value))
                if key in issued or key in pending:
                    continue
                existing = self._by_value.get(key)
                if existing is not None:
                    issued[key] = existing.token
                    continue
                pending.add(key)
                new_keys.append((key[0], key[1], value))

            if len(self._by_payload) + len(new_keys) > self._config.vault_max_entries:
                raise VaultCapacityError(
                    f"privacy vault is full ({self._config.vault_max_entries} entries)"
                )
            for pii_class, norm, value in new_keys:
                issued[(pii_class, norm)] = self._issue_locked(
                    (pii_class, norm), pii_class, value
                )
            return issued

    def token_key(self, pii_class: PIIClass, value: str) -> tuple[PIIClass, str]:
        return (pii_class, self._normalize(pii_class, value))

    def lookup(self, payload: str) -> _Entry | None:
        return self._by_payload.get(payload)

    #: Any run of Crockford symbols the right length to be a codeword body.
    #: Framing-independent on purpose: checking for a surviving "[[" only
    #: catches damage to the closing bracket, so "[GL:EMAIL:...]]" and every
    #: other opening-prefix corruption dispatched literally.
    #: A run of Crockford symbols possibly split by separators a model might
    #: insert. Framing-independent on purpose, and separator-tolerant because
    #: checking only contiguous runs missed "YS5F6JM.VKYQCSD5", which evaded
    #: the valid-token parser and dispatched as a literal recipient.
    #: Two passes rather than one. The contiguous case dominates real input and
    #: is cheap; the separator-tolerant pattern backtracks and runs only over
    #: regions that actually contain a separator between alphanumerics.
    _BODY_RE = re.compile(r"(?<![0-9A-Za-z])[0-9A-Za-z]{15}(?![0-9A-Za-z])")
    _SPLIT_BODY_RE = re.compile(
        r"(?<![0-9A-Za-z])[0-9A-Za-z](?:[\s\-./\\_,]*[0-9A-Za-z]){14,24}(?![0-9A-Za-z])"
    )
    #: The separator-tolerant pass backtracks, so it is bounded. Correctness no
    #: longer depends on it: _ARTIFACT_RE below is linear and unbounded, and
    #: catches damaged tokens at any input size.
    _SPLIT_SCAN_MAX = 64_000

    #: The distinctive GuardLLM token signature. Body damage that changes the
    #: symbol count (an inserted or deleted symbol) leaves nothing for a
    #: length-exact payload scan to match, so combined framing and body damage
    #: dispatched literally at any size. The signature survives both.
    _ARTIFACT_RE = re.compile(
        r"\bGL\s*:\s*(?P<cls>[A-Za-z_]{2,20})\s*:\s*(?P<body>[0-9A-Za-z][0-9A-Za-z\s\-./\\_,]{10,30})"
    )
    _SPLIT_HINT_RE = re.compile(r"[0-9A-Za-z][\s\-./\\_,][0-9A-Za-z]")

    #: A doubled-bracket region mentioning GL. Substitution has already
    #: consumed every resolvable token, so one of these still standing is a
    #: token whose framing or body the model damaged.
    #:
    #: A deleted or inserted body symbol cannot be error-corrected at all: the
    #: window no longer aligns with any codeword, so eight of nine
    #: framing-by-body damage combinations resolved to nothing and dispatched
    #: literally. Recovery is not available, so refusal is the only correct
    #: outcome, and the doubled brackets are what keep this off ordinary text
    #: like "GL:DEBUG:1" or an OpenGL version string.
    _GL_REGION_RE = re.compile(r"\[\s*\[[^\[\]]{4,80}\]\s*\]")

    #: The same signature without the brackets. Requiring them meant a token
    #: stripped of BOTH its framing and its colons was never offered to the
    #: proximity check at all: "GLEMAIL9YP4W6Y742ZMYT", one body symbol short,
    #: resolved to nothing, passed as ordinary text and dispatched literally.
    _GL_SIGNATURE_RE = re.compile(r"(?i)GL[0-9A-Za-z\s\-./\\_,:]{10,60}")

    #: Windows the proximity scan may examine per call. Every candidate region
    #: yields five widths at every offset, so a megabyte of payload-shaped
    #: content took 7.4 seconds, which is a worker occupied by one argument.
    _PROXIMITY_WINDOW_BUDGET = 40_000

    def _proximity_candidates(self, text: str) -> Iterator[str]:
        """Regions worth measuring edit distance against the issued set.

        The prefilter has to be cheap and has to run BEFORE any window is
        generated. A raw digit is what it tests, because a live payload always
        carries one and ordinary bracketed prose does not: "[[Glossary of
        terms]]" is rejected here for a few nanoseconds instead of producing
        seventy five windows and thirteen trigrams apiece. The test is on the
        raw text deliberately, since Crockford folding maps I, L and O onto
        digits and would hand every English word one.
        """
        seen: set[str] = set()
        for pattern, trim in ((self._GL_REGION_RE, 2), (self._GL_SIGNATURE_RE, 0)):
            for m in pattern.finditer(text):
                raw = m.group()[trim : len(m.group()) - trim] if trim else m.group()
                if not any(c.isdigit() for c in raw):
                    continue
                # Colons are stripped: the damage being detected is a missing
                # or misplaced delimiter, so the check cannot depend on one.
                compact = _crockford_fold(
                    raw.translate(self._STRIP_SEPARATORS).replace(":", "")
                )
                if len(compact) < codec.CODEWORD_SYMBOLS - 2 or compact in seen:
                    continue
                seen.add(compact)
                # Second prefilter, and the one that decides the cost. Every
                # trigram of a window is a trigram of the region containing it,
                # so a region sharing fewer than six with every issued body
                # cannot hold a window that shares six, and no window need be
                # generated for it at all. One pass over the region replaces
                # five widths at every offset. This cannot hide a damaged
                # token: it is a necessary condition for the inner test, not an
                # approximation of it. Ordinary prose lands here and stops:
                # 4,000 distinct "[[Reference GL-2024-0001 approved]]" regions
                # were otherwise enough to exhaust the budget and refuse a
                # perfectly good document.
                counts: dict[str, int] = {}
                for gram in _trigrams(compact):
                    for body in self._body_trigrams.get(gram, ()):
                        counts[body] = counts.get(body, 0) + 1
                if counts and max(counts.values()) >= 6:
                    yield compact

    def _has_stray_issued_payload(self, text: str) -> bool:
        """True when a live issued payload survives outside a valid token.

        Substitution consumes properly framed tokens, so a payload resolving to
        a live entry after that is a token whose framing or body the model
        damaged. Membership is exact, so a false positive needs a 60-bit
        collision, which is what lets this be aggressive about candidates.
        """
        # An empty vault has issued nothing, so nothing here can be a damaged
        # token. Checking first also stops a fresh Guard rejecting ordinary
        # GL: text.
        if not self._by_payload:
            return False
        # Deleting the colon between class and body defeats the artifact
        # pattern AND the standalone-run scanners, so
        # "[[GL:EMAIL54G621VXXEJ1RX4]]" dispatched as a literal recipient.
        # Slide a window over every alphanumeric run.
        #
        # Set membership, not decoding. Decoding at every position cost about
        # two seconds on a one-megabyte base64 argument, which a model-proposed
        # blob or an attachment can trigger repeatedly: a straightforward way to
        # occupy a worker. An intact body is an exact lookup after the same
        # Crockford folding the decoder would apply first, so decoding is only
        # needed for genuinely damaged bodies, and those are found by the
        # bounded patterns below.
        n = codec.CODEWORD_SYMBOLS
        for run in re.finditer(r"[0-9A-Za-z]{%d,}" % n, text):
            folded = _crockford_fold(run.group())
            for k in range(len(folded) - n + 1):
                if folded[k : k + n] in self._issued_bodies:
                    return True

        # Proximity to an ISSUED payload, not a shape heuristic. Keying on "GL"
        # plus a known class name was wrong in both directions: a transposed
        # class ("[[GL:EMIAL:...]]") evaded it, while "[[GL Email
        # Configuration]]" and "[[GL Address Normalization]]" were refused.
        # Edit distance to the issued set cannot do either: prose is nowhere
        # near a random 60-bit payload, and a mistyped token is.
        n = codec.CODEWORD_SYMBOLS
        budget = self._PROXIMITY_WINDOW_BUDGET
        for compact in self._proximity_candidates(text):
            for width in (n - 2, n - 1, n, n + 1, n + 2):
                for k in range(len(compact) - width + 1):
                    budget -= 1
                    if budget < 0:
                        # Out of scan budget with candidates still unexamined.
                        # Whether a damaged token is among them is now unknown,
                        # and unknown resolves the same way everywhere else
                        # here: refuse. Reaching this needs content that is
                        # both payload-shaped and enormous, which is a crafted
                        # input, not a document.
                        return True
                    window = compact[k : k + width]
                    counts: dict[str, int] = {}
                    for gram in _trigrams(window):
                        for body in self._body_trigrams.get(gram, ()):
                            counts[body] = counts.get(body, 0) + 1
                    for body, shared in counts.items():
                        # Two edits destroy at most six trigrams, so a genuine
                        # near miss still shares at least this many. The count
                        # is only a prefilter; the distance decides.
                        if shared >= 6 and _within_edits(window, body, 2):
                            return True

        for m in self._ARTIFACT_RE.finditer(text):
            # Require a real PII class name and a body near codeword length.
            # Matching any "GL:WORD:x" rejected ordinary content: a log line,
            # a JSON value, an OpenGL version string, a URL path segment.
            if m.group("cls").upper() not in _CLASS_NAMES:
                continue
            compact = m.group("body").translate(self._STRIP_SEPARATORS)
            if abs(len(compact) - codec.CODEWORD_SYMBOLS) <= 2:
                return True

        def _hits(pattern: re.Pattern[str]) -> bool:
            for m in pattern.finditer(text):
                compact = m.group().translate(self._STRIP_SEPARATORS)
                if len(compact) != codec.CODEWORD_SYMBOLS:
                    continue
                result = codec.decode_text(compact)
                if result.ok and codec.payload_key(result.payload) in self._by_payload:
                    return True
            return False

        if _hits(self._BODY_RE):
            return True
        # Only worth the expensive pattern where a separator actually sits
        # between two alphanumerics, which ordinary prose and code rarely do
        # inside a 15-symbol run.
        if len(text) > self._SPLIT_SCAN_MAX or not self._SPLIT_HINT_RE.search(text):
            return False
        return _hits(self._SPLIT_BODY_RE)

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
        # Scan every class the host configured, not just `classes`. A
        # class_policy override naming a class absent from `classes` would
        # otherwise never be detected, so a host that explicitly enabled a
        # protection would get silence instead of it.
        found = detect(
            text,
            classes=cfg.scanned_classes(),
            seeded=self.seeded,
            detectors=cfg.detectors,
            masked_spans=self._masked_spans(text),
        )

        warnings: list[str] = []
        warnings.extend(found.detector_warnings)
        if found.detection_incomplete and deny_action == "fail":
            # `"fail"` marks the host-assembled path (`Guard.deidentify`), as
            # against `"marker"` for untrusted ingest. The host asked for
            # de-identification on content it declared sensitive and a detector
            # it registered did not run, so we do not know what is in the text.
            # That is not the same as knowing it is clean, and the difference is
            # the whole reason this fails rather than warning.
            return DeidentifyResult(
                content=text,
                allowed=False,
                reason=(
                    "De-identification incomplete: "
                    + "; ".join(found.detector_warnings)
                ),
            )
        if found.unlocatable_credentials and deny_action == "fail":
            # No faithful span to substitute. On the host-assembled path that
            # is a refusal: the host declared this content sensitive and asked
            # for de-identification, so emitting it with the value still in it
            # is not an option.
            #
            # On the untrusted-ingress path it is NOT a refusal. Withholding
            # the document there handed any content author a way to suppress
            # its own retrieval by embedding one split credential-shaped
            # string, and it fired routinely on a leftover high-entropy
            # fragment of a credential that had already been located and
            # redacted. Ingress gets a bounded local replacement and a warning.
            return DeidentifyResult(
                content=text,
                allowed=False,
                reason=(
                    "Obfuscated credential detected with no substitutable span: "
                    + ", ".join(found.unlocatable_credentials)
                ),
                denied=[PIIClass.CREDENTIAL],
            )
        if found.unlocatable_credentials:
            warnings.append(
                "Obfuscated credential fragment may remain: "
                + ", ".join(found.unlocatable_credentials)
            )
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

        # Reserve capacity for the entire document before substituting, so a
        # capacity failure leaves the vault exactly as it was.
        wanted = [
            (m.pii_class, m.value)
            for m in found.matches
            if cfg.policy_for(m.pii_class) is ClassPolicy.TOKENIZE
        ]
        try:
            issued = self.issue_batch(wanted)
        except VaultCapacityError as exc:
            return DeidentifyResult(content=text, allowed=False, reason=str(exc))

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
            token = issued[self.token_key(match.pii_class, match.value)]
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
        content = "".join(pieces)

        # A credential whose extent could not be recovered leaves a prefix
        # behind: the shortest accepted prefix stops inside the secret, so up
        # to nineteen characters of a live key stayed model-visible with
        # allowed=True. A DENY class cannot partially cross.
        #
        # Sweep the result and replace only the containing LINE, which is the
        # bounded local replacement the ingress path needs: it leaves no
        # fragment without withholding the document, so a content author still
        # cannot suppress its own retrieval by embedding a split credential.
        if denied or found.unlocatable_credentials:
            content, swept = self._sweep_credential_residue(content)
            if swept:
                warnings.append(
                    f"Replaced {swept} line(s) still carrying credential material"
                )

        return DeidentifyResult(
            content=content,
            findings=findings,
            warnings=warnings,
            denied=denied,
            detection_incomplete=found.detection_incomplete,
            inference_used=bool(cfg.detectors),
        )

    def _sweep_credential_residue(self, content: str) -> tuple[str, int]:
        """Replace any line still carrying credential material with a marker.

        Runs L3's own scanner over the substituted result, so what counts as
        residue is exactly what the egress blocker would stop. Line-scoped
        because that is the smallest unit that reliably contains a wrapped or
        split value, and because replacing the document was the failure this
        exists to avoid.
        """
        from guardllm.security.outbound_dlp import _scan_secrets

        if not _scan_secrets(content):
            return content, 0
        swept = 0
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if _scan_secrets(line):
                lines[i] = marker_for(PIIClass.CREDENTIAL)
                swept += 1
        rebuilt = "\n".join(lines)
        if swept == 0 and _scan_secrets(rebuilt):
            # Residue spans a line break, so no single line carries it. Fall
            # back to the whole span between the first and last offending line.
            return marker_for(PIIClass.CREDENTIAL), 1
        return rebuilt, swept

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
            if not entry.value or entry.value not in out:
                continue
            # Bounded replacement. A global str.replace of a short vaulted
            # value corrupts unrelated words that merely contain it, which
            # damages a genuine L0 diagnostic instead of protecting anything.
            out = re.sub(
                rf"(?<![A-Za-z0-9]){re.escape(entry.value)}(?![A-Za-z0-9])",
                entry.token,
                out,
            )
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

        # A token whose closing framing the model damaged is not matched by
        # _TOKEN_RE, so substitution leaves it in place and the argument
        # dispatches literally: "[[GL:EMAIL:8BDBYD8BQE4VW4F]" as a recipient.
        # Free-text restoration counts stray openers against a budget; for a
        # tool argument that is not enough, because one surviving opener is a
        # corrupted dispatch. Unconditional.
        if failure is None:
            for leaf in _iter_strings(new_args):
                if self._has_stray_issued_payload(leaf):
                    failure = "Damaged privacy token framing in tool arguments"
                    break

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
