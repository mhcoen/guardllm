"""L13 detection: structural identifiers and host-seeded values.

Two tiers, both deterministic and both local:

**Structural.** A pattern plus, wherever the identifier carries one, an
arithmetic validator: Luhn for card numbers, mod-97 for IBANs, the ABA
checksum for routing numbers, issued-range checks for SSNs. The validator is
what separates this from naive regex redaction, and it is why the
false-positive rate is low enough to substitute automatically. Identifiers
with no checksum (passport, driver's licence, national ID) are matched only
when a labelling context is present, because an unanchored pattern for them
is mostly false positives.

**Host-seeded.** Values the application already knows are private, because
they came out of a database row or a session record. This is the mechanism
for person names and street addresses. The library does not attempt to find a
name in free text on its own: doing so means inferring a label from content,
which is the thing this project declines to do everywhere else. An
application that needs free-text name coverage supplies a recognizer.

Everything runs in one pass over the input. The combined alternation is
compiled once; validators execute only on candidate matches, never on the
whole text.
"""

from __future__ import annotations

import ipaddress
import re
from collections import deque
from dataclasses import dataclass, field

from guardllm.security.types import PIIClass

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _digits(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def luhn_valid(value: str) -> bool:
    """Luhn check. Rejects the vast majority of digit runs that look like cards."""
    ds = _digits(value)
    if not 13 <= len(ds) <= 19:
        return False
    total = 0
    parity = len(ds) % 2
    for i, ch in enumerate(ds):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


#: Major-issuer prefixes. Luhn is a checksum, not an identifier: it accepts
#: about one in ten random digit runs of the right length, which is why a
#: colour-table constant in colorsys.py and a rounding constant in decimal.py
#: were both classified as cards.
def _card_issuer(ds: str) -> bool:
    if ds.startswith("4"):  # Visa
        return True
    if ds[:2] in {"34", "37"}:  # Amex
        return True
    if 51 <= int(ds[:2]) <= 55 or 2221 <= int(ds[:4]) <= 2720:  # Mastercard
        return True
    if ds.startswith("6011") or ds[:2] == "65" or 644 <= int(ds[:3]) <= 649:  # Discover
        return True
    if ds[:2] in {"36", "38", "39"} or 300 <= int(ds[:3]) <= 305:  # Diners
        return True
    if 3528 <= int(ds[:4]) <= 3589:  # JCB
        return True
    return ds[:2] == "62"  # UnionPay


def card_valid(value: str) -> bool:
    """Luhn plus a real issuer prefix."""
    ds = _digits(value)
    if not 13 <= len(ds) <= 19:
        return False
    return luhn_valid(value) and _card_issuer(ds)


def iban_valid(value: str) -> bool:
    """ISO 13616 mod-97 check."""
    compact = re.sub(r"[\s-]", "", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def routing_valid(value: str) -> bool:
    """ABA routing transit number checksum."""
    ds = _digits(value)
    if len(ds) != 9:
        return False
    w = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    return sum(int(d) * k for d, k in zip(ds, w, strict=True)) % 10 == 0


def ssn_valid(value: str) -> bool:
    """Reject SSN area/group/serial combinations the SSA never issues.

    Area 000, 666, and 900-999 are unissued; group 00 and serial 0000 are
    unissued. Screening these out is what keeps ordinary 3-2-4 digit runs
    (part numbers, phone fragments) from being vaulted.
    """
    ds = _digits(value)
    if len(ds) != 9:
        return False
    area, group, serial = int(ds[:3]), int(ds[3:5]), int(ds[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    return group != 0 and serial != 0


def ipv4_valid(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 and (p == "0" or not p.startswith("0")) for p in parts)
    except ValueError:
        return False


#: Assigned E.164 country calling codes, longest first so "1" does not shadow
#: "1876". A compact international number is otherwise indistinguishable from a
#: signed integer, and treating every "+" followed by digits as a phone number
#: tokenizes counters, deltas, and version strings in code and logs.
_E164_COUNTRY_CODES = (
    "998 996 995 994 993 992 977 976 975 974 973 972 971 970 968 967 966 965 964 963 962 961 960 "
    "886 880 878 875 874 873 872 871 870 856 855 853 852 850 800 692 691 690 689 688 687 686 685 "
    "683 682 681 680 679 678 677 676 675 674 673 672 670 599 598 597 596 595 594 593 592 591 590 "
    "509 508 507 506 505 504 503 502 501 500 423 421 420 389 387 386 385 383 382 381 380 378 377 "
    "376 375 374 373 372 371 370 359 358 357 356 355 354 353 352 351 350 299 298 297 291 290 269 "
    "268 267 266 265 264 263 262 261 260 258 257 256 255 254 253 252 251 250 249 248 246 245 244 "
    "243 242 241 240 239 238 237 236 235 234 233 232 231 230 229 228 227 226 225 224 223 222 221 "
    "220 218 216 213 212 211 98 95 94 93 92 91 90 86 84 82 81 66 65 64 63 62 61 60 58 57 56 55 54 "
    "53 52 51 49 48 47 46 45 44 43 41 40 39 36 34 33 32 31 30 27 20 7 1"
).split()


def e164_valid(value: str) -> bool:
    """Accept a compact international number only on deterministic evidence.

    Requires an assigned country calling code and a total length in the range
    real subscriber numbers occupy. Without both, "+123456789" in a diff or a
    log line is tokenized as a phone number, which corrupts content the model
    was asked to reason about.
    """
    ds = _digits(value)
    if not 11 <= len(ds) <= 15:
        return False
    return any(ds.startswith(cc) for cc in _E164_COUNTRY_CODES)


def phone_valid(value: str) -> bool:
    """Require a plausible numbering plan, separators or not.

    Passing separated forms on punctuation alone was not enough: "+3.140000"
    in a formatted-float test string satisfies "country code, separator, digit
    groups" and was tokenized as a phone number.
    """
    if value.lstrip().startswith("+"):
        return e164_valid(value)
    return len(_digits(value)) == 10


def ipv6_valid(value: str) -> bool:
    """Delegate to ipaddress so compressed forms ("2001:db8::1") are accepted.

    The previous pattern required all eight groups written out, so every
    compressed address, which is the form people actually write, went
    undetected and crossed the boundary in plaintext.
    """
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def dob_valid(value: str) -> bool:
    """Accept only dates whose year is plausible for a date of birth."""
    years = re.findall(r"\d{4}", value)
    if not years:
        return False
    return 1900 <= int(years[0]) <= 2025


# ---------------------------------------------------------------------------
# Structural detectors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectorSpec:
    pii_class: PIIClass
    group: str
    pattern: str
    validator: object | None = None


#: Order matters only for tie-breaking inside `re`'s alternation; genuine
#: overlap is resolved structurally in `_resolve_overlaps`, not by this order.
_DETECTORS: tuple[DetectorSpec, ...] = (
    DetectorSpec(
        PIIClass.EMAIL,
        "email",
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    ),
    DetectorSpec(
        PIIClass.IBAN,
        "iban",
        r"(?i:\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}[ -]?[A-Z0-9]{1,4})\b",
        iban_valid,
    ),
    DetectorSpec(
        PIIClass.CREDIT_CARD,
        "credit_card",
        r"\b(?:\d[ -]?){12,18}\d\b",
        card_valid,
    ),
    DetectorSpec(
        PIIClass.SSN,
        "ssn",
        r"(?:(?i:\b(?:ssn|social\s+security(?:\s+(?:number|no\.?|#))?)\b\s*:?\s*)"
        r"(?P<ssn_v>\d{3}[-\s]?\d{2}[-\s]?\d{4})\b"
        r"|\b\d{3}-\d{2}-\d{4}\b)",
        ssn_valid,
    ),
    DetectorSpec(
        PIIClass.ROUTING_NUMBER,
        "routing_number",
        r"(?i:\b(?:routing|aba|rtn)(?:\s+(?:number|no\.?|#))?\s*:?\s*)(?P<routing_number_v>\d{9})\b",
        routing_valid,
    ),
    DetectorSpec(
        PIIClass.IPV6,
        "ipv6",
        r"(?<![:.\w])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![:.\w])",
        ipv6_valid,
    ),
    DetectorSpec(
        PIIClass.IPV4,
        "ipv4",
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        ipv4_valid,
    ),
    DetectorSpec(
        PIIClass.MAC,
        "mac",
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
    ),
    DetectorSpec(
        PIIClass.PHONE,
        "phone",
        r"(?:\+\d{1,3}[ .\-](?:\(?\d{2,5}\)?[ .\-]?){1,3}\d{3,4}\b"
        r"|(?:\+\d{1,3}[ .\-]?)?(?:\(\d{3}\)|\b\d{3})[ .\-]\d{3}[ .\-]\d{4}\b"
        r"|(?<![\w.+-])\+\d{11,15}(?![\d.]))",
        phone_valid,
    ),
    DetectorSpec(
        PIIClass.DATE_OF_BIRTH,
        "date_of_birth",
        r"(?i:\b(?:dob|date\s+of\s+birth|born)\b\s*:?\s*)"
        r"(?P<date_of_birth_v>\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{4}|"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})",
        dob_valid,
    ),
    DetectorSpec(
        PIIClass.MEDICAL_RECORD,
        "medical_record",
        r"(?i:\b(?:mrn|medical\s+record(?:\s+(?:number|no\.?|#))?)\s*:?\s*)(?P<medical_record_v>[A-Za-z0-9][A-Za-z0-9\-]{3,19})",
    ),
    # No checksum exists for these, so they are matched only with a labelling
    # context. An unanchored pattern would be mostly false positives, and a
    # detector that fires on ordinary text is worse than no detector: it
    # substitutes values the model needed and teaches operators to disable it.
    DetectorSpec(
        PIIClass.PASSPORT,
        "passport",
        r"(?i:\bpassport(?:\s+(?:number|no\.?|#))?\s*:?\s*)(?P<passport_v>[A-Za-z0-9]{6,9})\b",
    ),
    DetectorSpec(
        PIIClass.DRIVERS_LICENSE,
        "drivers_license",
        r"(?i:\b(?:driver'?s?\s+licen[cs]e(?:\s+(?:number|no\.?|#))?\s*:?\s*"
        r"|dl(?:\s*(?:number|no\.?|#))?\s*[:#]\s*))"
        r"(?P<drivers_license_v>[A-Za-z0-9][A-Za-z0-9\-]{4,19})\b",
    ),
    DetectorSpec(
        PIIClass.NATIONAL_ID,
        "national_id",
        r"(?i:\bnational\s+id(?:entity)?(?:\s+(?:number|no\.?|#))?\s*:?\s*)"
        r"(?P<national_id_v>[A-Za-z0-9][A-Za-z0-9\-]{4,19})\b",
    ),
    DetectorSpec(
        PIIClass.URL,
        "url",
        r"https?://[^\s<>\"']+",
    ),
)

_BY_GROUP: dict[str, DetectorSpec] = {d.group: d for d in _DETECTORS}

#: One compiled alternation, one pass over the input. Validators run only on
#: whatever this produces, never over the whole text, which is what keeps the
#: added cost proportional to the number of candidates rather than the length.
_COMBINED = re.compile("|".join(f"(?P<{d.group}>{d.pattern})" for d in _DETECTORS))

#: Maps every group name in a compiled alternation, both the detector group and
#: its optional inner value group, to the spec and the value group to read.
#: Precomputed so the match loop does no string building and no membership test
#: per match; on a PII-dense document that loop runs tens of thousands of times.
def _group_info(pattern: re.Pattern[str]) -> dict[str, tuple[DetectorSpec, str | None]]:
    info: dict[str, tuple[DetectorSpec, str | None]] = {}
    for d in _DETECTORS:
        if d.group not in pattern.groupindex:
            continue
        vgroup = f"{d.group}_v"
        vgroup = vgroup if vgroup in pattern.groupindex else None
        info[d.group] = (d, vgroup)
        if vgroup:
            info[vgroup] = (d, vgroup)
    return info


_GROUP_INFO = _group_info(_COMBINED)

#: Compiling only the requested classes skips whole detectors rather than
#: matching and discarding them. The default class set omits IPv4, IPv6, MAC,
#: and URL, which is four of fifteen alternatives and two of the more expensive
#: ones. Cached because a session's class set does not change between calls.
_SUBSET_CACHE: dict[frozenset[PIIClass], tuple[re.Pattern[str], dict]] = {}


def _compiled_for(classes: frozenset[PIIClass]) -> tuple[re.Pattern[str], dict]:
    hit = _SUBSET_CACHE.get(classes)
    if hit is not None:
        return hit
    wanted = [d for d in _DETECTORS if d.pii_class in classes]
    if not wanted:
        compiled = re.compile(r"(?!x)x")  # matches nothing
        entry = (compiled, {})
    else:
        compiled = re.compile("|".join(f"(?P<{d.group}>{d.pattern})" for d in wanted))
        entry = (compiled, _group_info(compiled))
    _SUBSET_CACHE[classes] = entry
    return entry


# ---------------------------------------------------------------------------
# Seeded values
# ---------------------------------------------------------------------------


class _AhoCorasick:
    """Multi-pattern exact matcher, built once and reused across calls.

    Used above _SEEDED_AUTOMATON_THRESHOLD entries so a large roster stays a
    single pass rather than N independent scans.
    """

    __slots__ = ("_goto", "_fail", "_out")

    def __init__(self, patterns: dict[str, PIIClass]) -> None:
        self._goto: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._out: list[list[tuple[str, PIIClass]]] = [[]]
        for pat, cls in patterns.items():
            node = 0
            for ch in pat:
                nxt = self._goto[node].get(ch)
                if nxt is None:
                    nxt = len(self._goto)
                    self._goto.append({})
                    self._fail.append(0)
                    self._out.append([])
                    self._goto[node][ch] = nxt
                node = nxt
            self._out[node].append((pat, cls))
        queue: deque[int] = deque()
        for nxt in self._goto[0].values():
            queue.append(nxt)
        while queue:
            node = queue.popleft()
            for ch, nxt in self._goto[node].items():
                queue.append(nxt)
                f = self._fail[node]
                while f and ch not in self._goto[f]:
                    f = self._fail[f]
                cand = self._goto[f].get(ch, 0)
                self._fail[nxt] = cand if cand != nxt else 0
                self._out[nxt].extend(self._out[self._fail[nxt]])

    def find(self, haystack: str) -> list[tuple[int, int, PIIClass]]:
        hits: list[tuple[int, int, PIIClass]] = []
        node = 0
        for i, ch in enumerate(haystack):
            while node and ch not in self._goto[node]:
                node = self._fail[node]
            node = self._goto[node].get(ch, 0)
            for pat, cls in self._out[node]:
                hits.append((i - len(pat) + 1, i + 1, cls))
        return hits


_SEEDED_AUTOMATON_THRESHOLD = 100


def _fold_with_offsets(text: str) -> tuple[str, list[int] | None]:
    """Case-fold, returning an index map only when folding changes length.

    Almost all text folds one-to-one, so the common path returns ``None`` and
    the caller uses folded offsets directly. Building one Python integer per
    character unconditionally cost ~84MB on a 1MB input, and there is no
    inbound size limit, so a multi-megabyte document in a deployment using
    seeded names could exhaust memory.
    """
    folded = text.casefold()
    if len(folded) == len(text):
        return folded, None
    out: list[str] = []
    offsets: list[int] = []
    for i, ch in enumerate(text):
        f = ch.casefold()
        out.append(f)
        offsets.extend([i] * len(f))
    return "".join(out), offsets


def _standalone(text: str, start: int, end: int) -> bool:
    """True when the span is not embedded inside a longer alphanumeric run."""
    if start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        return False
    if end < len(text) and (text[end].isalnum() or text[end] == "_"):
        return False
    return True


class SeededValues:
    """Host-declared private values, matched exactly after normalization."""

    def __init__(self) -> None:
        self._values: dict[str, PIIClass] = {}
        self._automaton: _AhoCorasick | None = None
        self._dirty = False

    def __len__(self) -> int:
        return len(self._values)

    def add(self, values: dict[str, PIIClass]) -> None:
        for raw, cls in values.items():
            norm = raw.strip().casefold()
            if norm:
                self._values[norm] = cls
        self._dirty = True

    def clear(self) -> None:
        self._values.clear()
        self._automaton = None
        self._dirty = False

    def find(self, text: str) -> list[tuple[int, int, PIIClass]]:
        """Locate seeded values, returning offsets into the ORIGINAL text.

        Case folding is not length preserving: ``"\u00df".casefold()`` is
        ``"ss"``, so every match after one in the text would be reported at a
        shifted offset and the substitution would cut the wrong characters.
        A per-character fold with an index map avoids that.

        Matches must also stand alone. Unrestricted substring matching means
        seeding a real short surname such as "Li" tokenizes the middle of
        "Alice", corrupting content the model needed and leaving the actual
        name in place.
        """
        if not self._values:
            return []
        folded, offsets = _fold_with_offsets(text)
        if len(self._values) > _SEEDED_AUTOMATON_THRESHOLD:
            if self._automaton is None or self._dirty:
                self._automaton = _AhoCorasick(self._values)
                self._dirty = False
            raw = self._automaton.find(folded)
        else:
            raw = []
            for needle, cls in self._values.items():
                start = folded.find(needle)
                while start != -1:
                    raw.append((start, start + len(needle), cls))
                    start = folded.find(needle, start + 1)

        hits: list[tuple[int, int, PIIClass]] = []
        for fs, fe, cls in raw:
            if not _standalone(folded, fs, fe):
                continue
            if offsets is None:
                hits.append((fs, fe, cls))
                continue
            if fs >= len(offsets) or fe - 1 >= len(offsets):
                continue
            hits.append((offsets[fs], offsets[fe - 1] + 1, cls))
        return hits


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RawMatch:
    pii_class: PIIClass
    start: int
    end: int
    value: str
    inferred: bool = False


@dataclass
class DetectionResult:
    matches: list[RawMatch]
    #: Spans that overlap partially without containment. Reported rather than
    #: resolved: inventing a precedence rule to break a genuine ambiguity is
    #: how a detector quietly substitutes the wrong span.
    ambiguous: list[tuple[RawMatch, RawMatch]]
    #: Credentials detectable only in a deobfuscated form, so they have no
    #: faithful span to substitute. The caller must refuse the content.
    unlocatable_credentials: list[str] = field(default_factory=list)


def _spans_overlap(a: RawMatch, b: RawMatch) -> bool:
    return a.start < b.end and b.start < a.end


def _contains(outer: RawMatch, inner: RawMatch) -> bool:
    return outer.start <= inner.start and inner.end <= outer.end


def _resolve_overlaps(matches: list[RawMatch]) -> DetectionResult:
    """Keep containing spans, drop contained ones, flag partial overlaps.

    A validated structural span that contains another wins: a card number
    inside a longer identifier, an email that swallows a bare domain. Partial
    overlap without containment is genuinely ambiguous and is surfaced instead
    of being decided by a made-up class-priority table.
    """
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
    kept: list[RawMatch] = []
    ambiguous: list[tuple[RawMatch, RawMatch]] = []
    for cand in ordered:
        replaced = False
        drop = False
        for i, existing in enumerate(kept):
            if not _spans_overlap(cand, existing):
                continue
            if _contains(existing, cand):
                drop = True
                break
            if _contains(cand, existing):
                kept[i] = cand
                replaced = True
                break
            ambiguous.append((existing, cand))
            drop = True
            break
        if not drop and not replaced:
            kept.append(cand)
    kept.sort(key=lambda m: m.start)
    return DetectionResult(kept, ambiguous)


def credential_spans(text: str) -> tuple[list[tuple[int, int]], list[str]]:
    """Locate credentials using L3's complete scanner, not a subset of it.

    Delegates to ``outbound_dlp.scan_secret_spans`` so the model-boundary
    denier and the egress blocker consume the same findings. Reusing only the
    regex table left high-entropy and hex-encoded secrets crossing inbound
    while L3 blocked the identical values outbound.
    """
    from guardllm.security.outbound_dlp import scan_secret_spans

    return scan_secret_spans(text)


def detect(
    text: str,
    *,
    classes: frozenset[PIIClass],
    seeded: SeededValues | None = None,
    recognizer: object | None = None,
    masked_spans: list[tuple[int, int]] | None = None,
) -> DetectionResult:
    """Find identifiers in ``text``.

    ``masked_spans`` are regions to skip, used to carry already-issued tokens
    through untouched. Without it, de-identification would not be idempotent:
    a second pass would try to vault the tokens the first pass produced.
    """
    masked = masked_spans or []

    def _is_masked(start: int, end: int) -> bool:
        return any(ms < end and start < me for ms, me in masked)

    matches: list[RawMatch] = []
    compiled, group_info = _compiled_for(classes)

    for m in compiled.finditer(text):
        info = group_info.get(m.lastgroup or "")
        if info is None:
            continue
        spec, value_group = info
        # Context-anchored detectors capture the identifier in a named value
        # group so the label ("MRN:", "Passport No.") is not swallowed into the
        # span and replaced along with the value.
        # A detector may offer a value group on only one branch of its
        # alternation (labelled compact SSN vs. separated SSN). When that
        # branch did not participate, fall back to the whole match instead of
        # dropping the hit, which would silently disable the other form.
        value = m.group(value_group) if value_group is not None else None
        if value is not None:
            start, end = m.start(value_group), m.end(value_group)
        else:
            start, end, value = m.start(), m.end(), m.group()
        if masked and _is_masked(start, end):
            continue
        if spec.validator is not None and not spec.validator(value):
            continue
        matches.append(RawMatch(spec.pii_class, start, end, value))

    unlocatable_credentials: list[str] = []
    if PIIClass.CREDENTIAL in classes:
        spans, unlocatable_credentials = credential_spans(text)
        for start, end in spans:
            if not _is_masked(start, end):
                matches.append(
                    RawMatch(PIIClass.CREDENTIAL, start, end, text[start:end])
                )

    if seeded is not None:
        for start, end, cls in seeded.find(text):
            if cls in classes and not _is_masked(start, end):
                matches.append(RawMatch(cls, start, end, text[start:end]))

    if recognizer is not None and hasattr(recognizer, "find"):
        for finding in recognizer.find(text):
            cls = getattr(finding, "pii_class", None)
            start = getattr(finding, "start", None)
            end = getattr(finding, "end", None)
            if cls in classes and start is not None and end is not None:
                if not _is_masked(start, end):
                    matches.append(RawMatch(cls, start, end, text[start:end], inferred=True))

    resolved = _resolve_overlaps(matches)
    resolved.unlocatable_credentials = unlocatable_credentials
    return resolved
