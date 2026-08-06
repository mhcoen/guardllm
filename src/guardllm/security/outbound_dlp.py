"""Part 7: Outbound DLP (Data Loss Prevention).

Scans outbound content against recently ingested untrusted content
to detect exfiltration attempts. Checks verbatim overlap, n-gram
overlap, and secret patterns.
"""

from __future__ import annotations

import math
import re
from collections import deque
from typing import NamedTuple

from guardllm.security.normalization import (
    MAX_OVERLAP_CHARS,
    compute_lcs_length,
    compute_ngram_overlap,
    deobfuscate_reversed,
    deobfuscate_separated,
    deobfuscate_spelled,
    normalize_for_overlap,
    strip_invisibles,
)
from guardllm.security.types import OutboundResult, SecurityContext

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

#: One registry. Each grammar records its anchor as literal segments with the
#: separators its own syntax requires, plus the body it accepts. Nothing here
#: is derived by rewriting another pattern: deriving a variant by making
#: required separators optional is what turned ``Bearer\s+`` into ``Bearer\s*``
#: and reported an English sentence as a JWT.
#:
#: ``anchor`` is the literal run, ``sep_after`` says a separator of the
#: grammar's own must follow it, and that flag is what rejects an anchor that
#: only exists because separators were removed. ``ghp_`` is ``ghp`` plus a
#: required separator, so ``through_put_measurement`` offers ``ghp`` in the
#: compact form but has a body character after it in the original and is not a
#: candidate. No exemption list is needed for that class.
#:
#: ``needs_random`` marks the anchors ordinary text writes on its own: ``sk``
#: lives inside ``disk`` and ``task``, ``Bearer`` starts sentences. Those must
#: also look random when they begin mid-token. The rest are anchored by
#: something English does not produce.


class _Grammar(NamedTuple):
    label: str
    anchor: tuple[str, ...]
    sep_after: bool
    body_extra: str
    upper_only: bool
    min_body: int
    max_body: int
    randomness: str  # "never" | "mid_token" | "always"


#: ``body_extra`` must match what each grammar really accepts. Getting this
#: wrong is quiet and expensive: with ``-`` treated as a separator rather than
#: as body, a Slack token reads as three fragments, its ten character minimum
#: is met by the first one, and everything past the second is left in the text.
#:
#: ``randomness`` is where the two awkward anchors are handled. ``sk`` lives
#: inside ``disk`` and ``task``, so it must look random when it starts
#: mid-token. ``Bearer`` is worse: it starts English sentences, and with ``.``
#: in its body "Use Bearer authorization. Header values are case sensitive."
#: parses as a JWT wherever it appears, so it must look random always.
_GRAMMARS: list[_Grammar] = [
    _Grammar("OpenAI project key", ("skproj",), True, "-_", False, 20, 220, "never"),
    _Grammar("OpenAI API key", ("sk",), True, "", False, 20, 80, "mid_token"),
    _Grammar("AWS access key", ("AKIA",), False, "", True, 16, 16, "never"),
    _Grammar("Google OAuth token", ("ya29",), True, "-_", False, 20, 600, "never"),
    _Grammar("GitHub OAuth token", ("gho",), True, "", False, 36, 60, "mid_token"),
    _Grammar("GitHub personal access token", ("ghp",), True, "", False, 36, 60, "mid_token"),
    _Grammar("GitHub app token", ("ghs",), True, "", False, 36, 60, "mid_token"),
    _Grammar("GitHub refresh token", ("ghr",), True, "", False, 36, 60, "mid_token"),
    _Grammar(
        "Slack token", ("xoxb", "xoxa", "xoxp", "xoxr", "xoxs"),
        True, "-", False, 10, 100, "never",
    ),
    _Grammar("Bearer/JWT token", ("Bearer",), True, "-_.", False, 30, 800, "always"),
]


_PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")

#: How wide a run of non-body characters may be and still be read as an
#: inserted split rather than a boundary between two things.
#:
#: The size is the weaker half of the test; _joinable_gap's quote rule is what
#: actually protects structure, and measurement says so: at 10, 20 and 40 the
#: standard library figure is identical and only the leak changes. Sixty four
#: is where every gap probed closes. It cannot simply be removed, though;
#: without any ceiling a credential and an unrelated token 400 characters
#: apart join into one 459 character finding.
_MAX_GAP = 64

#: How far a split anchor may itself be broken, e.g. ``s,k-abc``.
_MAX_ANCHOR_GAP = 2

_ENTROPY_THRESHOLD = 4.5
_ENTROPY_MIN_LENGTH = 20
# A string of length L has a maximum possible Shannon entropy of log2(L).
# For L in [20, 22] that ceiling (4.32 - 4.46 bits) is below _ENTROPY_THRESHOLD,
# so a 20-22 char random token could NEVER trip the absolute threshold. For
# such short tokens, flag when the entropy is within this margin of the
# theoretical maximum for the length (i.e. near-maximal randomness) instead.
_ENTROPY_LENGTH_MARGIN = 0.30

_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")

_HEX_RE = re.compile(r"[0-9a-fA-F]+")

# Whitespace run, used to build a whitespace-removed form for secret scanning
_WHITESPACE_RE = re.compile(r"\s+")


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _shannon_entropy_bytes(data: bytes) -> float:
    """Compute Shannon entropy of a byte string in bits per byte."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _joinable_gap(gap: str) -> bool:
    """Can this run of non-body characters be an inserted split?

    Two tests, and the second is what keeps structure intact. A gap longer than
    a few characters is not somebody breaking a value up. And a gap holding a
    quote is a boundary between two values rather than a wound in one: the
    ``","`` between minified JSON fields, the quotes around a CSV field. Only
    the size limit was in place at first, set to two, and it worked by accident
    because ``","`` happens to be three characters; a value split with ``" - "``
    then leaked because the same limit refused a legitimate three character
    gap. Saying what a boundary IS covers both.
    """
    if len(gap) > _MAX_GAP:
        return False
    # A quote is structural unless it is the whole gap. Where a value ends, the
    # quote closing it arrives with company: ``","`` between minified JSON
    # fields, ``", `` before the next key, ``") `` closing a call. A quote
    # driven INTO a value arrives alone. Refusing on any quote at all made
    # ``"`` the one separator that still smuggled 32 characters out; allowing
    # up to two swallowed the ``")`` that closes a function call.
    if not any(c in "\"'`" for c in gap):
        return True
    return len(gap) == 1


def _looks_random(s: str) -> bool:
    """Does this clear the same randomness bar the entropy scanner applies?

    Same threshold and length allowance, so "random" means one thing in this
    module rather than two. No minimum length, unlike the standalone entropy
    scan: this is asked about text a grammar has already claimed, and the
    shortest thing any grammar accepts is a 15 character Slack token.
    """
    if not s:
        return False
    return _shannon_entropy(s) >= min(
        _ENTROPY_THRESHOLD, math.log2(len(s)) - _ENTROPY_LENGTH_MARGIN
    )


def _is_alnum(ch: str) -> bool:
    """ASCII alphanumeric, the universal core of every body here.

    Anchor logic uses this rather than a grammar's body class. The separator a
    grammar requires after its anchor can itself be a body character: Slack's
    is ``-``, which its body also accepts, so asking "is this a body character"
    found no separator, rejected every Slack token, and left 35 characters of
    one in the text.
    """
    return ch.isascii() and ch.isalnum()


def _is_body(ch: str, g: _Grammar) -> bool:
    """Is this character part of this grammar's body?"""
    if not ch.isascii():
        return False
    if ch in g.body_extra:
        return True
    if g.upper_only:
        return ch.isdigit() or ("A" <= ch <= "Z")
    return ch.isalnum()


def _walk_anchor(text: str, pos: int, literal: str, g: _Grammar) -> int | None:
    """Match ``literal`` at ``pos``, tolerating separators driven into it.

    Returns the index just past the literal, or None. ``s,k-abc`` splits the
    anchor itself, so the letters are matched one at a time with a bounded gap
    allowed between them.
    """
    i = pos
    for k, want in enumerate(literal):
        if k:
            gap = 0
            while i < len(text) and gap <= _MAX_ANCHOR_GAP and not _is_alnum(text[i]):
                i += 1
                gap += 1
        if i >= len(text) or text[i] != want:
            return None
        i += 1
    return i


def _fragments(text: str, pos: int, g: _Grammar) -> list[tuple[int, int]]:
    """Body fragments after the anchor, joined across gaps of at most two.

    A fragment is a maximal run of body characters. This is the whole of the
    locality guarantee: the walk stops at the first gap too wide to be a split,
    so nothing beyond it can ever be drawn into the value. A newline is a gap
    like any other, which is why a value wrapped over several lines needs no
    line handling and why trailing spaces before a break cannot reopen it.
    """
    out: list[tuple[int, int]] = []
    i, total = pos, 0
    while i < len(text) and total < g.max_body:
        gap = i
        while gap < len(text) and not _is_body(text[gap], g):
            gap += 1
        if gap > i and not _joinable_gap(text[i:gap]):
            break
        stop = gap
        while stop < len(text) and _is_body(text[stop], g):
            stop += 1
        if stop == gap:
            break
        out.append((gap, stop))
        total += stop - gap
        i = stop
    return out


def _resolve(text: str, start: int, body_start: int, g: _Grammar) -> tuple[int, int] | None:
    """Decide how far a candidate reaches, in original coordinates.

    Fragments are taken while the grammar is not yet satisfied, which is a
    split value being reassembled, and then exactly one more, which is a value
    split after its minimum was already met. Both are needed and neither
    subsumes the other: without the first a value broken into five pieces keeps
    its tail, without the second a key split just past its minimum keeps
    everything after the split.

    The second one costs a following fragment when the value was in fact
    complete. That is the price of an extent nothing in the text determines,
    and it is paid one fragment at a time rather than to the end of the line.
    """
    frags = _fragments(text, body_start, g)
    if not frags:
        return None
    taken = 0
    for lo, hi in frags:
        taken += hi - lo
        if taken >= g.min_body:
            break
    if taken < g.min_body:
        return None
    used = 0
    total = 0
    for idx, (lo, hi) in enumerate(frags):
        total += hi - lo
        used = idx
        if total >= g.min_body:
            break
    if used + 1 < len(frags):
        used += 1
    # A value wrapped over several lines leaves each continuation alone on its
    # own line, and a long one clears the minimum on its first fragment, so
    # neither rule above reaches the tail: a 208 character project key broken
    # over six lines kept 34 of them. Keep taking fragments that are the entire
    # content of their line. A prose line has other words on it and stops this
    # at once.
    while used + 1 < len(frags):
        prev_end = frags[used][1]
        nxt_lo, nxt_hi = frags[used + 1]
        gap = text[prev_end:nxt_lo]
        if "\n" not in gap or gap.strip():
            break
        line_lo = text.rfind("\n", 0, nxt_lo) + 1
        line_end = text.find("\n", nxt_hi)
        if line_end == -1:
            line_end = len(text)
        if text[line_lo:nxt_lo].strip() or text[nxt_hi:line_end].strip():
            break
        used += 1
    # And a long value broken into pieces on ONE line clears the minimum on its
    # first piece too, so keep taking fragments that scan as credential
    # material in their own right. This asks the entropy scanner rather than
    # guessing at length: a random 35 character piece is caught, the word
    # "trailing" is not, and prose therefore stops it at the first word.
    # And a long value broken into pieces on ONE line clears the minimum on its
    # first piece too. Take fragments through to the LAST one that scans as
    # credential material in its own right, not up to the first that does not:
    # a piece whose entropy happens to fall under the bar sat between pieces
    # whose entropy did not, and stopping at it left 34 characters in the text
    # with the rest of the value redacted either side.
    #
    # This asks the entropy scanner rather than guessing at length. Prose stops
    # it immediately, because no word scans, so the last scanning fragment is
    # the value itself and nothing more is taken.
    last = used
    for idx in range(used + 1, len(frags)):
        lo_f, hi_f = frags[idx]
        if _entropy_spans(text[lo_f:hi_f]):
            last = idx
    # Nothing further. Two extra rules were tried here, one taking a fragment
    # past the last scanning one and one refusing to leave a single orphan
    # fragment, and measurement said both closed exactly nothing: the same six
    # residual cases survived either way, while the orphan rule additionally
    # swallowed the last field of a CSV row. What remains is a final fragment
    # of at most 16 characters in a value deliberately broken into four or more
    # pieces on one line, and the surrounding content is refused in four of
    # those six cases rather than passed.
    return start, frags[last][1]


def _findings(text: str) -> list[tuple[int, int, str]]:
    """Every credential in ``text``, as spans into the ORIGINAL text.

    The single engine. Both the span finder used by L13 and the label scan used
    by L3 read this, so the two cannot drift apart: a value split with
    punctuation was found by one and missed by the other precisely because they
    were separate implementations.

    Candidates are located on a compact form, because an anchor can itself be
    split, but nothing else uses it. Recognition and extent happen in the
    original text inside the candidate, so no amount of unrelated content
    elsewhere can be joined to a value. Erasing a minified JSON document, a URL
    and a CSV row was that joining.
    """
    out: list[tuple[int, int, str]] = []
    for m in _PEM_RE.finditer(text):
        out.append((m.start(), m.end(), "Private key header"))

    compact: list[str] = []
    cmap: list[int] = []
    for i, ch in enumerate(text):
        if ch.isascii() and ch.isalnum():
            compact.append(ch)
            cmap.append(i)
    packed = "".join(compact)

    for g in _GRAMMARS:
        for literal in g.anchor:
            pos = packed.find(literal)
            while pos != -1:
                start = cmap[pos]
                after = _walk_anchor(text, start, literal, g)
                if after is None:
                    pos = packed.find(literal, pos + 1)
                    continue
                # The grammar's own separator must actually be present. This is
                # what rejects an anchor that exists only because separators
                # were removed: `through_put_measurement` offers `ghp` in the
                # compact form, but the original has a body character after it.
                body_start = after
                if g.sep_after:
                    seen = 0
                    while (
                        body_start < len(text)
                        and seen <= _MAX_GAP
                        and not _is_alnum(text[body_start])
                    ):
                        body_start += 1
                        seen += 1
                    if seen == 0:
                        pos = packed.find(literal, pos + 1)
                        continue
                span = _resolve(text, start, body_start, g)
                if span is not None:
                    lo, hi = span
                    # An anchor beginning mid-token is the shape that joining
                    # invents, so those must look random. Applied only to the
                    # anchors ordinary text produces on its own; the rest are
                    # already protected by the separator rule above, and
                    # applying it to them lost AKIA keys, which are not random
                    # enough to clear the bar.
                    ok = True
                    if g.randomness == "always":
                        ok = _looks_random(_NON_ALNUM.sub("", text[lo:hi]))
                    elif g.randomness == "mid_token" and lo > 0 and _is_body(text[lo - 1], g):
                        ok = _looks_random(_NON_ALNUM.sub("", text[lo:hi]))
                    if ok:
                        out.append((lo, hi, g.label))
                pos = packed.find(literal, pos + 1)
    return out


def scan_secret_spans(text: str) -> tuple[list[tuple[int, int]], list[str]]:
    """Locate credentials in ``text``, returning spans into the ORIGINAL text.

    Shared with L13 so the model-boundary denier and the egress blocker cannot
    disagree about what a credential is. Both now read _findings, which is the
    point: when they were separate implementations, a value split with
    punctuation was located by this one and missed by the other, so L3 allowed
    outbound content holding a key.

    Extent, settled after several wrong answers worth recording so they are not
    retried. The shortest accepted prefix left 25 recoverable characters of a
    live key at 63 of 145 split positions. Extending through following tokens
    that were alphanumeric and at least ten characters failed in both
    directions at once, keeping a 27 character Slack tail, whose grammar admits
    ``-`` so the fragment was not alphanumeric, while deleting ``documentation
    configuration authentication`` out of prose. Redacting to the end of the
    logical line was safe but blunt, and on globally normalized forms it erased
    minified JSON, a URL and a CSV row outright.

    What survives is fragment-scoped and local. A value is a run of body
    characters, possibly broken by inserted separators; fragments join across a
    gap of at most two, which is what a split looks like and what structure
    does not, since ``","`` between JSON values is three. Fragments are taken
    while the grammar is unsatisfied, then exactly one more. The cost of an
    extent the text does not determine is one following fragment rather than
    the remainder of a line.

    An entropy hit is deliberately not treated as delimiting. It fires on one
    fragment of a split credential, and letting it settle the extent is how
    half a key stayed in the text.
    """
    spans: list[tuple[int, int]] = [(lo, hi) for lo, hi, _ in _findings(text)]
    spans.extend(_entropy_spans(text))

    merged_spans: list[tuple[int, int]] = []
    for lo, hi in sorted(set(spans)):
        if merged_spans and lo <= merged_spans[-1][1]:
            prev_lo, prev_hi = merged_spans[-1]
            merged_spans[-1] = (prev_lo, max(prev_hi, hi))
        else:
            merged_spans.append((lo, hi))

    masked = text
    for lo, hi in sorted(merged_spans, reverse=True):
        masked = masked[:lo] + " " * (hi - lo) + masked[hi:]
    return merged_spans, _scan_secrets(masked)


def _entropy_spans(text: str) -> list[tuple[int, int]]:
    """High-entropy runs, on the raw text only.

    Orthogonal to the grammars and unchanged by the restructure. Raw text only:
    with separators removed, unrelated lines join into one high-entropy run and
    mapping that back produced spans covering a whole document.
    """
    out: list[tuple[int, int]] = []
    for m in re.finditer(r"[A-Za-z0-9+/\-_]{20,}", text):
        token = m.group()
        entropy = _shannon_entropy(token)
        threshold = min(_ENTROPY_THRESHOLD, math.log2(len(token)) - _ENTROPY_LENGTH_MARGIN)
        if entropy >= threshold:
            out.append((m.start(), m.end()))
            continue
        if len(token) % 2 == 0 and _HEX_RE.fullmatch(token):
            try:
                if _shannon_entropy_bytes(bytes.fromhex(token)) >= _ENTROPY_THRESHOLD:
                    out.append((m.start(), m.end()))
            except ValueError:
                pass
    return out


def _scan_secrets(text: str) -> list[str]:
    """Report which credential classes appear in ``text``.

    Grammar findings come from _findings, the same engine the span scanner
    reads. When this had its own implementation the two disagreed: a value
    split with a comma was located by the span scanner and missed here, so
    outbound content carrying a key was allowed through. Invisible characters
    are stripped first because that obfuscation is orthogonal to everything
    below and cheap to undo.
    """
    found: list[str] = []
    stripped = strip_invisibles(text)
    for _lo, _hi, label in _findings(stripped):
        if label not in found:
            found.append(label)
    ws_removed = _WHITESPACE_RE.sub("", stripped)

    # High-entropy token detection: look for long hex/base64-like tokens.
    # Scan the invisible-stripped form (all tokens) AND the whitespace-removed
    # form so neither a zero-width char nor an inserted space can split a
    # random (unprefixed) token below the length gate. On the whitespace-merged
    # form, only consider tokens that contain a digit: this is the signature of
    # a machine token/secret, and it prevents a natural-language sentence
    # (whose words merge into one long alphabetic run) from being flagged.
    entropy_forms: list[tuple[str, bool]] = [(stripped, False)]
    if ws_removed != stripped:
        entropy_forms.append((ws_removed, True))
    seen_tokens: set[str] = set()
    for form, merged in entropy_forms:
        for token in re.findall(r"[A-Za-z0-9+/\-_]{20,}", form):
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            if len(token) < _ENTROPY_MIN_LENGTH:
                continue
            if merged and not any(c.isdigit() for c in token):
                continue
            entropy = _shannon_entropy(token)
            # Length-aware threshold: never require more entropy than the
            # length can produce. Caps at _ENTROPY_THRESHOLD for long tokens
            # (unchanged) but closes the 20-22 char dead zone for short ones.
            effective_threshold = min(
                _ENTROPY_THRESHOLD, math.log2(len(token)) - _ENTROPY_LENGTH_MARGIN
            )
            if entropy >= effective_threshold:
                label = f"High-entropy token ({entropy:.1f} bits)"
                if label not in found:
                    found.append(label)
                continue
            # Hex decode-then-scan: pure hex tokens (0-9, a-f) have max
            # entropy of 4.0 bits/char, always below the 4.5 threshold.
            # Decode to bytes and re-check entropy on the decoded form.
            if len(token) % 2 == 0 and _HEX_RE.fullmatch(token):
                try:
                    decoded = bytes.fromhex(token)
                    byte_entropy = _shannon_entropy_bytes(decoded)
                    if byte_entropy >= _ENTROPY_THRESHOLD:
                        label = f"High-entropy token (hex-decoded {byte_entropy:.1f} bits)"
                        if label not in found:
                            found.append(label)
                except ValueError:
                    pass
    return found


# ---------------------------------------------------------------------------
# OutboundDLP
# ---------------------------------------------------------------------------


class OutboundDLP:
    """Outbound content exfiltration detector.

    Before any outbound action executes, scans content against recently
    ingested untrusted content. Checks:
    - Secret patterns (always, even with quoting directive)
    - Untrusted-echo signal (outbound vs untrusted buffer, LCS >= 14).
      This is a SIGNAL, not a BLOCK. When it fires, it lowers the
      sensitive-leak threshold and sets echo_detected for downstream
      checks (provenance). It does not block on its own because
      natural English text from the same distribution shares 14+ char
      substrings at ~26% rate.
    - Sensitive-leak check (outbound vs sensitive buffer, LCS >= 12,
      or lowered when echo detected). This IS a BLOCK trigger.
    - N-gram overlap (>= 40% 5-gram overlap)
    - Separator-stripped variant (catches inserted spaces/hyphens/underscores)
    """

    def __init__(self, buffer_max: int = 50) -> None:
        self._buffer: deque[str] = deque(maxlen=buffer_max)
        self._sensitive_buffer: deque[str] = deque(maxlen=buffer_max)

    def ingest_untrusted(self, content: str) -> None:
        """Normalize and buffer untrusted content for later DLP checks."""
        normalized = normalize_for_overlap(content)[:MAX_OVERLAP_CHARS]
        if normalized:
            self._buffer.append(normalized)

    def ingest_sensitive(self, content: str) -> None:
        """Normalize and buffer sensitive content for contaminated-context checks."""
        normalized = normalize_for_overlap(content)[:MAX_OVERLAP_CHARS]
        if normalized:
            self._sensitive_buffer.append(normalized)

    def check(
        self,
        content: str,
        ctx: SecurityContext,
        has_quoting_directive: bool = False,
        *,
        contaminated: bool = False,
    ) -> OutboundResult:
        """Check outbound content for exfiltration indicators.

        Decision flow:
        1. Secret scan (always, even with quoting): BLOCK if match.
        2. Untrusted-echo check (outbound vs untrusted buffer): SIGNAL only.
           Records echo_detected and echo_lcs on the result but does NOT
           block on its own.
        3. Sensitive-leak check (outbound vs sensitive buffer): BLOCK if
           match at base threshold. This is the core security property.
        4. If nothing blocks: ALLOW with echo_detected metadata for
           downstream layers (provenance, audit).

        Args:
            content: Outbound content to check.
            ctx: Security context.
            has_quoting_directive: True if user explicitly directed quoting.
            contaminated: True if untrusted content has entered the session.

        Returns:
            OutboundResult with allowed=True if content passes DLP.
        """
        echo_threshold = int(getattr(ctx.policy, "dlp_verbatim_lcs_min", 14))
        ngram_threshold = float(getattr(ctx.policy, "dlp_ngram_overlap_min", 0.40))
        sensitive_lcs = int(getattr(ctx.policy, "dlp_sensitive_lcs_min", 12))

        # Step 1: Secret scan (always runs, even with quoting directive)
        secrets = _scan_secrets(content)
        if secrets:
            return OutboundResult(
                allowed=False,
                reason=f"Secret pattern detected: {', '.join(secrets)}",
                secrets_found=secrets,
            )

        # With quoting directive, skip overlap checks
        if has_quoting_directive:
            return OutboundResult(allowed=True, reason="clean (quoting)")

        # Cap the outbound content compared for overlap so a very large payload
        # cannot drive the O(m*n) LCS routine unbounded.
        content = content[:MAX_OVERLAP_CHARS]
        normalized_content = normalize_for_overlap(content)

        # Build deobfuscated variants for overlap checks.
        # Each entry: (normalized_text, strip_separators, label)
        #   strip_separators=True means the buffer must also be
        #   separator-stripped before comparison.
        variants: list[tuple[str, bool, str]] = [
            (normalized_content, False, ""),
        ]
        reversed_norm = normalize_for_overlap(deobfuscate_reversed(content))
        if reversed_norm != normalized_content:
            variants.append((reversed_norm, False, " (deobfuscated)"))
        spelled_norm = normalize_for_overlap(deobfuscate_spelled(content))
        if spelled_norm != normalized_content:
            variants.append((spelled_norm, False, " (deobfuscated)"))
        separated_norm = normalize_for_overlap(deobfuscate_separated(content))
        if separated_norm != normalized_content:
            variants.append((separated_norm, True, " (separator-stripped)"))

        # Step 2: Untrusted-echo check (SIGNAL, not BLOCK).
        # Compute the maximum LCS and n-gram overlap across all
        # untrusted buffer entries. This fires on natural English
        # boilerplate (~26% of random Enron pairs at LCS >= 14), so
        # it must not block on its own.
        echo_max_lcs = 0
        echo_max_ngram = 0.0
        echo_detected = False
        for variant, strip_seps, _label in variants:
            if echo_detected:
                break
            for buffered in self._buffer:
                buf = deobfuscate_separated(buffered) if strip_seps else buffered
                ngram = compute_ngram_overlap(variant, buf, n=5)
                if ngram > echo_max_ngram:
                    echo_max_ngram = ngram
                # Only run the LCS when a shared 5-gram exists. A common
                # substring of length >= the echo threshold necessarily shares
                # 5-grams, so ngram == 0 implies LCS < 5 and it can be skipped.
                if ngram > 0.0:
                    lcs_len = compute_lcs_length(variant, buf)
                    if lcs_len > echo_max_lcs:
                        echo_max_lcs = lcs_len
                # Echo is a boolean signal; once tripped, further scanning only
                # refines a metadata value, so stop (bounds work on large input).
                if echo_max_lcs >= echo_threshold or echo_max_ngram >= ngram_threshold:
                    echo_detected = True
                    break

        # Step 3: Sensitive-leak check (BLOCK trigger).
        # Outbound vs sensitive buffer at base threshold. Echo does not
        # widen this check; it is pure metadata for downstream layers.
        if contaminated and not has_quoting_directive:
            for variant, strip_seps, label in variants:
                for buffered in self._sensitive_buffer:
                    buf = deobfuscate_separated(buffered) if strip_seps else buffered
                    overlap = compute_ngram_overlap(variant, buf, n=5)
                    # Gate the O(m*n) LCS behind the cheap n-gram check: a
                    # verbatim overlap >= sensitive_lcs (>= 12) always shares
                    # 5-grams, so ngram == 0 implies no blocking LCS.
                    lcs_len = compute_lcs_length(variant, buf) if overlap > 0.0 else 0
                    if lcs_len >= sensitive_lcs:
                        result = OutboundResult(
                            allowed=False,
                            reason=f"Verbatim overlap ({lcs_len} chars){label} with "
                            f"ingested sensitive content",
                            overlap_pct=0.0,
                            contamination_triggered=True,
                            echo_detected=echo_detected,
                            echo_lcs=echo_max_lcs,
                        )
                        if ctx.policy.contaminated_action == "confirm":
                            result.reason = f"Confirmation required: {result.reason}"
                        return result
                    if overlap >= ngram_threshold:
                        result = OutboundResult(
                            allowed=False,
                            reason=f"N-gram overlap ({overlap:.0%}){label} with "
                            f"ingested sensitive content",
                            overlap_pct=overlap,
                            contamination_triggered=True,
                            echo_detected=echo_detected,
                            echo_lcs=echo_max_lcs,
                        )
                        if ctx.policy.contaminated_action == "confirm":
                            result.reason = f"Confirmation required: {result.reason}"
                        return result

        return OutboundResult(
            allowed=True,
            reason="clean" if not echo_detected else "clean (echo signal only)",
            echo_detected=echo_detected,
            echo_lcs=echo_max_lcs,
        )
