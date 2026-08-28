"""Part 7: Outbound DLP (Data Loss Prevention).

Scans outbound content against recently ingested untrusted content
to detect exfiltration attempts. Checks verbatim overlap, n-gram
overlap, and secret patterns.

Credential scanning is two passes over two different questions, and keeping
them apart is the organising idea of everything below.

``_exact_findings`` is ATTRIBUTION: given that a credential is here, which
characters can be replaced faithfully? It is bounded everywhere -- a ceiling on
how wide an inserted gap may be, a ceiling on how far an anchor may itself be
broken, a fragment walk that stops at the first structural break -- because a
span that reaches too far corrupts the document it was meant to protect. It
once deleted the closing tag of one XML element, a whole second element and the
opening tag of a third.

``_normalized_labels`` is RECOGNITION: is a credential here at all? It is
bounded nowhere. Every bound in the paragraph above is a number an attacker can
exceed on purpose, and each of them was: 65 separators, 33 shell line
continuations and adjacent empty shell quotes each made a whole credential
family disappear while ``/bin/sh`` still reconstructed the key. So this pass
compacts the entire document and runs the grammars over what is left, and what
no span accounts for is reported with no span at all, for the caller to refuse
or replace.

The division is what makes the bounds safe. Attribution may stop early; the
value does not thereby vanish, it moves from a span to a label. Conflating the
two is what produced both failures at once: answering them together reached
across a record to build one span, and answering only recognition left 481 of
6,290 split positions with nothing reported.
"""

from __future__ import annotations

import math
import re
import unicodedata
from array import array
from bisect import bisect_left
from collections import deque
from functools import cache
from typing import NamedTuple

from vordur.security.normalization import (
    _BIDI_RE,
    _CONFUSABLE_TABLE,
    _INVISIBLE_RE,
    _TAG_CHAR_RE,
    MAX_OVERLAP_SCAN_CHARS,
    deobfuscate_reversed,
    deobfuscate_separated,
    deobfuscate_spelled,
    normalize_for_overlap,
    overlap_scan,
    overlap_windows,
    strip_invisibles,
)
from vordur.security.types import OutboundResult, SecurityContext

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
    # Stripe's three live prefixes sit above ``sk`` for the same reason
    # ``skproj`` does: a more specific anchor should name the value first. The
    # general one still matches, and both labels are reported, which is what
    # ``sk-proj-`` has always done.
    _Grammar("Stripe secret key", ("sklive",), True, "", False, 24, 120, "never"),
    _Grammar("Stripe restricted key", ("rklive",), True, "", False, 24, 120, "never"),
    _Grammar("Stripe webhook secret", ("whsec",), True, "", False, 24, 120, "never"),
    _Grammar("OpenAI API key", ("sk",), True, "", False, 20, 80, "mid_token"),
    _Grammar("AWS access key", ("AKIA",), False, "", True, 16, 16, "never"),
    _Grammar("Google OAuth token", ("ya29",), True, "-_", False, 20, 600, "never"),
    _Grammar("GitHub OAuth token", ("gho",), True, "", False, 36, 60, "mid_token"),
    _Grammar("GitHub personal access token", ("ghp",), True, "", False, 36, 60, "mid_token"),
    _Grammar("GitHub app token", ("ghs",), True, "", False, 36, 60, "mid_token"),
    _Grammar("GitHub refresh token", ("ghr",), True, "", False, 36, 60, "mid_token"),
    _Grammar("GitHub user-to-server token", ("ghu",), True, "", False, 36, 60, "mid_token"),
    # The fine-grained token is a different shape from the four above it: an
    # underscore inside the body separates its two halves, so ``_`` is body
    # here and a separator there. ``min_body`` is well under the 82 characters
    # GitHub issues, deliberately. A minimum set at the exact issued length is
    # what leaves a grammar no window to sweep when the value arrives split,
    # which is why 25 of 27 remaining far-split leaks were classic GitHub
    # tokens whose body is exactly their minimum.
    _Grammar("GitHub fine-grained token", ("githubpat",), True, "_", False, 40, 120, "never"),
    _Grammar("GitLab personal access token", ("glpat",), True, "-_", False, 20, 60, "never"),
    # ``npm`` needs randomness everywhere for the reason ``hf`` does, and more
    # so: ``npm_config_registry``, ``npm_package_version`` and
    # ``npm_lifecycle_event`` are environment variables every build script
    # writes, and each begins at a token boundary AND supplies the separator,
    # so mid-token randomness is never asked. Measured: ``mid_token`` takes the
    # silent rate to 0 of 500 and labels 3 of 7 such identifiers plus enum.py;
    # ``always`` labels none of them. The recall it gives up is small, because
    # the entropy scan already found all but 12 of 500 on its own. What this
    # entry buys is the name.
    _Grammar("npm access token", ("npm",), True, "", False, 30, 60, "always"),
    # ``hf`` is two characters and compaction manufactures it constantly:
    # ``with_files`` compacts to ``withfiles``. The separator rule rejects that
    # one, but ``hf_hub_cache_directory`` supplies the separator and a token
    # boundary both, so mid-token randomness is no guard here. It has to look
    # random wherever it appears, exactly like Bearer.
    _Grammar("Hugging Face token", ("hf",), True, "", False, 30, 60, "always"),
    _Grammar(
        "Slack token",
        ("xoxb", "xoxa", "xoxp", "xoxr", "xoxs"),
        True,
        "-",
        False,
        10,
        100,
        "never",
    ),
    _Grammar("Bearer/JWT token", ("Bearer",), True, "-_.", False, 30, 800, "always"),
]


_PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")

#: A run that is one stretch of an alphabet written straight through. Reported,
#: because the RFC 4648 Base32 alphabet in order is also a valid TOTP shared
#: secret and nothing can tell the two apart. Named separately from a generic
#: high-entropy finding because the two mean different things to a caller that
#: acts: a located credential can be replaced, whereas a run far more often a
#: character table than a secret must not be. ``is_ambiguous_finding`` below is
#: how a caller asks, rather than by matching this string.
_AMBIGUOUS_ALPHABET = "Alphabet run (ambiguous: a character table or a secret)"


def is_ambiguous_finding(label: str) -> bool:
    """Is this finding too ambiguous to justify rewriting the text it came from?

    A caller that only reports findings can ignore this. A caller that DESTROYS
    content on one cannot: the vault's residue sweep replaces a whole line, and
    doing that for an alphabet chart corrupts documents silently.
    """
    return label == _AMBIGUOUS_ALPHABET


#: The one credential here whose evidence is its key rather than its value.
#:
#: npm's legacy registry token is 32 to 40 hex characters and carries no
#: prefix, so every grammar above is blind to it and so is the entropy scan:
#: 32 hex characters decode to 16 bytes, 16 distinct byte values cap Shannon
#: entropy at exactly log2(16) = 4.0 bits per byte, and the decode-then-scan
#: rule asks for 4.5. That rule therefore cannot fire below 46 hex characters
#: no matter how random the value is, which is why 500 of 500 at 32, 36 and 40
#: went out silent and the vault passed every one.
#:
#: Lowering that bar is not the fix. A length-aware bar on the decoded form
#: admits 16 random bytes, and it admits every git object id, MD5 digest and
#: unhyphenated UUID with it, which on the host path is a refused document.
#:
#: So the key is the evidence instead. ``_authToken`` is npm's own config key,
#: it does not appear in prose, and nothing has to be assumed about the shape
#: of what follows it. The span covers the VALUE only, so the line keeps its
#: key and the file still parses. ``$`` and ``{`` are outside the value class
#: on purpose: ``_authToken=${NPM_TOKEN}`` is the documented way to write this
#: safely, and refusing it would refuse the correct practice.
_NPM_AUTH_RE = re.compile(
    r"(?<![A-Za-z0-9])_authToken\s*=\s*([A-Za-z0-9+/=._~-]{20,})",
    re.IGNORECASE,
)

#: How wide a run of non-body characters may be and still be read as an
#: inserted split rather than a boundary between two things.
#:
#: The size is the weaker half of the test; _joinable_gap's structural rule is
#: what protects a document's shape, and measurement says so: at 10, 20 and 40
#: the standard library figure is identical and only the leak changes. Sixty
#: four is where every gap probed closes. It cannot simply be removed, though;
#: without any ceiling a credential and an unrelated token 400 characters
#: apart join into one 459 character finding.
#:
#: This bounds attribution and nothing else. Sixty five separators step over
#: it, and when they do the span stops here and recognition, which has no
#: ceiling, reports the value without one. That is why a ceiling is allowed to
#: exist at all: no threshold an attacker can exceed decides whether a
#: credential is present, only how much of it can be replaced faithfully.
_MAX_GAP = 64

#: How far a split anchor may itself be broken, e.g. ``s,k-abc``. Attribution
#: only, again: recognition reads the compact form and needs no such bound.
_MAX_ANCHOR_GAP = 2

_ENTROPY_THRESHOLD = 4.5
#: Below this length entropy separates nothing, so no question in this module
#: is asked of a shorter run. It is the floor for the standalone scan below, it
#: is the floor for the window sweep a grammar's body must clear, and it is the
#: shortest residue recognition will speak up about. Slack's ten character
#: minimum asked the randomness question of ten characters, where a bar of 3.02
#: bits is cleared by any run with nine distinct characters in it, and a
#: comment reading ``x.o = x.s + x.d`` was reported as a Slack token.
_ENTROPY_MIN_LENGTH = 20
# A string of length L has a maximum possible Shannon entropy of log2(L).
# For L in [20, 22] that ceiling (4.32 - 4.46 bits) is below _ENTROPY_THRESHOLD,
# so a 20-22 char random token could NEVER trip the absolute threshold. For
# such short tokens, flag when the entropy is within this margin of the
# theoretical maximum for the length (i.e. near-maximal randomness) instead.
_ENTROPY_LENGTH_MARGIN = 0.30

_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")

_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")

_HEX_RE = re.compile(r"[0-9a-fA-F]+")

# Whitespace run, used to build a whitespace-removed form for secret scanning
_WHITESPACE_RE = re.compile(r"\s+")


@cache
def _ascii_equivalent(ch: str) -> str:
    """The single ASCII character this one folds to, or itself.

    Compatibility forms are how a credential is written so that no scanner
    here sees it while a model still reads it: ``ＡＫＩＡ`` is four characters
    none of which are ASCII, and NFKC turns every one of them back. Of 700
    credentials rewritten that way, 399 passed both scanners silently and the
    vault let one through untouched, the longest recoverable run being 105
    characters.

    Punctuation counts, not just letters and digits. A Google token written
    full-width keeps its ``．`` and its ``－``, and a body class that has never
    heard of those breaks at every one of them; folding only the alphanumerics
    left 39 of 700 still silent for exactly that reason.

    One character in, one character out, and only when the result is a single
    ASCII character. That is what keeps every span mapping back to the
    original text unchanged; a general NFKC pass does not, because it expands
    ligatures and would shift every index after one.
    """
    folded = unicodedata.normalize("NFKC", ch)
    if len(folded) == 1 and folded.isascii():
        return folded
    # Compatibility forms are not the only way to write a Latin letter without
    # using one. Greek capital alpha and Cyrillic capital A look exactly like
    # `A` and NFKC leaves both alone, so folding compatibility forms closed one
    # door and left the one beside it open: 697 of 1,000 AWS keys whose first
    # character was swapped that way passed both scanners silently and the
    # vault returned them unchanged.
    #
    # The confusable table is shared with strip_invisibles, and it maps to
    # lowercase, which is why that path could not see the anchor either: an
    # AWS body is upper-only, so `aKIA` satisfies nothing. Case is taken from
    # the character actually written.
    confused = _CONFUSABLE_TABLE.get(ord(ch))
    if confused and len(confused) == 1 and confused.isascii() and confused.isalpha():
        return confused.upper() if ch.isupper() else confused
    return ch


def _fold_ascii(text: str) -> str:
    """Fold compatibility forms to ASCII without moving a single index."""
    if text.isascii():
        return text
    return "".join(_ascii_equivalent(ch) for ch in text)


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


def _invisible(ch: str) -> bool:
    """A character with no width, which cannot be part of anything's meaning.

    strip_invisibles removes these before the egress scan, and the span scanner
    cannot, because removing them moves every index after each one. So they are
    read as transparent instead: a body run passes through them and the span
    covers them, which is right, since they sit INSIDE the value an attacker
    put them in.
    """
    return bool(_INVISIBLE_RE.match(ch) or _TAG_CHAR_RE.match(ch) or _BIDI_RE.match(ch))


def _is_body(ch: str, g: _Grammar) -> bool:
    """Is this character part of this grammar's body?"""
    if _invisible(ch):
        # Transparent, not terminal. A zero-width joiner driven into a token
        # broke the body run there, so the span stopped at it and up to 29
        # visible characters of the value were left in the text with nothing
        # reported, 239 times in 700.
        return True
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
            while i < len(text) and gap < _MAX_ANCHOR_GAP and not _is_alnum(text[i]):
                i += 1
                gap += 1
        if i >= len(text) or text[i] != want:
            return None
        i += 1
    return i


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

    The ceiling is a bound on ATTRIBUTION only, and that is the whole reason it
    is allowed to exist. Sixty five separators walk straight over it, and when
    they do this returns False, the span stops, and recognition -- which has no
    ceiling at all -- reports the value without one. A threshold an attacker
    can simply exceed decides how much can be replaced here, never whether a
    credential is present.
    """
    if len(gap) > _MAX_GAP:
        return False
    # A quote or a bracket is structural unless it is the whole gap. Where a
    # value ends, the character closing it arrives with company: ``","``
    # between minified JSON fields, ``", `` before the next key, ``") ``
    # closing a call, ``</`` opening the tag that ends an element. Driven INTO
    # a value it arrives alone. Refusing on any quote at all made ``"`` the one
    # separator that still smuggled 32 characters out; allowing up to two
    # swallowed the ``")`` that closes a function call. Markup was added to the
    # same set for the same reason and against a measured failure: with only
    # quotes here, ``</`` was an ordinary two character gap, one fragment past
    # a split value in ``<token>`` was ``token`` inside its own closing tag,
    # and the record came out as ``><note>`` with the tag eaten.
    if not any(c in "\"'`<>{}[]" for c in gap):
        return True
    return len(gap) == 1


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
    """How far a candidate reaches, in original coordinates, or None.

    Fragments are taken while the grammar is not yet satisfied, which is a
    split value being reassembled, and then exactly one more, which is a value
    split after its minimum was already met. Both are needed and neither
    subsumes the other: without the first a value broken into five pieces keeps
    its tail, without the second a key split just past its minimum keeps
    everything after the split. The second costs a following fragment when the
    value was in fact complete, which is the price of an extent nothing in the
    text determines, and it is paid one fragment at a time rather than to the
    end of the line.

    Two further rules follow, for the shapes those two do not reach: a value
    wrapped over several lines, and one broken into four or more pieces on a
    single line. Both were removed once as the cause of a span that crossed
    three XML elements, and both are restored because that was the wrong
    culprit. Neither can reach further than _fragments walks, and what let that
    walk cross a record was a gap of ``</`` counting as an inserted split.
    Naming markup structural fixes it at the cause; removing the rules that
    consumed the walk only hid it, and cost a wrapped credential 19 characters.
    """
    frags = _fragments(text, body_start, g)
    if not frags:
        return None
    taken = 0
    used = 0
    for idx, (lo, hi) in enumerate(frags):
        taken += hi - lo
        used = idx
        if taken >= g.min_body:
            break
    if taken < g.min_body:
        return None
    if used + 1 < len(frags):
        used += 1
    # A value wrapped over several lines leaves each continuation alone on its
    # own line, and a long one clears the minimum on its first fragment, so
    # neither rule above reaches the tail: a 47 character Slack token broken
    # over five lines kept 19 of them, and 19 is under the length at which
    # recognition will speak up about what is left, so nothing was reported
    # either. Keep taking fragments that are the entire content of their line.
    # A prose line has other words on it and stops this at once.
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
    # A long value broken into pieces on ONE line once needed a third rule
    # here, taking fragments through the last that scanned as credential
    # material. It is gone: the entropy scan follows its own runs through the
    # fragments that continue them now, which covers the same shape from the
    # other side, and measurement says this rule closes nothing the walk does
    # not and costs one multi-piece case of its own.
    return start, frags[used][1]


def _admissible(text: str, start: int, lo: int, hi: int, g: _Grammar) -> bool:
    """Is a match beginning at ``start`` a credential, or part of a name?

    Two different failures meet here and they pull opposite ways.

    A value written INSIDE an identifier is not a credential, and rewriting it
    corrupts source and documentation on its way to the model:
    ``slack_xoxb_token_prefix_documentation`` and
    ``display_ya29_token_configuration`` both satisfy the separator rule, and
    both were being rewritten mid-identifier. A ``_`` or ``-`` in front of the
    anchor is what says so, and it says so for every grammar.

    A value with a character driven in FRONT of it to evade exactly that test
    is still a credential, and ``_sk-7LeXSyYV...`` is both shapes at once. So
    nothing is refused on the preceding character alone: it selects which
    question is asked. Before a ``_`` or ``-`` the value must look random,
    which the identifiers above do not and a real key does. Before an
    alphanumeric the grammar's own ``randomness`` field decides, because it
    records which anchors ordinary text writes unaided; asking it of the rest
    lost ``XAKIA,IOSFODNN7EXAMPLE``, whose body clears no bar.
    """
    if g.randomness == "always":
        return _looks_random(_NON_ALNUM.sub("", text[lo:hi]))
    if start == 0:
        return True
    prev = text[start - 1]
    if not _is_alnum(prev) and prev not in "_-":
        return True
    if prev in "_-" or g.randomness != "never":
        return _looks_random(_NON_ALNUM.sub("", text[lo:hi]))
    return True


def _packed(text: str) -> tuple[str, array[int]]:
    """The document with every non-alphanumeric removed, and where each came from.

    Both halves are built by the regular expression engine rather than a loop
    over characters. This runs four times per scan, twice on the document and
    twice on the masked copy, and as a Python loop it was nine tenths of the
    cost of scanning the standard library.
    """
    # The index map is an array of machine integers, not a list of Python
    # ones. It has an entry per alphanumeric character and there are several
    # packed forms alive at once, and as a list a one megabyte document cost
    # 82 megabytes of traced allocation.
    cmap = array("i")
    for m in _ALNUM_RUN.finditer(text):
        cmap.extend(range(m.start(), m.end()))
    return _NON_ALNUM.sub("", text), cmap


def _window_random(s: str, low: int, high: int) -> bool:
    """Does any credential-sized prefix of ``s`` clear the randomness bar?

    One window is not enough. A credential is usually longer than its grammar's
    minimum, and at that minimum the length allowance sits within a tenth of a
    bit of what a random base62 run actually scores, so asking only there
    decides half of them by rounding: it left 545 of 2,340 generated split
    values unreported. Asking every length from ``low`` to twice it asks
    whether the value is random anywhere a credential of this grammar could
    end, and prose is not random at any of those lengths.

    The upper end is not decoration. The bar is ``log2(n) - margin`` capped at
    ``_ENTROPY_THRESHOLD``, so past about thirty characters it stops rising
    with the window while ordinary text keeps accumulating distinct characters
    and eventually clears a flat 4.5 bits. Sweeping without that limit read the
    constants after a real credential in ``__future__.py`` as more of it, and
    reported ten of 153 standard library files as carrying one.

    Twice is where the curve turns. At one and a half a random base62 body is
    still being judged in the band where the bar and its own expected entropy
    differ by a hundredth of a bit, and 83 of 3,200 values split beyond
    attribution's reach went unreported for it. Past twice, five more close and
    six more benign files open.

    Entropy is accumulated as the window grows, so the sweep costs one pass
    rather than one pass per length.
    """
    if low < 1 or low > len(s) or high < low:
        return False
    counts: dict[str, int] = {}
    weight = 0.0  # sum of c*log2(c) over the counts seen so far
    for size, ch in enumerate(s[:high], 1):
        seen = counts.get(ch, 0)
        if seen:
            weight -= seen * math.log2(seen)
        counts[ch] = seen + 1
        weight += (seen + 1) * math.log2(seen + 1)
        if size < low:
            continue
        cap = math.log2(size)
        if cap - weight / size >= min(_ENTROPY_THRESHOLD, cap - _ENTROPY_LENGTH_MARGIN):
            return True
    return False


def _credential_window() -> tuple[int, int]:
    """The window lengths a body is asked to look random over.

    From ``_ENTROPY_MIN_LENGTH``, below which entropy separates nothing, to
    twice it, past which the bar has gone flat at ``_ENTROPY_THRESHOLD`` while
    ordinary text keeps accumulating distinct characters and catches up. Both
    ends were measured against values split beyond attribution's reach and
    against real credentials written into real source files, and both bite:
    a ceiling of thirty leaves 83 of 3,200 split values unreported, and one of
    sixty reads the constants following a key in ``__future__.py`` as more of
    the key.

    No grammar term. The ceiling was briefly twice each grammar's own minimum,
    which is the same thing for most of them and 72 for GitHub, and the extra
    width bought nothing measurable while costing benign files.
    """
    return _ENTROPY_MIN_LENGTH, 2 * _ENTROPY_MIN_LENGTH


def _exact_findings(
    text: str, pack: tuple[str, list[int]] | None = None
) -> list[tuple[int, int, str]]:
    """Credentials whose exact characters are known, as spans.

    This is attribution, and it answers only the second question: given that a
    credential is here, which characters can safely be replaced? Splitting that
    from recognition is the correction this file needed. Answering both at once
    produced four interacting phases that reached across whatever lay between
    fragments, which deleted the closing tag of one XML element, an entire
    second element and the opening tag of a third, because a request id further
    down the record cleared the entropy threshold.

    Candidates are located on the compact form, because an anchor can itself be
    split, but nothing else uses it: the anchor is re-walked, the separator
    checked and the extent settled in the ORIGINAL text, so no amount of
    unrelated content elsewhere can be joined to a value. Everything here is
    bounded, and it is allowed to be, because recognition is not: a value
    pushed past these bounds loses its span and is reported without one.
    """
    out: list[tuple[int, int, str]] = []
    for m in _PEM_RE.finditer(text):
        out.append((m.start(), m.end(), "Private key header"))
    for m in _NPM_AUTH_RE.finditer(text):
        out.append((m.start(1), m.end(1), "npm registry credential"))

    joined, cmap = pack if pack is not None else _packed(text)
    for g in _GRAMMARS:
        for literal in g.anchor:
            pos = joined.find(literal)
            while pos != -1:
                nxt = joined.find(literal, pos + 1)
                start = cmap[pos]
                after = _walk_anchor(text, start, literal, g)
                if after is None:
                    pos = nxt
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
                        pos = nxt
                        continue
                span = _resolve(text, start, body_start, g)
                if span is not None and _admissible(text, start, span[0], span[1], g):
                    out.append((span[0], span[1], g.label))
                pos = nxt
    return out


def _normalized_labels(
    text: str,
    covered: list[tuple[int, int]],
    pack: tuple[str, array[int]] | None = None,
) -> list[str]:
    """Credentials that exist once every separator is removed, without spans.

    This is recognition, and it deliberately has no locality bound of any kind.
    A ceiling on how far apart two fragments may sit is a threshold an attacker
    simply exceeds: 65 commas, or 33 shell line continuations, between five
    character chunks made every credential family disappear while ``/bin/sh``
    still reconstructed the key exactly. Adjacent empty shell quotes did the
    same, because quote counting cannot tell a split from a boundary either.

    So nothing here tries to. The whole document is compacted and the grammars
    are run over it; what no span already accounts for is reported as a label
    with no span, and the callers refuse or replace on that basis.

    What keeps ordinary prose out is not a bound but the two structural rules
    the exact path already applies, asked of the ORIGINAL text where the
    information still exists:

    The grammar's own separator must follow the anchor. Compaction is what
    manufactures anchors -- ``%s" % (key`` compacts to ``sskey`` and offers
    ``sk`` -- and a manufactured one has a body character after it, as does
    ``skip_bytes``. Without this rule 37 of 153 standard library files were
    reported as carrying an unlocatable credential, and each of those is a
    refused document.

    The anchor must begin at a token boundary, or else its body must look
    random. Compacting joins every word, so ``sk`` followed by twenty letters
    occurs constantly; the anchors ``randomness`` marks are the ones English
    writes on its own, and those must clear the bar wherever they begin.
    """
    joined, cmap = pack if pack is not None else _packed(text)
    inside = _covered_flags(cmap, covered)
    found: list[str] = []
    for g in _GRAMMARS:
        if g.label in found:
            continue
        for literal in g.anchor:
            pos = joined.find(literal)
            while pos != -1:
                if _normalized_hit(text, joined, cmap, inside, g, literal, pos):
                    found.append(g.label)
                    break
                pos = joined.find(literal, pos + 1)
            if g.label in found:
                break
    return found


def _covered_flags(cmap: array[int], covered: list[tuple[int, int]]) -> bytearray:
    """Which compacted characters lie inside an exact span."""
    flags = bytearray(len(cmap))
    for lo, hi in covered:
        left = bisect_left(cmap, lo)
        right = bisect_left(cmap, hi)
        for i in range(left, right):
            flags[i] = 1
    return flags


def _normalized_hit(
    text: str,
    joined: str,
    cmap: array[int],
    inside: bytearray,
    g: _Grammar,
    literal: str,
    pos: int,
) -> bool:
    """Is this compacted occurrence a credential no span already accounts for?"""
    body_start = pos + len(literal)
    stop = body_start
    limit = min(len(joined), body_start + g.max_body)
    while stop < limit and _is_body(joined[stop], g):
        stop += 1
    if stop - body_start < g.min_body:
        return False

    if g.sep_after:
        # Asked of the original text, where the separator survives. A split
        # value still carries it: compaction removes whatever run sits between
        # the anchor and the body, so the character after the anchor's last one
        # is not alphanumeric. `skip_bytes` has `i` there and is not a
        # candidate, for the same reason the exact path never reported it.
        end = cmap[pos + len(literal) - 1] + 1
        if end >= len(text) or _is_alnum(text[end]):
            return False

    # What the exact pass already accounted for, and whether more body material
    # sits past a break too wide to be anything but a value driven apart.
    residue = []
    accounted = False
    driven_apart = False
    for i in range(body_start, stop):
        if inside[i]:
            accounted = True
            continue
        residue.append(joined[i])
        # A run of more than _MAX_GAP characters, none of them alphanumeric,
        # inside one candidate. Compaction removed exactly the non-alphanumerics,
        # so the distance between two neighbours here IS that run and nothing
        # needs re-reading to measure it.
        #
        # This is the same number the gap ceiling uses and it points the other
        # way, which is the whole reason it is safe. Widening a gap is how a
        # value is pushed out of attribution's reach, so it must be what pushes
        # it into recognition's. Narrowing it gets the value joined into a span
        # instead. There is no width in between.
        if i and cmap[i] - cmap[i - 1] - 1 > _MAX_GAP:
            driven_apart = True

    origin = cmap[pos]
    at_boundary = origin == 0 or not (_is_alnum(text[origin - 1]) or text[origin - 1] in "_-")
    # ``mid_token`` is asked only of a match that begins mid-token, which is
    # what the field has always said and what the exact path has always done.
    # Reading it as "always" here cost a whole class: three characters driven
    # into `sk` or `ghp` defeat the anchor walk, so attribution never fires,
    # and an all-lowercase body clears no entropy bar, so recognition did not
    # either. `s,,,k-<40 lowercase>` left both scanners with nothing to say and
    # the vault passed it through unchanged, 582 times in 1,200 and up to 82
    # characters. `always` stays as it is: Bearer begins English sentences, and
    # without it "Send the Bearer token in the Authorization header" is a JWT.
    if not at_boundary or g.randomness == "always":
        # A body too short to reach the floor cannot be asked this at all, and
        # answering "no" for it is not a conservative default, it is a silent
        # loss. AKIA admits exactly sixteen characters, so every AWS key whose
        # anchor was driven apart was rejected by a test its grammar can never
        # satisfy; a short Slack token near the end of a document is the same
        # thing per value rather than per grammar. Below the floor entropy is
        # not evidence either way, and what decides instead is the anchor,
        # which is what `randomness` records.
        low, high = _credential_window()
        body = joined[body_start:stop]
        if len(body) >= low and not _window_random(body, low, min(high, g.max_body)):
            return False

    if not accounted or driven_apart:
        return True
    # Otherwise the residue has to answer for itself, and at these lengths the
    # bar is decided by rounding: a random base62 run of twenty characters
    # scores about 4.02 bits against a bar of 4.02. What rescues most genuine
    # tails is the test above, because a gap that puts a value beyond
    # attribution's reach is wide by construction. Prose after a credential is
    # not reached that way and stops here, which is why a document holding a
    # credential is not also refused for holding it.
    low, high = _credential_window()
    return _window_random("".join(residue), low, min(high, g.max_body))


def _findings(text: str) -> list[tuple[int, int, str]]:
    """Exact credential spans. Kept as the name the rest of the module uses."""
    return _exact_findings(text)


def scan_secret_spans(text: str) -> tuple[list[tuple[int, int]], list[str]]:
    """Locate credentials in ``text``, returning spans into the ORIGINAL text.

    Shared with L13 so the model-boundary denier and the egress blocker cannot
    disagree about what a credential is. Both read the same two passes, which
    is the point: when they were separate implementations, a value split with
    punctuation was located by this one and missed by the other, so L3 allowed
    outbound content holding a key.

    The two returned halves answer different questions and the callers must not
    confuse them. The spans are attribution: characters that can be replaced
    faithfully. The labels are recognition: credentials that are present, some
    of which no span accounts for, which the caller refuses or sweeps rather
    than passing on. A value split beyond what attribution can reach does not
    disappear, it moves from the first half to the second.

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
    joinable gap, which is what a split looks like and what structure does not.
    Fragments are taken while the grammar is unsatisfied, then exactly one
    more. The cost of an extent the text does not determine is one following
    fragment rather than the remainder of a line.

    An entropy hit is deliberately not treated as delimiting. It fires on one
    fragment of a split credential, and letting it settle the extent is how
    half a key stayed in the text.
    """
    # Compacted once and shared. Both passes read the same form of the same
    # string, and building it four times a scan rather than twice was most of
    # the difference between half a second over the standard library and one.
    # Folded first, and every index below is an index into the ORIGINAL text
    # because the fold is one character for one character. Neither pass ran on
    # anything but raw text before, so a credential written in full-width
    # characters was invisible to both while a model still read it.
    text = _fold_ascii(text)
    pack = _packed(text)
    exact = _exact_findings(text, pack)
    spans: list[tuple[int, int]] = [(lo, hi) for lo, hi, _ in exact]
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
    # Labels cover BOTH what is left after masking and what only exists once
    # separators are removed. The second is the unlocatable case: recognized,
    # no span that can safely be replaced, so it is reported for the caller to
    # refuse or replace rather than quietly passed.
    labels = _scan_secrets(masked)
    # Coverage is judged against EXACT credential spans only, never against
    # entropy spans. An entropy hit lands on one fragment of a split value, and
    # treating that as coverage suppressed the normalized report for the whole
    # credential: 592 of 6,290 split positions went silent that way.
    for label in _normalized_labels(text, [(lo, hi) for lo, hi, _ in exact], pack):
        if label not in labels:
            labels.append(label)
    return merged_spans, labels


def _entropy_spans(text: str) -> list[tuple[int, int]]:
    """High-entropy runs, on the raw text only, with their continuations.

    Orthogonal to the grammars. Raw text only: with separators removed,
    unrelated lines join into one high-entropy run and mapping that back
    produced spans covering a whole document.

    A run found here is extended through what continues it, for the same
    reason and by the same rule the grammars use. A random value split by one
    inserted space becomes two fragments, and the halves do not score alike:
    one clears the bar and is replaced, the other falls under it, is not, and
    is left in the text with nothing reported, because the evidence for it was
    the half that just got masked. Splitting a 64 character token at every
    position leaked 8,727 times out of 17,763 that way, up to 37 characters.

    So an undelimited run costs one adjoining fragment on each side, exactly as
    an undelimited credential does, and then keeps taking fragments only while
    they are too long to be words. The first rule catches the short tail the
    length test would miss; the second follows a value broken into many pieces
    without following prose, since prose stops it at the first ordinary word.
    Gaps are judged by _joinable_gap, so quotes and markup end the walk and
    JSON, XML and CSV records keep their shape.
    """
    out: list[tuple[int, int]] = []
    reached = 0
    for m in re.finditer(r"[A-Za-z0-9+/\-_]{20,}", text):
        # A match already inside the span the previous one grew into is the
        # same value, and walking it again is what made this quadratic: 800
        # adjoining fragments cost 0.81s, four times the cost of 400.
        if m.start() < reached:
            continue
        token = m.group()
        if _monotonic(token):
            continue
        entropy = _shannon_entropy(token)
        threshold = min(_ENTROPY_THRESHOLD, math.log2(len(token)) - _ENTROPY_LENGTH_MARGIN)
        if entropy >= threshold:
            span = _entropy_extent(text, m.start(), m.end())
            reached = max(reached, span[1])
            out.append(span)
            continue
        if len(token) % 2 == 0 and _HEX_RE.fullmatch(token):
            try:
                if _shannon_entropy_bytes(bytes.fromhex(token)) >= _ENTROPY_THRESHOLD:
                    span = _entropy_extent(text, m.start(), m.end())
                    reached = max(reached, span[1])
                    out.append(span)
            except ValueError:
                # The two guards above should make this unreachable: an even
                # length of characters `fromhex` accepts. It is caught anyway
                # because the alternative is a scanner that raises out of the
                # egress path on some input nobody anticipated, and a token
                # this pass cannot decode is one the entropy test above already
                # declined. Not finding a second reason to report it is the
                # correct outcome, so there is nothing to do here.
                pass
    return out


def _monotonic(token: str) -> bool:
    """Is this run one stretch of an alphabet, written straight through?

    A chart of an alphabet has maximal entropy by construction and carries
    nothing. Folding compatibility forms made three more styles of chart look
    like one, on top of the plain and mathematical rows that already did.

    Asked by the SPAN pass only, so that a chart is never redacted and the
    document keeps its shape. The label pass does not ask, and must not: a
    TOTP shared secret drawn from the RFC 4648 alphabet in order IS a chart,
    and suppressing it in both places let all 32 characters out with
    reason="clean". This predicate decides how much can be replaced, never
    whether a credential is present, which is the same division every bound in
    the attribution pass observes.

    Consecutive, not merely sorted. Sorted was too broad by far: any value
    whose characters happen to ascend is sorted, and 1,000 of 1,000 generated
    high-entropy secrets that did were suppressed outright, missed by both
    entry points and passed by the vault. A chart steps by exactly one at every
    position; a secret that ascends does not, because it skips.

    Case-insensitively, because the confusable table maps some letters to
    lowercase and leaves others alone, so a folded chart arrives as
    ``abcDeFghi...`` and does not step by one in code points at all.

    Anything shorter than two characters is not a chart, and asking was a
    crash: the boundary-split rule that used to sit below this one handed it an
    empty continuation, which indexed position zero of nothing, so
    ``TOKEN="<key>"`` at the end of a file raised IndexError out of the span
    scanner. That rule is gone; the guard stays, because nothing should have to
    know that it is the only caller that could reach it.
    """
    if len(token) < 2:
        return False
    plain = token.lower()
    # A chart may be damaged and still be a chart. Requiring every step to be
    # exactly one was too narrow by as much as "sorted" was too broad: a row
    # with a letter missing, a letter repeated, two letters swapped or a
    # separator dropped in was no longer suppressed, and 142 of 214 such rows
    # came back as false spans, every one of which the vault refuses. A few
    # irregular steps is a damaged chart; a value that merely ascends has
    # almost nothing but irregular steps.
    # Three, which covers a missing letter, a repeat, a swap and a separator
    # dropped in, and is far below what a value that merely ascends scores. A
    # proportional allowance was tried and suppressed 10 of 500 sorted secrets;
    # a fixed one suppresses none of 1,000.
    allowed = 3
    for direction in (1, -1):
        irregular = sum(
            ord(b) - ord(a) != direction for a, b in zip(plain, plain[1:], strict=False)
        )
        if irregular <= allowed:
            return True
    return False


def _entropy_body(ch: str) -> bool:
    """The character class the entropy scan's own pattern accepts."""
    return ch.isascii() and (ch.isalnum() or ch in "+/-_")


def _structural(gap: str) -> bool:
    """Does this gap hold a character that ends one value and starts another?"""
    return any(c in "\"'`<>{}[]" for c in gap)


def _entropy_extent(text: str, lo: int, hi: int) -> tuple[int, int]:
    """Follow a high-entropy run through the fragments that continue it.

    One adjoining fragment on each side whatever its length, then only
    fragments at least ``_ENTROPY_MIN_LENGTH`` long. Written as two plain
    walks rather than one parameterised by direction, because the version that
    was clever about it could not be read.

    The gap itself is bounded only by ``_MAX_GAP``; _joinable_gap is not asked,
    because its quote rule refuses a two character gap outright and that is
    precisely the split being followed. Structure ends the walk, and no price buys a
    crossing. Charging one -- a fragment of at least twenty characters -- was
    tried and broke every document whose next key, tag or attribute name was
    that long: a span ran from a JSON value through ``", "`` and into a twenty
    character key, 100 times in 100, and the record came out unparseable. There
    is no safe length, because a name may be any length. A value split across
    structure is therefore NOT reported at all. Reporting one was carried for
    two rounds and measured wrong in both directions every time -- judging the
    far side of the break by its contents labelled 1,000 of 1,500 benign
    documents, judging it by length labelled 1,000 of 1,000 holding a 220
    character key -- and neither caught a value split between two JSON fields,
    where the continuation is two fragments away rather than one. The record
    keeping its shape is what is guaranteed here; the split is recorded as open
    in the handoff.
    """
    first = True
    while lo > 0:
        gap = lo
        while gap > 0 and not _entropy_body(text[gap - 1]):
            gap -= 1
        if gap == lo or lo - gap > _MAX_GAP:
            break
        frag = gap
        while frag > 0 and _entropy_body(text[frag - 1]):
            frag -= 1
        if _structural(text[gap:lo]):
            break
        if frag == gap or (not first and gap - frag < _ENTROPY_MIN_LENGTH):
            break
        lo, first = frag, False

    first = True
    while hi < len(text):
        gap = hi
        while gap < len(text) and not _entropy_body(text[gap]):
            gap += 1
        if gap == hi or gap - hi > _MAX_GAP:
            break
        frag = gap
        while frag < len(text) and _entropy_body(text[frag]):
            frag += 1
        if _structural(text[hi:gap]):
            break
        if frag == gap or (not first and frag - gap < _ENTROPY_MIN_LENGTH):
            break
        hi, first = frag, False
    return lo, hi


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
    # Two forms, because the two entry points must not disagree and they
    # normalise differently. strip_invisibles applies NFC and a confusable
    # table, which composes `A` and a combining acute into one character and
    # then folds it to lowercase, destroying the AKIA anchor that the span
    # scanner still sees in the raw text: 485 of 500 such values were found by
    # one entry point and missed by the other. Reading both forms means this
    # cannot miss what the span scanner finds.
    raw = _fold_ascii(text)
    stripped = _fold_ascii(strip_invisibles(text))
    forms = [stripped] if raw == stripped else [stripped, raw]
    for form in forms:
        pack = _packed(form)
        exact = _exact_findings(form, pack)
        for _lo, _hi, label in exact:
            if label not in found:
                found.append(label)
        for label in _normalized_labels(form, [(lo, hi) for lo, hi, _ in exact], pack):
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
    # The raw form is the primary one. Reading the invisible-stripped form as
    # primary made every soft hyphen and zero-width joiner between two words a
    # token-forming character: a pangram joined at its word boundaries became
    # one long run scoring 4.6 bits, and 1,000 of 1,000 of them were labelled
    # and refused. Removing invisibles joins words exactly as removing
    # whitespace does, so it earns the same digit requirement.
    entropy_forms: list[tuple[str, bool]] = [(raw, False)]
    if stripped != raw:
        entropy_forms.append((stripped, True))
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
            # NOTE: _monotonic is deliberately NOT consulted here, only in the
            # span pass. Suppressing a chart in both places is the one rule in
            # this module that could make a credential disappear entirely
            # rather than move from a span to a label, which is exactly what
            # the division at the top of this file exists to prevent. It did:
            # `234567ABCDEFGHIJKLMNOPQRSTUVWXYZ` is the RFC 4648 Base32
            # alphabet and also an ordinary TOTP shared secret, and all 32
            # characters left through check_outbound with reason="clean".
            #
            # A value can be indistinguishable from an alphabet only by being
            # one, so nothing here can separate the two. Reporting is the safe
            # direction: the span pass still refuses to redact a chart, so
            # measured over 153 standard library files the spans and the
            # characters they cover are unchanged at 37 and 3,157, and the
            # whole cost is three more files drawing a label, base64.py and
            # calendar.py among them. A refused document is loud and an
            # operator can act on it. A shared secret leaving in the clear is
            # silent.
            entropy = _shannon_entropy(token)
            # Length-aware threshold: never require more entropy than the
            # length can produce. Caps at _ENTROPY_THRESHOLD for long tokens
            # (unchanged) but closes the 20-22 char dead zone for short ones.
            effective_threshold = min(
                _ENTROPY_THRESHOLD, math.log2(len(token)) - _ENTROPY_LENGTH_MARGIN
            )
            if entropy >= effective_threshold:
                # A chart gets its own label rather than the generic one. Both
                # are reported, so a TOTP secret written as the Base32 alphabet
                # is still refused at egress, but the two are not
                # interchangeable to a caller that ACTS on a finding: the
                # vault's residue sweep replaces any line that scans as
                # carrying credential material, and with one label it replaced
                # `alphabet = abcdefghijklmnopqrstuvwxyz` outright. Destroying
                # a line on a run that is far more often a character table
                # than a secret is the corruption the whole span/label
                # division exists to avoid, and it is silent, which is what
                # makes it worse than the leak it was guarding against.
                label = (
                    _AMBIGUOUS_ALPHABET
                    if _monotonic(token)
                    else f"High-entropy token ({entropy:.1f} bits)"
                )
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
        self._append_windows(self._buffer, content)

    def ingest_sensitive(self, content: str) -> None:
        """Normalize and buffer sensitive content for contaminated-context checks."""
        self._append_windows(self._sensitive_buffer, content)

    @staticmethod
    def _append_windows(buffer: deque[str], content: str) -> None:
        """Buffer all of ``content``, in windows, rather than its first 50k.

        Truncating each entry was the same bypass as truncating the outbound
        side, in the other direction: a document ingested past the cap was only
        remembered up to it, so copying a passage out of the tail of a 60,000
        character document came back clean. Reproduced before this change.

        One window per entry keeps every entry within the per-entry bound the
        comparison relies on, so the memory ceiling is unchanged: entries are
        still capped, and the deque still holds a fixed number of them. What
        changes is that a large document occupies several slots instead of
        silently losing its tail. The total the buffer can remember is
        therefore its length times the window, and a document beyond that
        evicts its own earliest windows, which is the same recency rule the
        deque already applied between documents.
        """
        normalized = normalize_for_overlap(content)
        if not normalized:
            return
        for window in overlap_windows(normalized):
            if window:
                buffer.append(window)

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

        # The overlap checks below scan ALL of the content, in windows. This
        # used to truncate to MAX_OVERLAP_CHARS and compare the prefix, which
        # was a silent bypass: the same copied passage padded past the cap came
        # back clean. Beyond what we will scan, refuse rather than truncate,
        # because reporting clean on content we did not read is the bug.
        normalized_content = normalize_for_overlap(content)
        if len(normalized_content) > MAX_OVERLAP_SCAN_CHARS:
            return OutboundResult(
                allowed=False,
                reason=(
                    f"content is {len(normalized_content)} normalized characters, "
                    f"beyond the {MAX_OVERLAP_SCAN_CHARS} the overlap checks inspect"
                ),
            )

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
            refs = [deobfuscate_separated(b) if strip_seps else b for b in self._buffer]
            # One windowed pass over the whole variant for the whole buffer. The
            # substring check is gated on a shared gram the length of the
            # threshold, which is exact: a common substring that long contains
            # such a gram, so no shared gram proves no blocking overlap.
            for ngram, lcs_len in overlap_scan(variant, refs, lcs_gate=echo_threshold):
                if ngram > echo_max_ngram:
                    echo_max_ngram = ngram
                if lcs_len > echo_max_lcs:
                    echo_max_lcs = lcs_len
                # Echo is a boolean signal; once tripped, further scanning only
                # refines a metadata value, so stop.
                if echo_max_lcs >= echo_threshold or echo_max_ngram >= ngram_threshold:
                    echo_detected = True
                    break

        # Step 3: Sensitive-leak check (BLOCK trigger).
        # Outbound vs sensitive buffer at base threshold. Echo does not
        # widen this check; it is pure metadata for downstream layers.
        if contaminated and not has_quoting_directive:
            for variant, strip_seps, label in variants:
                sensitive_refs = [
                    deobfuscate_separated(b) if strip_seps else b for b in self._sensitive_buffer
                ]
                for overlap, lcs_len in overlap_scan(
                    variant, sensitive_refs, lcs_gate=sensitive_lcs
                ):
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
