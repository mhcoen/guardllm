"""Part 7: Outbound DLP (Data Loss Prevention).

Scans outbound content against recently ingested untrusted content
to detect exfiltration attempts. Checks verbatim overlap, n-gram
overlap, and secret patterns.
"""

from __future__ import annotations

import math
import re
from collections import deque
from collections.abc import Callable

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

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk[-_][A-Za-z0-9]{20,80}"), "OpenAI API key"),
    (re.compile(r"sk[-_]proj[-_][A-Za-z0-9\-_]{20,220}"), "OpenAI project key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"ya29\.[A-Za-z0-9_\-]{20,600}"), "Google OAuth token"),
    (re.compile(r"gho_[A-Za-z0-9]{36,60}"), "GitHub OAuth token"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,60}"), "GitHub personal access token"),
    (re.compile(r"ghs_[A-Za-z0-9]{36,60}"), "GitHub app token"),
    (re.compile(r"ghr_[A-Za-z0-9]{36,60}"), "GitHub refresh token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,100}"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private key header"),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(?:\.[A-Za-z0-9\-_]+)?"),
        "Bearer/JWT token",
    ),
]

def _merged_variant(source: str) -> str:
    """Rewrite a pattern so it still matches once whitespace has been removed.

    Two grammars here contain whitespace of their own: ``Bearer\\s+...`` and the
    PEM header. Against the whitespace-merged form they could never match, so a
    JWT split inside its payload was reconstructed by nobody and left its middle
    segment in the text. Making their whitespace optional is what lets the
    merged scan see them at all.
    """
    return source.replace(r"\s+", r"\s*").replace(" ", r"\s*")


_ENTROPY_THRESHOLD = 4.5
_ENTROPY_MIN_LENGTH = 20
# A string of length L has a maximum possible Shannon entropy of log2(L).
# For L in [20, 22] that ceiling (4.32 - 4.46 bits) is below _ENTROPY_THRESHOLD,
# so a 20-22 char random token could NEVER trip the absolute threshold. For
# such short tokens, flag when the entropy is within this margin of the
# theoretical maximum for the length (i.e. near-maximal randomness) instead.
_ENTROPY_LENGTH_MARGIN = 0.30

_MERGED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(_merged_variant(p.pattern)), label) for p, label in _SECRET_PATTERNS
]

#: Grammars whose merged form must additionally look random.
#:
#: Only the JWT one qualifies and the reason is specific to it. Its payload is
#: two or three base64url segments separated by dots, which as a pattern is
#: indistinguishable from two English words separated by a full stop. In the
#: raw text a sentence is safe because the space after the stop breaks the
#: match. Merged, that space is gone, and "Use Bearer authorization. Header
#: values are case sensitive." became a JWT and blocked outbound content with
#: the vault switched off. A real payload is base64 and clears the bar; a
#: sentence does not.
#:
#: Not applied to the others. They are anchored by a literal prefix that
#: English does not produce, and their bodies are not always maximally random:
#: AKIAIOSFODNN7EXAMPLE is a real key that sits below this threshold.
_MERGED_NEEDS_RANDOM = frozenset({"Bearer/JWT token"})

#: The grammars again with every separator gone, for text where the value was
#: split with punctuation rather than whitespace.
#:
#: Removing whitespace alone left this open: a comma, a full stop, a pipe, a
#: semicolon, a bracket, in fact anything but ``+`` and ``/``, split a key into
#: two fragments that no form reassembled, and 32 characters stayed in the
#: text at most split positions of most grammars. ``+`` and ``/`` were the
#: exceptions only because they are inside the entropy scanner's own character
#: class, so both halves stayed in one token it could see.
#:
#: These are written out rather than derived from the table above. Deriving one
#: by rewriting required separators to optional ones is what turned
#: ``Bearer\s+`` into ``Bearer\s*`` and made a sentence a JWT, and a
#: transformation that cannot be read is a transformation nobody checks.
#: test_every_grammar_has_a_separator_free_twin pins each of these to a real
#: credential of its grammar, so the table cannot drift from the one above.
#:
#: `sk` and `Bearer` are deliberately absent, and that omission is the whole
#: reason this table is small. They are the two prefixes ordinary text produces
#: on its own: `sk` sits inside `disk`, `task` and `ask`. Applied to a form
#: with underscores removed, `disk_usage` becomes `diskusage` and every such
#: identifier in a source file starts an OpenAI key. That cost 492,745
#: characters of the standard library, against 3,051 before, and took 33
#: seconds. Those two grammars are served by the punctuation-stripped form
#: below, which keeps `-` and `_` and so never joins an identifier to its
#: neighbour. What is left here are prefixes English does not write, and they
#: are what a value split with a hyphen or an underscore needs, since those two
#: characters are inside several of the grammars themselves.
#:
#: The third element, whether a match must also look random, is false for every
#: entry: a token boundary is required outright on this form, which is the
#: stronger constraint, and it was randomness rather than the boundary that
#: build-config text kept clearing. The column stays because the merged form
#: shares this loop and does need it for the JWT grammar.
#:
#: The PEM header is listed but a hyphen driven into it still evades this form,
#: because the alnum form preserves whitespace runs and the header contains
#: them. That is left alone on purpose. The header is public boilerplate
#: carrying no secret, and a real key block is still caught by the entropy scan
#: on the key material beneath it; closing it would mean loosening the grammar
#: further, which is the move that made a sentence a JWT.
_SEPARATOR_FREE_PATTERNS: list[tuple[re.Pattern[str], str, bool]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key", False),
    (re.compile(r"skproj[A-Za-z0-9]{20,220}"), "OpenAI project key", False),
    (re.compile(r"ya29[A-Za-z0-9]{20,600}"), "Google OAuth token", False),
    (re.compile(r"gh[oprs][A-Za-z0-9]{36,60}"), "GitHub token", False),
    (re.compile(r"xox[baprs][A-Za-z0-9]{10,100}"), "Slack token", False),
    (re.compile(r"BEGIN(?:RSA|EC|DSA|OPENSSH)?PRIVATEKEY"), "Private key header", False),
]

#: Grammars whose prefix ordinary text does not produce.
#:
#: These are exempt from the mid-token randomness rule. That rule exists for
#: the two prefixes English writes on its own: `sk` inside `netmask_cache`,
#: `Bearer` starting a sentence. Applied to the rest it only cost detection,
#: because their bodies are not always random enough to clear the bar, so
#: prefixing one character in front of a split value hid it: "XAKIA,IOSF..."
#: kept 19 of 20 characters, and the same trick worked on the project key and
#: the Google token with a plain space.
_DISTINCTIVE_PREFIXES = frozenset({
    "AWS access key",
    "OpenAI project key",
    "Google OAuth token",
    "GitHub token",
    "GitHub OAuth token",
    "GitHub personal access token",
    "GitHub app token",
    "GitHub refresh token",
    "Slack token",
    "Private key header",
})

_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]")
_PUNCT_FREE_RE = re.compile(r"[^A-Za-z0-9\-_+/]")

#: Punctuation only: everything that is not alphanumeric and not one of the
#: four characters the grammars and the entropy scanner actually contain.
#: Stripping this catches a value split with a comma, full stop, pipe, colon,
#: bracket or any other punctuation, which leaked 32 characters at nearly every
#: split position, while leaving `disk_usage` and `x-request-id` intact.
_PUNCT_KEEP = frozenset("-_+/")

# Pure hex character pattern for decode-then-scan
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


def _strip_with_offsets(text: str, drop: str | None) -> tuple[str, list[int]]:
    """Remove characters, recording each survivor's original index.

    ``drop=None`` means whitespace. Passing a literal string of whitespace
    characters would be wrong: any membership test against a sentinel string
    also matches the letters in that sentinel.
    """
    out: list[str] = []
    idx: list[int] = []
    for i, ch in enumerate(text):
        if ch.isspace() if drop is None else (ch in drop):
            continue
        out.append(ch)
        idx.append(i)
    return "".join(out), idx


def _strip_intra_token(
    text: str, base: list[int], keep: frozenset[str]
) -> tuple[str, list[int]]:
    """Remove separator runs that sit BETWEEN two alphanumerics, and no others.

    This is what makes a punctuation-stripped form usable at all. Stripping
    every separator joined each credential to whatever followed it, so
    ``sk-...uvwx, trailing`` and ``{"key": "sk-...uvwx", "other": "value"}``
    both became ambiguous and cost their whole line, undoing the precision that
    quoting and punctuation are supposed to buy.

    The asymmetry that fixes it: splitting a value with punctuation means
    writing ``sk-abc,def``, with nothing either side of the comma, because
    adding a space would make it the whitespace case instead. Ordinary text
    writes ``key, next word``, with a space after. So a separator run counts
    only when alphanumerics close it on both sides.
    """
    out: list[str] = []
    idx: list[int] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if (ch.isascii() and ch.isalnum()) or ch in keep:
            out.append(ch)
            idx.append(base[i])
            i += 1
            continue
        j = i
        while j < n and not ((text[j].isascii() and text[j].isalnum()) or text[j] in keep):
            j += 1
        def _content(ch: str) -> bool:
            # Kept separators count as content on either side, or a comma
            # placed against the grammar's own punctuation is not recognised
            # as intra-token: "sk,-proj-..." and "ghp,_A1b2..." both survived,
            # which is where the remaining leaks were, all of them inside a
            # prefix rather than in the body.
            return (ch.isascii() and ch.isalnum()) or ch in keep

        flanked = (
            i > 0
            and j < n
            and _content(text[i - 1])
            and _content(text[j])
            # A run holding any whitespace is the ordinary-text case, not a
            # split: "key, next word" has a space after the comma and
            # "sk-abc,def" does not. Whitespace joins are the merged form's
            # job, and letting them be joined here as well made every
            # delimited credential ambiguous again.
            and not any(c.isspace() for c in text[i:j])
        )
        if not flanked:
            # Keep the run's own characters out of the form but do not let the
            # two sides join: emit a space so the grammars still see a break.
            out.append(" ")
            idx.append(base[i])
        i = j
    return "".join(out), idx


def _pattern_and_entropy_spans(form: str, merged: bool) -> list[tuple[int, int]]:
    """Every credential span in one representation of the text."""
    out: list[tuple[int, int]] = []
    for pattern, _label in _SECRET_PATTERNS:
        out.extend((m.start(), m.end()) for m in pattern.finditer(form))
    for m in re.finditer(r"[A-Za-z0-9+/\-_]{20,}", form):
        token = m.group()
        # On a whitespace-merged form, only tokens containing a digit are
        # candidates: a natural-language sentence merges into one long
        # alphabetic run that clears the entropy threshold. _scan_secrets
        # applies the same guard for the same reason.
        if merged and not any(c.isdigit() for c in token):
            continue
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


def _looks_random(s: str) -> bool:
    """Does this clear the same randomness bar the entropy scanner applies?

    Same threshold and same length allowance, so "random" means one thing in
    this module rather than two. No minimum length here, unlike the standalone
    entropy scan: this is asked about text a grammar has already claimed, and
    the shortest thing a grammar accepts is a 15 character Slack token.
    """
    if not s:
        return False
    return _shannon_entropy(s) >= min(
        _ENTROPY_THRESHOLD, math.log2(len(s)) - _ENTROPY_LENGTH_MARGIN
    )


def _line_end(text: str, pos: int) -> int:
    """End of the line containing ``pos``, exclusive of the newline."""
    nl = text.find("\n", pos)
    return len(text) if nl == -1 else nl


def _line_start(text: str, pos: int) -> int:
    """Start of the line containing ``pos``."""
    return text.rfind("\n", 0, pos) + 1


def _next_token(text: str, pos: int) -> tuple[int, int]:
    """The next whitespace delimited token at or after ``pos``."""
    nxt = pos
    while nxt < len(text) and text[nxt].isspace():
        nxt += 1
    stop = nxt
    while stop < len(text) and not text[stop].isspace():
        stop += 1
    return nxt, stop


def _extend_ambiguous(
    text: str,
    lo: int,
    hi: int,
    pattern: re.Pattern[str],
    reach: int,
    may_wrap: bool,
    normalize: Callable[[str], str],
) -> int:
    """Widen a span whose true extent cannot be recovered from the text.

    A credential is contiguous when written. Once whitespace is inserted into
    it, nothing marks where it stopped: the characters that continue a key are
    the characters that spell a word. Every rule that tried to tell them apart
    failed in one direction or the other. The predecessor here required a
    following token to be alphanumeric and at least ten characters, which both
    kept a 27 character tail of a Slack token, whose grammar admits ``-`` so
    the fragment was not alphanumeric, and deleted ``documentation
    configuration authentication`` out of ordinary prose.

    So this does not guess at word boundaries. Within the line the unit of
    redaction is the whole line. Past the line break it is a single token, and
    only under conditions that make a wrap possible at all, because a walk that
    was free to cross break after break took the rest of a document with it.
    """
    end = _line_end(text, max(lo, hi - 1))
    if not may_wrap:
        return end

    def merged_to(stop: int) -> str:
        # Normalized the same way the form that produced this match was, or the
        # grammar cannot be asked whether it is satisfied yet.
        return normalize(text[lo:stop])

    # The value may be cut short of its own grammar by the break, so take
    # whatever tokens the minimum still requires. ``match``, not ``fullmatch``:
    # the question is whether a complete credential is present from the start,
    # not whether the entire span is one. Bounded by the grammar's minimum.
    while end < len(text) and not pattern.match(merged_to(end)):
        nxt, stop = _next_token(text, end)
        if nxt >= len(text):
            break
        end = stop

    # A value broken across several short lines leaves each continuation alone
    # on its own line. That is the shape, and it is what separates a wrap from
    # prose: a wrapped fragment is the only thing on its line, an English line
    # has several words on it. Take those whole lines while they last. Bounded
    # twice over, by the merged match's reach and so by the grammar's maximum
    # length, and by the first line that turns out to be a sentence.
    #
    # Without this a Slack token split across five lines kept its last 19
    # characters: the minimum was satisfied three lines up, and one further
    # token did not reach the end.
    while end < reach:
        nxt, stop = _next_token(text, end)
        if nxt >= reach or text.find("\n", end, nxt) == -1:
            break  # same line, so not a wrap; the single-token rule handles it
        if stop > reach or stop != _line_end(text, nxt):
            break  # something else shares the line, so it is not a bare wrap
        end = stop

    # One token more, for the remainder of a value the break split after its
    # minimum was already met. Exactly one: that covers a wrap, and it bounds
    # what a contiguous credential sitting at a line end can cost the text
    # below it to a single word. Skipped when the raw scan already covers the
    # continuation from its first character, since it will redact it unaided
    # and widening here would only destroy more.
    if end < reach:
        nxt, stop = _next_token(text, end)
        if nxt < reach:
            cand = text[nxt : min(stop, reach)]
            if not any(a == 0 for a, _ in _pattern_and_entropy_spans(cand, merged=False)):
                end = min(stop, max(reach, end))
    return end


def _is_exact(spans: list[tuple[int, int]], lo: int, hi: int) -> bool:
    """Did the raw scan already locate precisely this span?

    A merged-form match that maps back onto the identical span found nothing
    the raw grammar had not already delimited, so its extent is known and the
    surrounding text is safe. This is what keeps quoted and punctuated contexts
    precise: in ``{"key": "sk-...", "other": "value"}`` the quote ends the
    character class in both forms, the two matches coincide, and nothing beyond
    the credential is touched.
    """
    return any(a == lo and b == hi for a, b in spans)


def scan_secret_spans(text: str) -> tuple[list[tuple[int, int]], list[str]]:
    """Locate credentials in ``text``, returning spans into the ORIGINAL text.

    Shared with L13 so the model-boundary denier and the egress blocker cannot
    disagree about what a credential is.

    The extent question, settled. For four rounds this alternated between the
    greedy reconstruction, which ran through the words after the credential and
    deleted them, and the shortest accepted prefix, which stopped inside the
    secret. Measured with an oracle that looks for runs of the original value
    rather than asking the same scanner again, the shortest prefix left up to
    25 recoverable characters of a live key at 63 of 145 split positions.

    The settled rule is that the extent is either KNOWN or it is not, and the
    two get different treatment:

    * **Known.** The whitespace-merged form matches over exactly the span the
      raw grammar already delimited. Merging changed nothing, so the credential
      is contiguous and its own start and end are authoritative. Nothing around
      it is touched. Quoting and punctuation land here, because a quote or
      comma ends the character class in both forms: in
      ``{"key": "sk-...", "other": "value"}`` only the key is redacted.
    * **Unknown.** The merged form matches over more than the raw scan
      delimited, so whitespace was inserted into the value, or the raw match
      was only its prefix. Nothing in the text says where it stopped: the
      characters that continue a key are the characters that spell a word.
      This does not guess. The unit of redaction becomes the logical line, and
      the grammar decides how many lines: keep taking them while the merged
      span still does not contain a complete credential, which crosses exactly
      one line break for a wrapped value and none for a value that ended
      inside its line.

    Two earlier rules failed here and are recorded so they are not retried. The
    shortest accepted prefix left up to 25 recoverable characters of a live key
    at 63 of 145 split positions. Its replacement, extending through following
    tokens that were alphanumeric and at least ten characters, failed in both
    directions at once: it kept a 27 character tail of a Slack token, whose
    grammar admits ``-`` so the fragment was not alphanumeric, and it deleted
    ``documentation configuration authentication`` out of ordinary prose.

    An entropy hit is deliberately not treated as delimiting. It fires on one
    token of a split credential, and letting it suppress the reconstruction is
    exactly how half of a key stayed in the text.
    """
    pattern_spans: list[tuple[int, int]] = []
    for pattern, _label in _SECRET_PATTERNS:
        pattern_spans.extend((m.start(), m.end()) for m in pattern.finditer(text))

    spans: list[tuple[int, int]] = list(pattern_spans)

    def _entropy_spans(form: str, merged: bool) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        for m in re.finditer(r"[A-Za-z0-9+/\-_]{20,}", form):
            token = m.group()
            # On a whitespace-merged form only tokens containing a digit count:
            # an English sentence merges into one long alphabetic run that
            # clears the entropy threshold. _scan_secrets guards the same way.
            if merged and not any(c.isdigit() for c in token):
                continue
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

    spans.extend(_entropy_spans(text, merged=False))

    stripped, stripped_idx = _strip_with_offsets(text, "\u200b\u200c\u200d\u2060\ufeff")
    ws_removed, ws_idx = _strip_with_offsets(stripped, None)
    ws_map = [stripped_idx[i] for i in ws_idx]

    # Two further forms, for values split with something other than whitespace.
    # Offsets map back through each strip.
    #
    #  - punctuation removed but `-_+/` kept, matched with the ordinary
    #    grammars, since those four characters are the ones the grammars and
    #    the entropy scanner contain. This is the general case.
    #  - everything non-alphanumeric removed, matched with the small table of
    #    distinctive prefixes only. This is what a value split on a hyphen or
    #    an underscore needs, and it is restricted precisely because removing
    #    those two joins ordinary identifiers to their neighbours.
    punct_free, punct_free_map = _strip_intra_token(stripped, stripped_idx, _PUNCT_KEEP)
    alnum_only, alnum_map = _strip_intra_token(stripped, stripped_idx, frozenset())

    forms: list[tuple[str, list[int], str]] = [
        (stripped, stripped_idx, "raw"),
        (ws_removed, ws_map, "merged"),
        (punct_free, punct_free_map, "punct_free"),
        (alnum_only, alnum_map, "separator_free"),
    ]
    for form, idx, kind in forms:
        if form == text:
            continue
        merged = kind != "raw"
        # Patterns only. An entropy hit on a merged form says nothing about
        # extent: with the whitespace removed, unrelated lines join into one
        # high-entropy run, and mapping that back produced spans covering a
        # whole document. Entropy still contributes on the raw text above,
        # where token boundaries are intact.
        found: list[tuple[int, int, re.Pattern[str], str, bool]] = []
        if kind == "separator_free":
            table = [(p, lbl, rnd) for p, lbl, rnd in _SEPARATOR_FREE_PATTERNS]
        else:
            base = _MERGED_PATTERNS if kind == "merged" else _SECRET_PATTERNS
            table = [(p, lbl, lbl in _MERGED_NEEDS_RANDOM and merged) for p, lbl in base]
        for pattern, label, needs_random in table:
            found.extend(
                (m.start(), m.end(), pattern, label, needs_random)
                for m in pattern.finditer(form)
            )
        for lo_f, hi_f, pattern, label, needs_random in found:
            if not (lo_f < len(idx) and hi_f - 1 < len(idx)):
                continue
            lo, hi = idx[lo_f], idx[hi_f - 1] + 1
            # The merged form located exactly what the raw grammar already had.
            # Nothing is ambiguous, so nothing around it is touched.
            if _is_exact(pattern_spans, lo, hi):
                continue
            # Removing whitespace creates prefixes that never existed: `sk_`
            # sits inside `netmask_cache`, and once the following words are
            # joined to it, twenty alphanumerics follow and the OpenAI grammar
            # matches. Acted on, that redacted 67,445 characters of
            # ipaddress.py.
            #
            # A match that begins where a token begins is taken at face value;
            # quotes, colons and brackets all satisfy that, so a key inside
            # JSON or YAML is unaffected. One that begins mid-token has to earn
            # it, because that is the shape the merge invents.
            #
            # What earns it is randomness, not a digit. Requiring the boundary
            # alone was defeated by typing one character in front of the value,
            # which leaked 32 characters. Accepting a digit instead let
            # "netmask_cache holds 20 prefixlen values here" through, since the
            # merge joins the words and the sentence supplies the digit. The
            # bodies differ where it counts: joined English words repeat
            # letters and a key does not.
            #
            merged_body = _NON_ALNUM_RE.sub("", text[lo:hi])
            if needs_random and not _looks_random(merged_body):
                continue
            # A mid-token match has to earn itself by looking random, because
            # joining words is what invents prefixes that were never written.
            #
            # That rule is not applied to the separator-free form. Every
            # grammar in that table is anchored by something English does not
            # produce, and the intra-token rule above already stops two words
            # being joined across a space, so the shape it guards against
            # cannot arise there. Applying it anyway cost the AWS grammar,
            # whose keys are not random enough to clear the bar:
            # "XAKIA,IOSFODNN7EXAMPLE" kept 19 of its 20 characters.
            #
            # A separate boundary test for that form used to sit here. It
            # became dead the moment separator runs stopped being stripped
            # across whitespace, and removing it changed neither the standard
            # library measurement nor any test, so it is gone rather than kept
            # as untested weight.
            at_boundary = lo == 0 or not (text[lo - 1].isalnum() or text[lo - 1] in "_-")
            if (
                label not in _DISTINCTIVE_PREFIXES
                and not at_boundary
                and not _looks_random(merged_body)
            ):
                continue
            # How far the merged match reaches in original coordinates, kept
            # before the clamps below so the wrap case can consult it.
            reach = hi
            # Otherwise the value is split, or the raw match was only its
            # prefix. Widen to the whitespace delimited tokens involved.
            while lo > 0 and not text[lo - 1].isspace():
                lo -= 1
            while hi < len(text) and not text[hi].isspace():
                hi += 1
            # Clamp to the line the match starts on before widening further. A
            # reconstruction allowed to run free consumed the remainder of a
            # multi-line document, which is the destruction this area exists to
            # avoid; _extend_ambiguous re-crosses a line break only when the
            # grammar says the credential cannot have ended yet.
            line_e = _line_end(text, lo)
            hi = min(hi, line_e)
            if hi <= lo:
                continue
            # Can the value have been broken by the line break at all? Only if
            # it runs up to it. A raw match that finished earlier on this line,
            # with whitespace after it, was terminated by that whitespace, so
            # nothing below continues it. Without this the walk crossed break
            # after break through ordinary prose and took the rest of a
            # document with it, which is the failure this area exists to avoid.
            #
            # Only spans belonging to THIS candidate may answer that question.
            # Consulting every raw span on the line let an unrelated credential
            # silence the wrap logic for its neighbour: an AWS key sitting in
            # front of a wrapped Slack token made may_wrap false, and the whole
            # 19 character Slack tail stayed in the text.
            may_wrap = not any(
                a < reach and lo < b and b < line_e and text[b].isspace()
                for a, b in pattern_spans
            )
            normalize = (
                _NON_ALNUM_RE.sub
                if kind == "separator_free"
                else _PUNCT_FREE_RE.sub
                if kind == "punct_free"
                else _WHITESPACE_RE.sub
            )
            spans.append(
                (
                    lo,
                    _extend_ambiguous(
                        text, lo, hi, pattern, reach, may_wrap,
                        lambda t, _n=normalize: _n("", t),
                    ),
                )
            )

    # Merge overlapping spans. They are all one class, so two that overlap are
    # one finding, and leaving them separate made partially overlapping
    # credential spans trip the ambiguous-identifier rule and refuse the
    # document.
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


def _scan_secrets(text: str) -> list[str]:
    """Scan text for known secret patterns and high-entropy strings."""
    found: list[str] = []

    # The secret scan is the only always-on hard block, so it must not be
    # defeated by trivial obfuscation. Build extra forms:
    #  - `stripped`: zero-width/bidi/tag chars removed (defeats a U+200B
    #    inserted mid-token, e.g. "sk-abc<ZWSP>def...").
    #  - `ws_removed`: whitespace also removed (defeats a space inserted
    #    mid-token, e.g. "sk-abcdefghij klmno...").
    # Patterns that legitimately contain whitespace (Bearer, PRIVATE KEY
    # header) cannot match a form their own separators were removed from, so
    # the merged form is scanned with the variants that make that whitespace
    # optional. Without it, splitting a JWT inside its payload was reported by
    # nobody.
    stripped = strip_invisibles(text)
    ws_removed = _WHITESPACE_RE.sub("", stripped)
    forms = [text]
    for form in (stripped, ws_removed):
        if form not in forms:
            forms.append(form)
    merged_only = [f for f in (ws_removed,) if f not in (text, stripped)]

    for (pattern, label), (merged_pattern, _) in zip(_SECRET_PATTERNS, _MERGED_PATTERNS):
        if label in found:
            continue
        if any(pattern.search(form) for form in forms):
            found.append(label)
            continue
        # A hit that exists only once whitespace is gone has to look random.
        # Making the mandatory separator optional is what lets a grammar cross
        # a sentence boundary it could never cross in the original: "Use Bearer
        # authorization. Header values are case sensitive." became a JWT, and
        # blocked outbound content with the vault switched off entirely.
        for form in merged_only:
            m = merged_pattern.search(form)
            if m is not None and _looks_random(m.group()):
                found.append(label)
                break

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
