"""Part 7: Outbound DLP (Data Loss Prevention).

Scans outbound content against recently ingested untrusted content
to detect exfiltration attempts. Checks verbatim overlap, n-gram
overlap, and secret patterns.
"""

from __future__ import annotations

import math
import re
from collections import deque

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
    text: str, lo: int, hi: int, pattern: re.Pattern[str], reach: int, may_wrap: bool
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
        return _WHITESPACE_RE.sub("", text[lo:stop])

    # The value may be cut short of its own grammar by the break, so take
    # whatever tokens the minimum still requires. ``match``, not ``fullmatch``:
    # the question is whether a complete credential is present from the start,
    # not whether the entire span is one. Bounded by the grammar's minimum.
    while end < len(text) and not pattern.match(merged_to(end)):
        nxt, stop = _next_token(text, end)
        if nxt >= len(text):
            break
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

    for form, idx, merged in ((stripped, stripped_idx, False), (ws_removed, ws_map, True)):
        if form == text:
            continue
        # Patterns only. An entropy hit on a merged form says nothing about
        # extent: with the whitespace removed, unrelated lines join into one
        # high-entropy run, and mapping that back produced spans covering a
        # whole document. Entropy still contributes on the raw text above,
        # where token boundaries are intact.
        found: list[tuple[int, int, re.Pattern[str]]] = []
        table = _MERGED_PATTERNS if merged else _SECRET_PATTERNS
        for pattern, _label in table:
            found.extend((m.start(), m.end(), pattern) for m in pattern.finditer(form))
        for lo_f, hi_f, pattern in found:
            if not (lo_f < len(idx) and hi_f - 1 < len(idx)):
                continue
            lo, hi = idx[lo_f], idx[hi_f - 1] + 1
            # The merged form located exactly what the raw grammar already had.
            # Nothing is ambiguous, so nothing around it is touched.
            if _is_exact(pattern_spans, lo, hi):
                continue
            # A credential begins where a token begins. Removing whitespace
            # creates prefixes that never existed: `sk_` sits inside
            # `netmask_cache`, and once the following words are joined to it,
            # twenty alphanumerics follow and the OpenAI grammar matches. Acted
            # on, that redacted 67,445 characters of ipaddress.py. Quotes,
            # colons and brackets still count as boundaries, so a key inside
            # JSON or YAML is unaffected.
            if lo > 0 and (text[lo - 1].isalnum() or text[lo - 1] in "_-"):
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
            may_wrap = not any(
                a >= _line_start(text, lo) and b < line_e and text[b].isspace()
                for a, b in pattern_spans
            )
            spans.append((lo, _extend_ambiguous(text, lo, hi, pattern, reach, may_wrap)))

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
        if any(pattern.search(form) for form in forms) or any(
            merged_pattern.search(form) for form in merged_only
        ):
            found.append(label)

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
