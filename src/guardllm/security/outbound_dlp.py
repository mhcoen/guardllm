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
    (re.compile(r"sk[-_][A-Za-z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"sk[-_]proj[-_][A-Za-z0-9\-_]{20,}"), "OpenAI project key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"ya29\.[A-Za-z0-9_\-]{20,}"), "Google OAuth token"),
    (re.compile(r"gho_[A-Za-z0-9]{36,}"), "GitHub OAuth token"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "GitHub personal access token"),
    (re.compile(r"ghs_[A-Za-z0-9]{36,}"), "GitHub app token"),
    (re.compile(r"ghr_[A-Za-z0-9]{36,}"), "GitHub refresh token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private key header"),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(?:\.[A-Za-z0-9\-_]+)?"),
        "Bearer/JWT token",
    ),
]

_ENTROPY_THRESHOLD = 4.5
_ENTROPY_MIN_LENGTH = 20
# A string of length L has a maximum possible Shannon entropy of log2(L).
# For L in [20, 22] that ceiling (4.32 - 4.46 bits) is below _ENTROPY_THRESHOLD,
# so a 20-22 char random token could NEVER trip the absolute threshold. For
# such short tokens, flag when the entropy is within this margin of the
# theoretical maximum for the length (i.e. near-maximal randomness) instead.
_ENTROPY_LENGTH_MARGIN = 0.30

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


#: How much non-participating text a mapped-back span may cover beyond the
#: match itself: a handful of inserted spaces or zero-width characters.
_MAX_OBFUSCATION_SLACK = 8


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


def scan_secret_spans(text: str) -> tuple[list[tuple[int, int]], list[str]]:
    """Locate credentials in ``text``, returning spans into the ORIGINAL text.

    Shared with L13 so the model-boundary denier and the egress blocker cannot
    disagree about what a credential is. The full scan, not just the regex
    table: unprefixed high-entropy tokens and hex-encoded secrets count, and so
    do values obfuscated with inserted whitespace or invisible characters.

    Obfuscated findings are mapped back through the strip to a conservative
    span running from the first participating character to the last. Without
    that mapping they had no span, de-identification refused the whole
    document, and an untrusted content author could suppress any retrieved page
    by embedding one spaced credential-shaped string.
    """
    spans: list[tuple[int, int]] = []
    raw_spans: list[tuple[int, int]] = []

    def _collect(form: str, idx: list[int] | None, merged: bool = False) -> None:
        def _record(start: int, end: int) -> None:
            if idx is None:
                spans.append((start, end))
                return
            if not (start < len(idx) and end - 1 < len(idx)):
                return
            lo, hi = idx[start], idx[end - 1] + 1
            # A raw match is exact. A deobfuscated one is a reconstruction, so
            # it must not displace or truncate a raw span covering the same
            # text: minimizing a reconstruction to its shortest accepted prefix
            # is right when it would otherwise run through following words, and
            # wrong when the raw match already had the true extent.
            if any(a < hi and lo < b for a, b in raw_spans):
                return
            # sk[-_][A-Za-z0-9]{20,} is greedy, and on a whitespace-merged form
            # it runs straight through the words that followed the credential.
            # Mapping that back to a bounding range made marker substitution
            # delete the rest of the sentence. A real obfuscated credential
            # carries a few inserted separators, not fifty.
            if (hi - lo) - (end - start) > _MAX_OBFUSCATION_SLACK:
                return
            spans.append((lo, hi))

        for pattern, _label in _SECRET_PATTERNS:
            for m in pattern.finditer(form):
                end = m.end()
                if idx is not None:
                    # On a merged form a quantifier like {20,} keeps consuming
                    # through the words that followed the credential, so the
                    # mapped span swallows them. Shrink to the shortest prefix
                    # the same pattern still accepts: that is the credential
                    # itself, and everything after it is ordinary text.
                    for candidate in range(m.start() + 1, m.end() + 1):
                        if pattern.fullmatch(form, m.start(), candidate):
                            end = candidate
                            break
                _record(m.start(), end)
        for m in re.finditer(r"[A-Za-z0-9+/\-_]{20,}", form):
            token = m.group()
            # On a whitespace-merged form, only tokens containing a digit are
            # candidates. Without this a natural-language sentence, whose words
            # merge into one long alphabetic run, exceeds the entropy threshold.
            # _scan_secrets applies the same guard for the same reason.
            if merged and not any(c.isdigit() for c in token):
                continue
            entropy = _shannon_entropy(token)
            threshold = min(_ENTROPY_THRESHOLD, math.log2(len(token)) - _ENTROPY_LENGTH_MARGIN)
            if entropy >= threshold:
                _record(m.start(), m.end())
                continue
            if len(token) % 2 == 0 and _HEX_RE.fullmatch(token):
                try:
                    if _shannon_entropy_bytes(bytes.fromhex(token)) >= _ENTROPY_THRESHOLD:
                        _record(m.start(), m.end())
                except ValueError:
                    pass

    _collect(text, None)
    raw_spans = list(spans)
    stripped, stripped_idx = _strip_with_offsets(text, "\u200b\u200c\u200d\u2060\ufeff")
    if stripped != text:
        _collect(stripped, stripped_idx)
    ws_removed, ws_idx = _strip_with_offsets(stripped, None)
    if ws_removed != stripped:
        _collect(ws_removed, [stripped_idx[i] for i in ws_idx], merged=True)

    # Mask what we located and rerun the full scanner. Anything it still finds
    # has no faithful span even after the offset mapping, so the caller must
    # refuse rather than emit content still carrying it.
    # Prefer the narrowest span covering each credential. A greedy pattern on
    # a whitespace-merged form matches straight through the words that followed
    # the credential, so its mapped-back span is a superset of the raw match,
    # and substituting it deleted the rest of the sentence. Dropping any span
    # that strictly contains another keeps the tight one regardless of which
    # pass produced it.
    unique = sorted(set(spans))
    minimal = [
        (a, b)
        for a, b in unique
        if not any((c, d) != (a, b) and a <= c and d <= b for c, d in unique)
    ]

    masked = text
    for start, end in sorted(minimal, reverse=True):
        masked = masked[:start] + " " * (end - start) + masked[end:]
    return minimal, _scan_secrets(masked)


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
    # header) still match the raw `text`, so scan every form and union hits.
    stripped = strip_invisibles(text)
    ws_removed = _WHITESPACE_RE.sub("", stripped)
    forms = [text]
    for form in (stripped, ws_removed):
        if form not in forms:
            forms.append(form)

    for pattern, label in _SECRET_PATTERNS:
        if label not in found and any(pattern.search(form) for form in forms):
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
