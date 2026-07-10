"""Normalization contract for overlap computation (spec §8).

Six-step pipeline producing canonical text for DLP overlap checks,
provenance comparison, and other content matching operations.

Includes Unicode TR39 confusable normalization to defeat homoglyph
substitution attacks (e.g. Cyrillic 'a' -> Latin 'a').
"""

from __future__ import annotations

import re
import secrets
import unicodedata
import warnings

# Zero-width and invisible characters (spec §1.2)
_INVISIBLE_RE = re.compile(
    "["
    "\u00ad"  # Soft hyphen
    "\u200b-\u200d"  # Zero-width space/non-joiner/joiner
    "\u2060"  # Word joiner
    "\ufeff"  # BOM / zero-width no-break space
    "\ufffc"  # Object replacement character
    "\ufff9-\ufffb"  # Interlinear annotation markers
    "]",
    flags=re.UNICODE,
)

# Tag characters (invisible metadata plane)
_TAG_CHAR_RE = re.compile(r"[\U000E0001-\U000E007F]")

# Bidi controls
_BIDI_RE = re.compile(
    "["
    "\u202a-\u202e"  # LRE, RLE, PDF, LRO, RLO
    "\u2066-\u2069"  # LRI, RLI, FSI, PDI
    "]"
)

# Whitespace collapse: runs of any whitespace -> single space
_WHITESPACE_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Unicode TR39 confusable normalization
# ---------------------------------------------------------------------------


def _build_confusable_table() -> dict[int, str]:
    """Build a translation table mapping non-ASCII confusables to ASCII.

    Uses the confusables library (Unicode TR39 data) to map each non-ASCII
    character that has an ASCII visual equivalent to that ASCII form.
    Prefers lowercase ASCII mappings where available.
    """
    try:
        from confusables import CONFUSABLE_MAP
    except ImportError:
        # `confusables` is a declared runtime dependency. If it is missing,
        # homoglyph normalization silently degrades to a no-op, which would
        # reopen the TR39 confusable-substitution bypass. Fail loud rather
        # than fail silent so operators notice the defense is disabled.
        warnings.warn(
            "guardllm: the 'confusables' package is not installed, so TR39 "
            "homoglyph normalization is DISABLED. Homoglyph-substitution "
            "attacks (e.g. Cyrillic 'a' -> Latin 'a') will pass through "
            "un-normalized. Reinstall guardllm with its declared "
            "dependencies to restore this defense.",
            RuntimeWarning,
            stacklevel=2,
        )
        return {}

    table: dict[int, str] = {}
    for char, confusables_list in CONFUSABLE_MAP.items():
        if len(char) != 1 or ord(char) < 128:
            continue
        lower_ascii = None
        upper_ascii = None
        any_ascii = None
        for c in confusables_list:
            if len(c) == 1 and ord(c) < 128:
                if c.islower():
                    lower_ascii = c
                elif c.isupper():
                    upper_ascii = c
                else:
                    any_ascii = c
        best = lower_ascii or upper_ascii or any_ascii
        if best:
            table[ord(char)] = best
    return table


# Built once at import time (2252 mappings from TR39 data)
_CONFUSABLE_TABLE: dict[int, str] = _build_confusable_table()


def _char_script(ch: str) -> str | None:
    """Best-effort Unicode script of a letter, from its character name.

    Returns e.g. "LATIN", "CYRILLIC", "GREEK", or None for non-letters
    (digits, punctuation, whitespace are script-neutral and ignored).
    """
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    return name.split(" ", 1)[0]


def normalize_confusables(text: str) -> str:
    """Map homoglyph characters to their ASCII canonical forms.

    Applies NFC normalization, then maps TR39 confusable characters to ASCII
    equivalents, but only within a mixed-script letter run -- the signature of
    a homoglyph-substitution attack (e.g. Cyrillic U+0430 spliced into an
    otherwise-Latin "b_nk" -> "bank"). Pure-script runs are left untouched, so
    legitimate international text ("Małgorzata", "mystères") is preserved
    rather than being flattened to ASCII.

    This is the preserving normalizer applied to content that flows onward to
    the model/user. Internal comparison/scanning normalizers
    (``normalize_for_overlap``, ``strip_invisibles``) remain aggressive.
    """
    text = unicodedata.normalize("NFC", text)
    if not _CONFUSABLE_TABLE:
        return text

    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isalpha():
            j = i
            while j < n and text[j].isalpha():
                j += 1
            run = text[i:j]
            scripts = {s for s in map(_char_script, run) if s is not None}
            out.append(run.translate(_CONFUSABLE_TABLE) if len(scripts) > 1 else run)
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def strip_invisibles(text: str) -> str:
    """Remove zero-width, tag-plane, and bidi control characters.

    Applies NFC and TR39 confusable mapping first (so homoglyph and
    compatibility forms collapse toward ASCII), then deletes the invisible
    characters an attacker can insert mid-token to split a keyword or secret
    and evade a pattern scan.

    Unlike normalize_for_overlap(), this preserves case and whitespace
    structure, so it is safe to run just before regex/keyword scans that
    rely on word boundaries (injection detection, secret scanning).
    """
    text = unicodedata.normalize("NFC", text)
    if _CONFUSABLE_TABLE:
        text = text.translate(_CONFUSABLE_TABLE)
    text = _INVISIBLE_RE.sub("", text)
    text = _TAG_CHAR_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    return text


def normalize_for_overlap(text: str) -> str:
    """Apply the 6-step normalization pipeline.

    Steps:
    1. Unicode NFC normalization
    2. TR39 confusable normalization (homoglyph -> ASCII)
    3. Strip invisible characters (zero-width, directional, tags)
    4. Collapse whitespace (all runs -> single space, trim)
    5. Lowercase
    6. Strip bidi controls

    The result is suitable for overlap comparison (DLP, provenance).
    This function is idempotent: normalize(normalize(x)) == normalize(x).
    """
    # Step 1: NFC
    text = unicodedata.normalize("NFC", text)

    # Step 2: TR39 confusable normalization
    if _CONFUSABLE_TABLE:
        text = text.translate(_CONFUSABLE_TABLE)

    # Step 3: Strip invisible characters
    text = _INVISIBLE_RE.sub("", text)
    text = _TAG_CHAR_RE.sub("", text)

    # Step 4: Collapse whitespace
    text = _WHITESPACE_RE.sub(" ", text).strip()

    # Step 5: Lowercase
    text = text.lower()

    # Step 6: Strip bidi controls
    text = _BIDI_RE.sub("", text)

    # Re-collapse whitespace after bidi removal (ensures idempotency)
    text = _WHITESPACE_RE.sub(" ", text).strip()

    return text


# ---------------------------------------------------------------------------
# Shared overlap computation utilities (used by DLP and provenance)
# ---------------------------------------------------------------------------

# Hard cap on the number of characters compared by the O(m*n) LCS routine.
# Callers should also cap ingested/outbound content, but this is a defense-in-
# depth bound so a single comparison can never exceed MAX_OVERLAP_CHARS**2
# work regardless of caller. 50k is far above any legitimate span of text that
# needs verbatim-overlap detection (thresholds are 12-50 chars).
MAX_OVERLAP_CHARS = 50_000


# Polynomial rolling-hash parameters. The base is randomized per process so an
# attacker cannot craft hash collisions to degrade the search; correctness does
# not depend on it (candidate matches are verified by direct comparison).
_LCS_HASH_MOD = (1 << 61) - 1  # Mersenne prime
_LCS_HASH_BASE = secrets.randbelow(1 << 30) + 257


def _has_common_substring(a: str, b: str, length: int) -> bool:
    """Whether a and b share a common substring of exactly ``length`` chars.

    Rabin-Karp: hash every window of ``a``, then scan ``b``'s windows; each hash
    hit is verified by direct string comparison so the result is exact. O(m+n).
    """
    if length == 0:
        return True
    if length > len(a) or length > len(b):
        return False
    base, mod = _LCS_HASH_BASE, _LCS_HASH_MOD
    high = pow(base, length - 1, mod)

    windows: dict[int, list[int]] = {}
    h = 0
    for i in range(length):
        h = (h * base + ord(a[i])) % mod
    windows.setdefault(h, []).append(0)
    for i in range(1, len(a) - length + 1):
        h = ((h - ord(a[i - 1]) * high) * base + ord(a[i + length - 1])) % mod
        windows.setdefault(h, []).append(i)

    hb = 0
    for i in range(length):
        hb = (hb * base + ord(b[i])) % mod

    def _match(bi: int, hb: int) -> bool:
        if hb not in windows:
            return False
        sub = b[bi : bi + length]
        return any(a[ai : ai + length] == sub for ai in windows[hb])

    if _match(0, hb):
        return True
    for i in range(1, len(b) - length + 1):
        hb = ((hb - ord(b[i - 1]) * high) * base + ord(b[i + length - 1])) % mod
        if _match(i, hb):
            return True
    return False


def compute_lcs_length(a: str, b: str) -> int:
    """Compute longest common substring length.

    Binary search on the length, testing each candidate with a Rabin-Karp
    common-substring check, giving O((m+n)*log(min(m,n))) time -- a bounded
    replacement for the naive O(m*n) DP that a large adversarial input could
    otherwise use to exhaust CPU. Results are exact (hash hits are verified).
    Inputs should be pre-normalized via normalize_for_overlap(); each operand
    is truncated to MAX_OVERLAP_CHARS as a memory bound.
    """
    if not a or not b:
        return 0
    if len(a) > MAX_OVERLAP_CHARS:
        a = a[:MAX_OVERLAP_CHARS]
    if len(b) > MAX_OVERLAP_CHARS:
        b = b[:MAX_OVERLAP_CHARS]
    lo, hi, best = 1, min(len(a), len(b)), 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if _has_common_substring(a, b, mid):
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def compute_ngram_overlap(a: str, b: str, n: int = 5) -> float:
    """Compute character-level n-gram overlap ratio.

    Returns the fraction of b's n-grams found in a. Inputs should be
    pre-normalized via normalize_for_overlap() before calling.

    Args:
        a: The content being checked (e.g. outbound text).
        b: The reference text (e.g. untrusted span).
        n: N-gram size (default 5).

    Returns:
        Overlap ratio in [0.0, 1.0]. Returns 0.0 if either string
        is shorter than n characters.
    """
    if len(b) < n or len(a) < n:
        return 0.0
    b_grams = {b[i : i + n] for i in range(len(b) - n + 1)}
    a_grams = {a[i : i + n] for i in range(len(a) - n + 1)}
    if not b_grams:
        return 0.0
    overlap = b_grams & a_grams
    return len(overlap) / len(b_grams)


# ---------------------------------------------------------------------------
# Deobfuscation helpers (reversed text, spelled-out characters)
# ---------------------------------------------------------------------------


def deobfuscate_reversed(text: str) -> str:
    """Reverse the entire string to detect reversed-text exfiltration."""
    return text[::-1]


_SPELLED_SEPARATORS = ["-", " ", ".", ",", "|", "/", ":", ";"]


def deobfuscate_spelled(text: str) -> str:
    """Collapse spelled-out sequences like 's-t-r-i-p-e' to 'stripe'.

    For each common separator, finds runs of single non-separator characters
    separated by that delimiter (minimum 4 characters) and collapses them.
    """
    for sep in _SPELLED_SEPARATORS:
        esc = re.escape(sep)
        char = f"[^{esc}\\s]" if sep != " " else r"\S"
        pattern = re.compile(f"({char}){esc}(?:{char}{esc}){{2,}}{char}")
        text = pattern.sub(lambda m, s=sep: m.group(0).replace(s, ""), text)
    return text


# Regex for stripping separator characters inserted between token chunks
_SEPARATOR_STRIP_RE = re.compile(r"[\s\-_./,;:|]+")


def deobfuscate_separated(text: str) -> str:
    """Strip inserted separators to recover the original token.

    Catches evasion where a secret like ``sk_abcdef1234`` is split into
    ``sk_ abc def 123 4`` by inserting spaces, hyphens, or underscores
    every few characters.  Stripping all common separator characters
    produces ``skabcdef1234`` which can then be matched via LCS against
    the original.
    """
    return _SEPARATOR_STRIP_RE.sub("", text)
