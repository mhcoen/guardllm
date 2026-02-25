"""Normalization contract for overlap computation (spec §8).

Six-step pipeline producing canonical text for DLP overlap checks,
provenance comparison, and other content matching operations.

Includes Unicode TR39 confusable normalization to defeat homoglyph
substitution attacks (e.g. Cyrillic 'a' -> Latin 'a').
"""

from __future__ import annotations

import re
import unicodedata
from typing import Dict

# Zero-width and invisible characters (spec §1.2)
_INVISIBLE_RE = re.compile(
    "["
    "\u00AD"          # Soft hyphen
    "\u200B-\u200D"   # Zero-width space/non-joiner/joiner
    "\u2060"          # Word joiner
    "\uFEFF"          # BOM / zero-width no-break space
    "\uFFFC"          # Object replacement character
    "\uFFF9-\uFFFB"   # Interlinear annotation markers
    "]",
    flags=re.UNICODE,
)

# Tag characters (invisible metadata plane)
_TAG_CHAR_RE = re.compile(r"[\U000E0001-\U000E007F]")

# Bidi controls
_BIDI_RE = re.compile(
    "["
    "\u202A-\u202E"   # LRE, RLE, PDF, LRO, RLO
    "\u2066-\u2069"   # LRI, RLI, FSI, PDI
    "]"
)

# Whitespace collapse: runs of any whitespace -> single space
_WHITESPACE_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Unicode TR39 confusable normalization
# ---------------------------------------------------------------------------

def _build_confusable_table() -> Dict[int, str]:
    """Build a translation table mapping non-ASCII confusables to ASCII.

    Uses the confusables library (Unicode TR39 data) to map each non-ASCII
    character that has an ASCII visual equivalent to that ASCII form.
    Prefers lowercase ASCII mappings where available.
    """
    try:
        from confusables import CONFUSABLE_MAP
    except ImportError:
        return {}

    table: Dict[int, str] = {}
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
_CONFUSABLE_TABLE: Dict[int, str] = _build_confusable_table()


def normalize_confusables(text: str) -> str:
    """Map Unicode confusable characters to their ASCII canonical forms.

    Applies NFC normalization first, then maps all TR39 confusable
    characters to ASCII equivalents. This defeats homoglyph substitution
    attacks (e.g. Cyrillic U+0430 -> Latin 'a').

    This function should be called at every trust boundary before any
    security-relevant operation (tagging, entropy scan, pattern matching,
    overlap comparison).
    """
    text = unicodedata.normalize("NFC", text)
    if not _CONFUSABLE_TABLE:
        return text
    return text.translate(_CONFUSABLE_TABLE)


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


def compute_lcs_length(a: str, b: str) -> int:
    """Compute longest common substring length using rolling-row DP.

    O(m*n) time, O(min(m,n)) space. Inputs should be pre-normalized
    via normalize_for_overlap() before calling.
    """
    if not a or not b:
        return 0
    # Ensure b is the shorter string for space efficiency
    if len(a) < len(b):
        a, b = b, a
    prev = [0] * (len(b) + 1)
    best = 0
    for i in range(1, len(a) + 1):
        curr = [0] * (len(b) + 1)
        for j in range(1, len(b) + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1] + 1
                if curr[j] > best:
                    best = curr[j]
        prev = curr
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
    b_grams = {b[i:i + n] for i in range(len(b) - n + 1)}
    a_grams = {a[i:i + n] for i in range(len(a) - n + 1)}
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


_SPELLED_SEPARATORS = ['-', ' ', '.', ',', '|', '/', ':', ';']


def deobfuscate_spelled(text: str) -> str:
    """Collapse spelled-out sequences like 's-t-r-i-p-e' to 'stripe'.

    For each common separator, finds runs of single non-separator characters
    separated by that delimiter (minimum 4 characters) and collapses them.
    """
    for sep in _SPELLED_SEPARATORS:
        esc = re.escape(sep)
        char = f'[^{esc}\\s]' if sep != ' ' else r'\S'
        pattern = re.compile(f'({char}){esc}(?:{char}{esc}){{2,}}{char}')
        text = pattern.sub(lambda m, s=sep: m.group(0).replace(s, ''), text)
    return text


# Regex for stripping separator characters inserted between token chunks
_SEPARATOR_STRIP_RE = re.compile(r'[\s\-_./,;:|]+')


def deobfuscate_separated(text: str) -> str:
    """Strip inserted separators to recover the original token.

    Catches evasion where a secret like ``sk_abcdef1234`` is split into
    ``sk_ abc def 123 4`` by inserting spaces, hyphens, or underscores
    every few characters.  Stripping all common separator characters
    produces ``skabcdef1234`` which can then be matched via LCS against
    the original.
    """
    return _SEPARATOR_STRIP_RE.sub('', text)
