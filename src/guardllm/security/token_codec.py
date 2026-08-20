"""L13 token codec: Crockford base32 over an RS(15,12) code in GF(2^5).

A privacy-vault token carries a random payload so it cannot be guessed, and
error-correction redundancy so ordinary model mangling is recoverable rather
than indistinguishable from a forgery.

Two properties this module must hold, both tested:

1. **Correct one symbol, refuse two.** RS(15,12) over GF(2^5) is MDS, so its
   minimum distance is ``d = n - k + 1 = 4``. Correcting ``t`` symbols while
   detecting ``s > t`` requires ``d >= t + s + 1``; for ``t = 1, s = 2`` that
   is ``d >= 4``, which this code satisfies exactly. A code with three
   symbols of redundancy is the minimum that does. RS(12,10) has ``d = 3``,
   where a two-symbol corruption can land at distance 1 from a *different*
   codeword and a bounded-distance decoder silently miscorrects to it.

2. **The parity symbols are redundancy, not integrity.** The encoder ships in
   this library, so anyone can produce a structurally valid codeword. Nothing
   about a token proves it was issued. Only the vault's issued-set lookup
   does that. Security against forgery comes from payload entropy (see
   ``PAYLOAD_SYMBOLS``), never from the code.

Crockford base32 is the alphabet because it absorbs the most common model
mangling for free, before any correction budget is spent: it decodes
case-insensitively and maps ``I``/``l``/``L`` to ``1`` and ``O``/``o`` to
``0``. https://www.crockford.com/base32.html
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Crockford base32
# ---------------------------------------------------------------------------

#: Excludes I, L, O, U. I/L/O are visually confusable with 1/0; U is excluded
#: by the specification to avoid accidental obscenity.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

_DECODE_MAP: dict[str, int] = {ch: i for i, ch in enumerate(_ALPHABET)}
_DECODE_MAP.update({ch.lower(): i for i, ch in enumerate(_ALPHABET)})
# Confusable folding, per the Crockford spec.
for _c in "IiLl":
    _DECODE_MAP[_c] = 1
for _c in "Oo":
    _DECODE_MAP[_c] = 0


def symbol_to_char(sym: int) -> str:
    """Map a GF(32) symbol to its Crockford character."""
    return _ALPHABET[sym]


def char_to_symbol(ch: str) -> int | None:
    """Map a character to a GF(32) symbol, folding confusables. None if invalid."""
    return _DECODE_MAP.get(ch)


# ---------------------------------------------------------------------------
# GF(2^5) arithmetic
# ---------------------------------------------------------------------------

#: x^5 + x^2 + 1, primitive over GF(2).
_GF_POLY = 0b100101
_GF_ORDER = 32
_GF_MAX = _GF_ORDER - 1  # 31 nonzero elements


def _build_tables() -> tuple[list[int], list[int]]:
    exp = [0] * (2 * _GF_MAX)
    log = [0] * _GF_ORDER
    x = 1
    for i in range(_GF_MAX):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & _GF_ORDER:
            x ^= _GF_POLY
    for i in range(_GF_MAX, 2 * _GF_MAX):
        exp[i] = exp[i - _GF_MAX]
    return exp, log


_EXP, _LOG = _build_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(32) division by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % _GF_MAX]


def _pow_alpha(i: int) -> int:
    """Return alpha^i for any integer i."""
    return _EXP[i % _GF_MAX]


# ---------------------------------------------------------------------------
# RS(15,12) parameters
# ---------------------------------------------------------------------------

CODEWORD_SYMBOLS = 15
PARITY_SYMBOLS = 3
PAYLOAD_SYMBOLS = CODEWORD_SYMBOLS - PARITY_SYMBOLS  # 12 symbols = 60 bits

#: Bits of entropy in the payload. The forgery bound is driven entirely by this
#: and by the live vault size N: per-attempt success is approximately
#: N / 2^PAYLOAD_BITS. Raising vault capacity without raising this degrades the
#: bound, so the two are coupled and PrivacyConfig documents the relationship.
PAYLOAD_BITS = PAYLOAD_SYMBOLS * 5  # 60


# Generator polynomial g(x) = (x - a^1)(x - a^2)(x - a^3), coefficients high to low.
def _build_generator() -> list[int]:
    g = [1]
    for j in range(1, PARITY_SYMBOLS + 1):
        root = _pow_alpha(j)
        new = [0] * (len(g) + 1)
        for i, c in enumerate(g):
            new[i] ^= c
            new[i + 1] ^= _mul(c, root)
        g = new
    return g


_GENERATOR = _build_generator()


def _poly_eval(poly: list[int], x: int) -> int:
    """Horner evaluation. poly[0] is the highest-degree coefficient."""
    y = poly[0]
    for coeff in poly[1:]:
        y = _mul(y, x) ^ coeff
    return y


def encode(payload: list[int]) -> list[int]:
    """Systematically encode 12 payload symbols into a 15-symbol codeword."""
    if len(payload) != PAYLOAD_SYMBOLS:
        raise ValueError(f"payload must be {PAYLOAD_SYMBOLS} symbols, got {len(payload)}")
    # Multiply by x^PARITY_SYMBOLS, then take the remainder mod g(x).
    remainder = list(payload) + [0] * PARITY_SYMBOLS
    for i in range(PAYLOAD_SYMBOLS):
        coeff = remainder[i]
        if coeff == 0:
            continue
        for j, gc in enumerate(_GENERATOR):
            remainder[i + j] ^= _mul(gc, coeff)
    return list(payload) + remainder[PAYLOAD_SYMBOLS:]


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

#: Decode outcomes. These are observable properties of the received string,
#: never claims about intent: a string inside the correction radius of an
#: issued codeword resolves whether it was innocently damaged or deliberately
#: crafted. The vault's issued-set lookup, not this module, decides what a
#: resolved payload means.
EXACT = "exact"
CORRECTED = "corrected"
UNCORRECTABLE = "uncorrectable"
MALFORMED = "malformed"


@dataclass(frozen=True)
class DecodeResult:
    """Outcome of decoding one candidate token body."""

    status: str
    payload: tuple[int, ...] | None = None
    corrected_position: int | None = None

    @property
    def ok(self) -> bool:
        return self.status in (EXACT, CORRECTED)


def _syndromes(codeword: list[int]) -> list[int]:
    return [_poly_eval(codeword, _pow_alpha(j)) for j in range(1, PARITY_SYMBOLS + 1)]


def decode(symbols: list[int]) -> DecodeResult:
    """Decode a 15-symbol codeword, correcting at most one symbol.

    Returns ``UNCORRECTABLE`` for anything beyond a single-symbol error. That
    includes every two-symbol corruption: because ``d = 4``, a two-symbol error
    cannot land inside the radius-1 ball of another codeword, so the syndrome
    consistency check below detects it rather than miscorrecting.
    """
    if len(symbols) != CODEWORD_SYMBOLS:
        return DecodeResult(MALFORMED)

    s1, s2, s3 = _syndromes(symbols)
    if s1 == 0 and s2 == 0 and s3 == 0:
        return DecodeResult(EXACT, tuple(symbols[:PAYLOAD_SYMBOLS]))

    # A single error of magnitude e at power position p satisfies
    #   S1 = e*a^p,  S2 = e*a^2p,  S3 = e*a^3p
    # which forces S2^2 == S1*S3. Any received word failing that carries at
    # least two symbol errors and must be refused, not guessed at.
    if s1 == 0 or s2 == 0:
        return DecodeResult(UNCORRECTABLE)
    if _mul(s2, s2) != _mul(s1, s3):
        return DecodeResult(UNCORRECTABLE)

    ratio = _div(s2, s1)  # a^p
    p = _LOG[ratio]
    # p is the exponent of x at the error site; array index counts from the
    # highest-degree coefficient, so index = n - 1 - p.
    index = CODEWORD_SYMBOLS - 1 - p
    if not (0 <= index < CODEWORD_SYMBOLS):
        return DecodeResult(UNCORRECTABLE)

    magnitude = _div(_mul(s1, s1), s2)  # e = S1^2 / S2
    if magnitude == 0:
        return DecodeResult(UNCORRECTABLE)

    fixed = list(symbols)
    fixed[index] ^= magnitude

    # Re-verify. A correction that does not zero every syndrome means the
    # received word was not within the correction radius after all.
    if any(_syndromes(fixed)):
        return DecodeResult(UNCORRECTABLE)

    return DecodeResult(CORRECTED, tuple(fixed[:PAYLOAD_SYMBOLS]), corrected_position=index)


# ---------------------------------------------------------------------------
# Text form
# ---------------------------------------------------------------------------


def random_payload() -> list[int]:
    """Draw PAYLOAD_SYMBOLS uniformly at random from a CSPRNG."""
    return [secrets.randbelow(_GF_ORDER) for _ in range(PAYLOAD_SYMBOLS)]


def encode_text(payload: list[int]) -> str:
    """Encode a payload and render the 15-symbol codeword as Crockford base32."""
    return "".join(symbol_to_char(s) for s in encode(payload))


def decode_text(body: str) -> DecodeResult:
    """Canonicalize a candidate token body, then decode it.

    Canonicalization absorbs the mangling that costs nothing to undo: interior
    whitespace, hyphens, case, and the I/L/O confusables. Only what survives
    that is charged against the correction budget.
    """
    cleaned = [ch for ch in body if not ch.isspace() and ch != "-"]
    if len(cleaned) != CODEWORD_SYMBOLS:
        return DecodeResult(MALFORMED)
    symbols: list[int] = []
    for ch in cleaned:
        sym = char_to_symbol(ch)
        if sym is None:
            return DecodeResult(MALFORMED)
        symbols.append(sym)
    return decode(symbols)


def payload_key(payload: tuple[int, ...] | list[int]) -> str:
    """Canonical string form of a payload, for use as a vault lookup key."""
    return "".join(symbol_to_char(s) for s in payload)
