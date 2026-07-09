"""Tests for MCP security normalization: the 5-step pipeline.

Covers:
- Step 1: NFC normalization (composed vs decomposed forms)
- Step 2: Invisible chars stripped (zero-width, soft hyphen, directional overrides)
- Step 3: Whitespace collapsed (multiple spaces, tabs, newlines -> single space)
- Step 4: Lowercase applied
- Step 5: Bidi controls stripped
- Idempotency: normalize(normalize(x)) == normalize(x)
- Empty string, simple string unchanged
"""

import pytest

from guardllm.security.normalization import (
    _CONFUSABLE_TABLE,
    _build_confusable_table,
    compute_lcs_length,
    compute_ngram_overlap,
    normalize_confusables,
    normalize_for_overlap,
    strip_invisibles,
)


class TestNFCNormalization:
    """Step 1: Unicode NFC normalization."""

    def test_composed_vs_decomposed_e_acute(self):
        """NFC normalizes decomposed e-acute to composed form."""
        # Decomposed: e + combining acute accent
        decomposed = "caf\u0065\u0301"
        # Composed: single character e-with-acute
        composed = "caf\u00e9"
        result = normalize_for_overlap(decomposed)
        # Both should produce the same normalized output (lowercased)
        assert result == normalize_for_overlap(composed)

    def test_nfc_idempotent(self):
        """NFC on already-NFC text is a no-op."""
        text = "hello world"
        assert normalize_for_overlap(text) == "hello world"

    def test_nfc_with_combining_characters(self):
        """Multiple combining characters normalize correctly."""
        # a + combining tilde = a-with-tilde
        decomposed = "man\u0303ana"
        result = normalize_for_overlap(decomposed)
        expected = normalize_for_overlap("ma\u00f1ana")
        assert result == expected


class TestInvisibleCharStripping:
    """Step 2: Invisible characters removed."""

    def test_zero_width_space_stripped(self):
        """Zero-width space (U+200B) is removed."""
        text = "hello\u200bworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_zero_width_non_joiner_stripped(self):
        """Zero-width non-joiner (U+200C) is removed."""
        text = "hello\u200cworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_zero_width_joiner_stripped(self):
        """Zero-width joiner (U+200D) is removed."""
        text = "hello\u200dworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_soft_hyphen_stripped(self):
        """Soft hyphen (U+00AD) is removed."""
        text = "dis\u00adplay"
        assert normalize_for_overlap(text) == "display"

    def test_word_joiner_stripped(self):
        """Word joiner (U+2060) is removed."""
        text = "some\u2060text"
        assert normalize_for_overlap(text) == "sometext"

    def test_bom_stripped(self):
        """BOM / zero-width no-break space (U+FEFF) is removed."""
        text = "\ufeffhello"
        assert normalize_for_overlap(text) == "hello"

    def test_object_replacement_stripped(self):
        """Object replacement character (U+FFFC) is removed."""
        text = "before\ufffcafter"
        assert normalize_for_overlap(text) == "beforeafter"

    def test_interlinear_annotation_stripped(self):
        """Interlinear annotation markers (U+FFF9-U+FFFB) are removed."""
        text = "text\ufff9annotation\ufffainterlinear\ufffbmore"
        assert normalize_for_overlap(text) == "textannotationinterlinearmore"

    def test_tag_characters_stripped(self):
        """Tag characters (U+E0001-U+E007F) are removed."""
        text = "hello\U000e0001\U000e0041\U000e007fworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_multiple_invisible_chars_in_sequence(self):
        """Multiple different invisible chars all stripped."""
        text = "a\u200b\u200c\u200d\u00ad\u2060\ufeffb"
        assert normalize_for_overlap(text) == "ab"


class TestWhitespaceCollapse:
    """Step 3: Whitespace collapsed to single space, trimmed."""

    def test_multiple_spaces_collapsed(self):
        """Multiple spaces become a single space."""
        text = "hello    world"
        assert normalize_for_overlap(text) == "hello world"

    def test_tabs_collapsed(self):
        """Tabs are collapsed to single space."""
        text = "hello\t\tworld"
        assert normalize_for_overlap(text) == "hello world"

    def test_newlines_collapsed(self):
        """Newlines are collapsed to single space."""
        text = "hello\n\nworld"
        assert normalize_for_overlap(text) == "hello world"

    def test_mixed_whitespace_collapsed(self):
        """Mixed whitespace types all collapse to single space."""
        text = "hello \t \n \r world"
        assert normalize_for_overlap(text) == "hello world"

    def test_leading_trailing_whitespace_trimmed(self):
        """Leading and trailing whitespace is trimmed."""
        text = "  hello world  "
        assert normalize_for_overlap(text) == "hello world"

    def test_only_whitespace_becomes_empty(self):
        """Whitespace-only string becomes empty."""
        text = "   \t  \n  "
        assert normalize_for_overlap(text) == ""


class TestLowercase:
    """Step 4: Lowercase applied."""

    def test_uppercase_lowered(self):
        """All-uppercase text is lowered."""
        assert normalize_for_overlap("HELLO WORLD") == "hello world"

    def test_mixed_case_lowered(self):
        """Mixed case text is lowered."""
        assert normalize_for_overlap("Hello World") == "hello world"

    def test_already_lowercase_unchanged(self):
        """Already-lowercase text is unchanged."""
        assert normalize_for_overlap("hello") == "hello"


class TestBidiControlStripping:
    """Step 5: Bidi controls removed."""

    def test_lre_stripped(self):
        """Left-to-Right Embedding (U+202A) is removed."""
        text = "hello\u202aworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_rle_stripped(self):
        """Right-to-Left Embedding (U+202B) is removed."""
        text = "hello\u202bworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_pdf_stripped(self):
        """Pop Directional Formatting (U+202C) is removed."""
        text = "hello\u202cworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_lro_stripped(self):
        """Left-to-Right Override (U+202D) is removed."""
        text = "hello\u202dworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_rlo_stripped(self):
        """Right-to-Left Override (U+202E) is removed."""
        text = "hello\u202eworld"
        assert normalize_for_overlap(text) == "helloworld"

    def test_lri_stripped(self):
        """Left-to-Right Isolate (U+2066) is removed."""
        text = "hello\u2066world"
        assert normalize_for_overlap(text) == "helloworld"

    def test_rli_stripped(self):
        """Right-to-Left Isolate (U+2067) is removed."""
        text = "hello\u2067world"
        assert normalize_for_overlap(text) == "helloworld"

    def test_fsi_stripped(self):
        """First Strong Isolate (U+2068) is removed."""
        text = "hello\u2068world"
        assert normalize_for_overlap(text) == "helloworld"

    def test_pdi_stripped(self):
        """Pop Directional Isolate (U+2069) is removed."""
        text = "hello\u2069world"
        assert normalize_for_overlap(text) == "helloworld"

    def test_all_bidi_controls_stripped(self):
        """All bidi controls removed from a single string."""
        text = "\u202ahello\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069world"
        assert normalize_for_overlap(text) == "helloworld"


class TestIdempotency:
    """normalize(normalize(x)) == normalize(x) for all inputs."""

    @pytest.mark.parametrize(
        "text",
        [
            "Hello World",
            "caf\u0065\u0301",
            "hello\u200b\u200cworld",
            "  multiple   spaces  ",
            "\u202aHello\u202e World\u2069",
            "MiXeD CaSe with\ttabs\nand\nnewlines",
            "",
            "simple",
            "a\u200b\u00ad\ufeff\u2060b\u202ac\u202ed",
        ],
    )
    def test_idempotent(self, text: str):
        """Double normalization produces the same result as single."""
        once = normalize_for_overlap(text)
        twice = normalize_for_overlap(once)
        assert once == twice


class TestEdgeCases:
    """Edge cases and simple inputs."""

    def test_empty_string(self):
        """Empty string returns empty string."""
        assert normalize_for_overlap("") == ""

    def test_simple_string_unchanged(self):
        """Plain lowercase ASCII string is returned unchanged."""
        assert normalize_for_overlap("hello world") == "hello world"

    def test_numbers_preserved(self):
        """Numbers are not affected by normalization."""
        assert normalize_for_overlap("test 123 456") == "test 123 456"

    def test_punctuation_preserved(self):
        """Punctuation is preserved."""
        assert normalize_for_overlap("Hello, World!") == "hello, world!"

    def test_full_pipeline_combined(self):
        """All steps work together on a complex input."""
        # Decomposed e-acute + zero-width space + multiple spaces + uppercase + bidi
        text = "CAFI\u0301\u200b  \u202a LATTE"
        result = normalize_for_overlap(text)
        # NFC: I + combining accent -> I-acute (lowercased to i-acute)
        # Zero-width stripped, spaces collapsed, lowercased, bidi stripped
        expected = normalize_for_overlap("caf\u00ed latte")
        assert result == expected


# ---------------------------------------------------------------------------
# Golden fixture tests for shared overlap utilities
# ---------------------------------------------------------------------------

# Each tuple: (candidate, untrusted, expected_lcs, expected_ngram)
_GOLDEN_FIXTURES = [
    # Full substring match: all n-grams of "the quick brown fox" in content
    (
        "the quick brown fox jumps over the lazy dog",
        "the quick brown fox",
        19,
        1.0,
    ),
    # Zero overlap: completely disjoint strings
    (
        "hello world this is a test",
        "completely different text here now",
        3,
        0.0,
    ),
    # Identical strings: perfect overlap
    (
        "the secret password is hunter2",
        "the secret password is hunter2",
        30,
        1.0,
    ),
    # Partial overlap: shared "at three pm in the " substring
    (
        "the meeting is at three pm in the conference room",
        "the party starts at three pm in the garden area",
        21,
        0.395349,
    ),
    # Near-zero overlap: very short common substring
    (
        "pack my box with five dozen liquor jugs",
        "how quickly daft jumping zebras vex",
        3,
        0.0,
    ),
    # Short string below n-gram threshold: n-gram returns 0.0
    (
        "hi",
        "hi",
        2,
        0.0,
    ),
]


class TestComputeLcsLength:
    """Golden fixture tests for compute_lcs_length."""

    @pytest.mark.parametrize(
        "candidate,untrusted,expected_lcs,_ngram",
        _GOLDEN_FIXTURES,
        ids=[f"pair-{i}" for i in range(len(_GOLDEN_FIXTURES))],
    )
    def test_golden_lcs(self, candidate, untrusted, expected_lcs, _ngram):
        a = normalize_for_overlap(candidate)
        b = normalize_for_overlap(untrusted)
        assert compute_lcs_length(a, b) == expected_lcs

    def test_empty_inputs(self):
        assert compute_lcs_length("", "abc") == 0
        assert compute_lcs_length("abc", "") == 0
        assert compute_lcs_length("", "") == 0

    def test_symmetric(self):
        a = "the quick brown fox"
        b = "quick brown"
        assert compute_lcs_length(a, b) == compute_lcs_length(b, a)


class TestComputeNgramOverlap:
    """Golden fixture tests for compute_ngram_overlap."""

    @pytest.mark.parametrize(
        "candidate,untrusted,_lcs,expected_ngram",
        _GOLDEN_FIXTURES,
        ids=[f"pair-{i}" for i in range(len(_GOLDEN_FIXTURES))],
    )
    def test_golden_ngram(self, candidate, untrusted, _lcs, expected_ngram):
        a = normalize_for_overlap(candidate)
        b = normalize_for_overlap(untrusted)
        result = compute_ngram_overlap(a, b)
        assert abs(result - expected_ngram) < 0.001, (
            f"Expected {expected_ngram:.4f}, got {result:.4f}"
        )

    def test_empty_inputs(self):
        assert compute_ngram_overlap("", "abcdef") == 0.0
        assert compute_ngram_overlap("abcdef", "") == 0.0

    def test_identical_long_string(self):
        text = "a" * 100
        assert compute_ngram_overlap(text, text) == 1.0

    def test_custom_n(self):
        a = "abcdefghij"
        b = "abcdefghij"
        assert compute_ngram_overlap(a, b, n=3) == 1.0
        assert compute_ngram_overlap(a, b, n=10) == 1.0


# ---------------------------------------------------------------------------
# C2 regression: TR39 homoglyph normalization must stay active
# ---------------------------------------------------------------------------


class TestConfusableNormalization:
    """The `confusables` dependency must be installed and homoglyph
    normalization must actively map non-ASCII confusables to ASCII.

    These tests fail if the dependency is dropped or the mapping degrades
    to a no-op, which would reopen the homoglyph-substitution bypass
    (e.g. Cyrillic 'a' U+0430 -> Latin 'a').
    """

    def test_confusable_table_is_populated(self):
        """A populated table proves the TR39 data is actually loaded."""
        assert len(_CONFUSABLE_TABLE) > 1000

    def test_cyrillic_i_mapped_to_ascii(self):
        # Cyrillic small letter i (U+0456) is a visual twin of Latin 'i'
        assert normalize_confusables("іgnore") == "ignore"

    def test_cyrillic_a_mapped_to_ascii(self):
        # Cyrillic small letter a (U+0430) is a visual twin of Latin 'a'
        assert normalize_confusables("bаnk") == "bank"

    def test_homoglyph_normalized_in_overlap_pipeline(self):
        """normalize_for_overlap must also apply confusable mapping."""
        assert normalize_for_overlap("іgnore") == "ignore"

    def test_missing_confusables_fails_loud_not_silent(self):
        """If the dependency is absent, the builder must warn (fail loud)
        and return an empty table, not silently no-op without a signal."""
        import sys

        class _Blocker:
            def find_spec(self, name, path=None, target=None):
                if name == "confusables":
                    raise ImportError("blocked for test")
                return None

        blocker = _Blocker()
        sys.meta_path.insert(0, blocker)
        saved = sys.modules.pop("confusables", None)
        try:
            with pytest.warns(RuntimeWarning, match="homoglyph"):
                table = _build_confusable_table()
            assert table == {}
        finally:
            sys.meta_path.remove(blocker)
            if saved is not None:
                sys.modules["confusables"] = saved


class TestStripInvisibles:
    """strip_invisibles(): shared primitive for the always-on gates.

    Unlike normalize_for_overlap it preserves case and whitespace, so it
    is safe ahead of word-boundary regex scans (C1/C3 fixes).
    """

    def test_zero_width_stripped(self):
        assert strip_invisibles("ig​nore") == "ignore"

    def test_soft_hyphen_stripped(self):
        assert strip_invisibles("ig­nore") == "ignore"

    def test_bidi_stripped(self):
        assert strip_invisibles("ig‮nore") == "ignore"

    def test_case_and_whitespace_preserved(self):
        # Distinguishes strip_invisibles from normalize_for_overlap.
        assert strip_invisibles("Ig​Nore  Me") == "IgNore  Me"

    def test_confusable_mapped(self):
        assert strip_invisibles("іgnore") == "ignore"
