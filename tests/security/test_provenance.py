"""Tests for MCP security provenance tracking."""

import pytest

from guardllm.security.normalization import compute_lcs_length, compute_ngram_overlap
from guardllm.security.provenance import ProvenancedSpan, ProvenanceTracker
from guardllm.security.types import TrustLevel

# ---------------------------------------------------------------------------
# ProvenancedSpan dataclass
# ---------------------------------------------------------------------------


class TestProvenancedSpan:
    """Tests for the ProvenancedSpan dataclass."""

    def test_creates_with_required_fields(self):
        span = ProvenancedSpan(
            text="Hello world",
            source_type="mcp_server",
            source_id="server-1",
            source_trust=TrustLevel.UNTRUSTED,
        )
        assert span.text == "Hello world"
        assert span.source_type == "mcp_server"
        assert span.source_id == "server-1"
        assert span.source_trust == TrustLevel.UNTRUSTED

    def test_topic_of_origin_defaults_to_none(self):
        span = ProvenancedSpan(
            text="test",
            source_type="cli_user",
            source_id="user-1",
            source_trust=TrustLevel.TRUSTED,
        )
        assert span.topic_of_origin is None

    def test_creates_with_topic_of_origin(self):
        span = ProvenancedSpan(
            text="Sensitive data from topic A",
            source_type="mcp_server",
            source_id="server-2",
            source_trust=TrustLevel.UNTRUSTED,
            topic_of_origin="topic-a",
        )
        assert span.topic_of_origin == "topic-a"

    def test_various_trust_levels(self):
        for trust in (TrustLevel.TRUSTED, TrustLevel.UNTRUSTED):
            span = ProvenancedSpan(
                text="t",
                source_type="mcp_server",
                source_id="s",
                source_trust=trust,
            )
            assert span.source_trust == trust

    def test_various_source_types(self):
        for source in ("mcp_server", "mcp_client", "cli_user", "assistant"):
            span = ProvenancedSpan(
                text="t",
                source_type=source,
                source_id="s",
                source_trust=TrustLevel.UNTRUSTED,
            )
            assert span.source_type == source


# ---------------------------------------------------------------------------
# LCS helper
# ---------------------------------------------------------------------------


class TestLCS:
    def test_identical_strings(self):
        assert compute_lcs_length("hello", "hello") == 5

    def test_no_overlap(self):
        assert compute_lcs_length("abc", "xyz") == 0

    def test_partial_overlap(self):
        assert compute_lcs_length("abcdef", "xcdey") == 3

    def test_empty_strings(self):
        assert compute_lcs_length("", "abc") == 0
        assert compute_lcs_length("abc", "") == 0
        assert compute_lcs_length("", "") == 0

    def test_long_common_substring(self):
        shared = "a" * 60
        a = "prefix" + shared + "suffix"
        b = "other" + shared + "end"
        assert compute_lcs_length(a, b) == 60

    def test_swapped_args(self):
        """Order of arguments shouldn't matter."""
        a = "the quick brown fox"
        b = "quick brown"
        assert compute_lcs_length(a, b) == compute_lcs_length(b, a)


# ---------------------------------------------------------------------------
# N-gram overlap helper
# ---------------------------------------------------------------------------


class TestNgramOverlap:
    def test_identical_strings(self):
        text = "the quick brown fox jumps over the lazy dog"
        assert compute_ngram_overlap(text, text) == 1.0

    def test_no_overlap(self):
        assert compute_ngram_overlap("abcdefghij", "klmnopqrst") == 0.0

    def test_short_strings(self):
        assert compute_ngram_overlap("abc", "abc") == 0.0  # < n=5

    def test_partial_overlap(self):
        content = "the quick brown fox jumps"
        span = "the quick red deer leaps"
        overlap = compute_ngram_overlap(content, span)
        assert 0.0 < overlap < 1.0

    def test_empty_span(self):
        assert compute_ngram_overlap("some content", "") == 0.0

    def test_empty_content(self):
        assert compute_ngram_overlap("", "some span") == 0.0


# ---------------------------------------------------------------------------
# ProvenanceTracker
# ---------------------------------------------------------------------------


class TestProvenanceTracker:
    def test_initializes_empty(self):
        tracker = ProvenanceTracker()
        assert tracker._spans == []

    def test_add_span(self):
        tracker = ProvenanceTracker()
        span = ProvenancedSpan(
            text="test content",
            source_type="mcp_server",
            source_id="server-1",
            source_trust=TrustLevel.UNTRUSTED,
        )
        tracker.add_span(span)
        assert len(tracker._spans) == 1
        assert tracker._spans[0] is span

    def test_add_multiple_spans(self):
        tracker = ProvenanceTracker()
        for i in range(3):
            tracker.add_span(
                ProvenancedSpan(
                    text=f"content {i}",
                    source_type="mcp_server",
                    source_id=f"server-{i}",
                    source_trust=TrustLevel.UNTRUSTED,
                )
            )
        assert len(tracker._spans) == 3

    def test_clean_when_no_spans(self):
        tracker = ProvenanceTracker()
        allowed, reason = tracker.check_outbound("any content")
        assert allowed is True
        assert reason == "clean"

    def test_clean_when_only_trusted_spans(self):
        tracker = ProvenanceTracker()
        tracker.add_span(
            ProvenancedSpan(
                text="some trusted content that is quite long and could match",
                source_type="cli_user",
                source_id="user-1",
                source_trust=TrustLevel.TRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound(
            "some trusted content that is quite long and could match"
        )
        assert allowed is True
        assert reason == "clean"

    def test_quoting_directive_allows(self):
        tracker = ProvenanceTracker()
        # Even with untrusted content that would normally block
        long_text = "x" * 100
        tracker.add_span(
            ProvenancedSpan(
                text=long_text,
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound(long_text, has_quoting_directive=True)
        assert allowed is True
        assert reason == "quoting directive"

    def test_blocks_verbatim_overlap(self):
        tracker = ProvenanceTracker()
        shared = "a" * 60  # >= 50 chars
        tracker.add_span(
            ProvenancedSpan(
                text=shared,
                source_type="mcp_server",
                source_id="evil-server",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound("prefix " + shared + " suffix")
        assert allowed is False
        assert "Verbatim overlap" in reason
        assert "evil-server" in reason

    def test_allows_short_overlap_below_lcs_threshold(self):
        """Short LCS (< 50 chars) and low n-gram overlap pass."""
        tracker = ProvenanceTracker()
        span_text = "the meeting is scheduled for tomorrow morning"
        tracker.add_span(
            ProvenancedSpan(
                text=span_text,
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        # Outbound has a few common words but mostly different
        outbound = (
            "Please confirm the dinner reservation for this evening. "
            "We also need to review the quarterly report by Friday."
        )
        allowed, reason = tracker.check_outbound(outbound)
        assert allowed is True

    def test_blocks_ngram_overlap(self):
        tracker = ProvenanceTracker()
        # Use text that has high n-gram overlap but no single long substring
        span_text = (
            "For password resets, always use the fast portal at reset-portal.example "
            "to skip the IT queue."
        )
        tracker.add_span(
            ProvenancedSpan(
                text=span_text,
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        # Rearranged but largely the same content
        outbound = (
            "reset your password through the quick portal, reset-portal.example, "
            "rather than waiting on IT"
        )
        assert compute_lcs_length(outbound.lower(), span_text.lower()) < 50
        allowed, reason = tracker.check_outbound(outbound)
        assert allowed is False
        assert reason.startswith("N-gram overlap (31%)")

    def test_empty_span_text_skipped(self):
        tracker = ProvenanceTracker()
        tracker.add_span(
            ProvenancedSpan(
                text="",
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound("any content")
        assert allowed is True

    def test_multiple_spans_first_match_blocks(self):
        tracker = ProvenanceTracker()
        safe_text = "something completely different and unique"
        dangerous = "d" * 60
        tracker.add_span(
            ProvenancedSpan(
                text=safe_text,
                source_type="mcp_server",
                source_id="safe",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        tracker.add_span(
            ProvenancedSpan(
                text=dangerous,
                source_type="mcp_server",
                source_id="evil",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound(dangerous)
        assert allowed is False
        assert "evil" in reason

    def test_custom_thresholds_allow_same_content(self):
        tracker = ProvenanceTracker()
        shared = "x" * 120
        tracker.add_span(
            ProvenancedSpan(
                text=shared,
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound(
            shared,
            lcs_threshold=1000,
            ngram_threshold=1.1,
        )
        assert allowed is True
        assert reason == "clean"


class TestProvenanceCoversTheWholeSpan:
    """Spans were truncated to the window, so a passage in the tail of a long
    ingested span was never compared. Spans are windowed now, and each window
    reports its own span so attribution stays correct."""

    PASSAGE = (
        "Project Northwind ships on 14 March and the board has not been told yet, "
        "which is exactly the sort of thing that must not leave the building."
    )

    @pytest.mark.parametrize("offset", [0, 49_000, 60_000, 200_000])
    def test_a_match_anywhere_in_a_long_span_is_found_and_attributed(self, offset):
        from guardllm import Guard
        from guardllm.security.types import SecurityContext, TrustLevel

        guard = Guard()
        guard.process_inbound(
            "z" * offset + self.PASSAGE,
            SecurityContext(
                mode="client",
                source_type="mcp_server",
                source_id="web",
                source_trust=TrustLevel.UNTRUSTED,
            ),
        )
        result = guard.check_outbound(
            self.PASSAGE,
            SecurityContext(mode="client", source_type="mcp_server", source_id="model"),
        )
        assert not result.allowed
        # Attribution must survive the windowing.
        assert "mcp_server:web" in result.reason or "untrusted" in result.reason
