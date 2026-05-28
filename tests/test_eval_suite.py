"""Parametrized eval suite for non-injection control surfaces.

Run:
    pytest tests/ -k eval_suite --tb=short

Each non-inbound_sanitize benchmark case becomes an individual pytest test.
This covers tool gating, authorization, validation, error sanitization,
binding replay, action gating, source gating, rate limiting, canary detection,
outbound checks, and contaminated-context exfiltration.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add benchmarks/ to sys.path so we can import the evaluator functions.
_BENCH_DIR = Path(__file__).resolve().parents[1] / "benchmarks"
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

from run_benchmarks import load_cases, run_case  # noqa: E402

_INBOUND_SANITIZE = "inbound_sanitize"


def _load_non_inbound_cases() -> list[dict]:
    """Load all benchmark cases, excluding inbound_sanitize."""
    cases = load_cases(suite=None)
    return [c for c in cases if c.get("kind") != _INBOUND_SANITIZE]


_CASES = _load_non_inbound_cases()


@pytest.mark.eval_suite
@pytest.mark.parametrize(
    "case",
    _CASES,
    ids=[c["id"] for c in _CASES],
)
def test_eval_suite(case: dict) -> None:
    result = run_case(case)
    assert result.passed, f"{result.id} ({result.kind}): {result.details}"
