"""Execute what the documentation advertises, and pin the numbers it quotes.

A security library's copy-paste examples are load bearing: a reader who pastes
one and gets a denial learns the wrong lesson about the library, and a reader
who pastes one that silently under-protects learns a worse one. These tests run
the examples as published, so an example cannot rot into a lie.
"""

from __future__ import annotations

import re
from importlib.metadata import version
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def _python_blocks(path: Path) -> list[str]:
    """Fenced python blocks that are examples, not sample output."""
    blocks = re.findall(r"```python\n(.*?)```", path.read_text(), re.S)
    return [b for b in blocks if "guardllm" in b]


def test_quick_start_examples_execute_as_published():
    """Every runnable block in the quick start runs, and the gate permits.

    The published tool example previously used the client-side context builder,
    left destructive tools disabled, and authorized a scope narrower than the
    arguments it dispatched. Pasting it raised PermissionError.
    """
    blocks = _python_blocks(DOCS / "quick_start.md")
    assert blocks, "quick start has no runnable examples"
    permitted = 0
    for block in blocks:
        namespace: dict = {}
        exec(compile(block, "docs/quick_start.md", "exec"), namespace)  # noqa: S102
        result = namespace.get("result")
        if result is not None and hasattr(result, "allowed"):
            assert result.allowed, f"quick start example denies: {result.reason}"
            assert result.reason == "Authorization verified"
            permitted += 1
    assert permitted >= 1, "no quick start example reaches an allowed tool call"


def test_outbound_does_not_fail_closed_on_unknown_provenance():
    """SECURITY.md describes this precisely; the claim used to be too broad.

    A session that never ingested anything has nothing to compare against, so
    ordinary outbound text is clean. Registering input through process_inbound
    is what gives egress something to match.
    """
    from guardllm import Guard

    guard = Guard()
    result = guard.check_outbound(
        "Here is an ordinary sentence.",
        Guard.context_web(source_id="example.com"),
    )
    assert result.allowed is True
    assert result.reason == "clean"

    security = (ROOT / "SECURITY.md").read_text()
    assert "do not fail closed on unknown provenance" in security
    assert 'reason="clean"' in security


def test_advertised_public_exports_match_the_package():
    """The API spec called the package exhaustive while listing one export."""
    import guardllm

    exported = set(guardllm.__all__)
    assert "Guard" in exported
    # Twelve more are public and importable; the spec must not claim otherwise.
    assert len(exported) == 13
    for name in exported:
        assert hasattr(guardllm, name), name

    # Check the export list itself, not the whole document. A 570 line spec
    # mentions these names in passing all over the place, so searching the file
    # made this assertion pass while the list still claimed a single export.
    spec = (DOCS / "api_spec.md").read_text()
    listed_block = spec.split("`src/guardllm/__init__.py` exports", 1)[1].split("\n\n##", 1)[0]
    listed = set(re.findall(r"^- `(\w+)`", listed_block, re.M))
    assert listed == exported, f"export list drifted: {sorted(exported ^ listed)}"


def test_runtime_dependency_count_is_stated_accurately():
    pyproject = (ROOT / "pyproject.toml").read_text()
    block = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]
    declared = re.findall(r'"([a-zA-Z0-9_.\-]+)', block)
    assert sorted(declared) == ["beautifulsoup4", "confusables", "soupsieve"]
    contributing = (ROOT / "CONTRIBUTING.md").read_text()
    assert "There are three" in contributing


@pytest.mark.parametrize("stale", ["3.14", "6,443", "729 cases"])
def test_reproduce_guide_does_not_quote_stale_figures(stale):
    """These drifted silently because nothing checked them."""
    assert stale not in (ROOT / "REPRODUCE.md").read_text()


def test_reproduce_guide_matches_the_shipped_case_count():
    cases = sorted((ROOT / "benchmarks" / "cases").glob("*.jsonl"))
    total = sum(sum(1 for _ in path.open()) for path in cases)
    text = (ROOT / "REPRODUCE.md").read_text()
    assert f"{len(cases)} native fixture files" in text
    assert f"{total} cases" in text


def test_ci_python_matrix_matches_the_documented_range():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    matrix = re.search(r"python-version: \[(.*?)\]", workflow).group(1)
    versions = re.findall(r'"([\d.]+)"', matrix)
    assert versions == ["3.10", "3.11", "3.12", "3.13"]
    reproduce = (ROOT / "REPRODUCE.md").read_text()
    assert f"CI covers {', '.join(versions)}" in reproduce


def test_installed_version_matches_the_changelog_top_entry():
    changelog = (ROOT / "CHANGELOG.md").read_text()
    released = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.M)
    assert released, "changelog has no released version headings"
    assert released[0] == version("guardllm")
