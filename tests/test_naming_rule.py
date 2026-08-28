"""The name is spelled two ways, and which one is mechanical, not a judgement.

Vörður is the name. ``vordur`` is the identifier. The rule that decides between
them needs no taste: if it is in code font it is ASCII, if it is in prose it is
accented. The identifier is introduced once per document, in the first sentence
that names the package, and after that appears only in code font.

"Vordur" unaccented never appears in prose. It is neither the Icelandic word nor
the identifier, and it is the form that reads like a typo.

These tests exist because a rename touches 150 files at once and the two
spellings are one keystroke apart. Without them the rule holds only as long as
whoever edits next remembers it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Frozen or historical, and deliberately not renamed. CHANGELOG entries describe
#: what shipped under the old name; benchmark artifacts are records of runs.
EXEMPT = (
    "CHANGELOG.md",
    "paper/",
    "benchmarks/published/",
    "benchmarks/results/",
    "verification_packet",
    ".git/",
    "node_modules/",
    ".venv/",
)


def _tracked(*suffixes: str) -> list[Path]:
    import subprocess

    out = subprocess.run(
        ["git", "ls-files", *[f"*{s}" for s in suffixes]],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [ROOT / p for p in out if not any(e in p for e in EXEMPT)]


def _markdown_prose(text: str) -> str:
    """Markdown with everything that is legitimately ASCII removed.

    Fenced blocks, inline code, link targets and bare URLs all carry the
    identifier by design. What is left is prose, where the rule applies.
    """
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(r"`[^`\n]*`", " ", text)
    text = re.sub(r"\]\([^)]*\)", "](  )", text)
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"^\s*(?:title|baseurl|description|name):.*$", " ", text, flags=re.M)
    return text


def _html_prose(text: str) -> str:
    """HTML with code elements, attributes, scripts and styles removed."""
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<code\b[^>]*>.*?</code>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return text


def _offenders(path: Path, prose: str, pattern: re.Pattern[str]) -> list[str]:
    return [
        f"{path.relative_to(ROOT)}: ...{prose[max(0, m.start() - 45) : m.end() + 45].strip()}..."
        for m in pattern.finditer(prose)
    ]


UNACCENTED = re.compile(r"\bVordur\b")
BARE_IDENTIFIER = re.compile(r"(?<![\w/.-])vordur(?![\w/.-])")


@pytest.mark.parametrize("reader,suffix", [(_markdown_prose, ".md"), (_html_prose, ".html")])
def test_the_unaccented_form_never_appears_in_prose(reader, suffix):
    """It is neither the word nor the identifier, so it is always a mistake."""
    bad: list[str] = []
    for path in _tracked(suffix):
        bad += _offenders(path, reader(path.read_text(encoding="utf-8")), UNACCENTED)
    assert not bad, "Vordur unaccented in prose:\n  " + "\n  ".join(bad)


@pytest.mark.parametrize("reader,suffix", [(_markdown_prose, ".md"), (_html_prose, ".html")])
def test_the_identifier_does_not_run_as_a_prose_word(reader, suffix):
    """In code font it is ASCII; in prose the accented form is the name."""
    bad: list[str] = []
    for path in _tracked(suffix):
        bad += _offenders(path, reader(path.read_text(encoding="utf-8")), BARE_IDENTIFIER)
    assert not bad, "identifier used as a prose word:\n  " + "\n  ".join(bad)


def test_the_accented_name_is_actually_used():
    """A guard on the guards: if the rename were reverted these would pass empty."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Vörður" in readme
    assert readme.lstrip().startswith("# Vörður")
    assert "GuardLLM" not in readme


def test_the_identifier_is_introduced_once_per_document():
    """The parenthetical is an introduction, so twice is once too many."""
    intro = re.compile(r"Vörður \(package `vordur`\)")
    for path in _tracked(".md"):
        n = len(intro.findall(path.read_text(encoding="utf-8")))
        assert n <= 1, f"{path.relative_to(ROOT)} introduces the identifier {n} times"


def test_protocol_tokens_stay_ascii():
    """A header field name is a token, not display text, so it cannot be accented."""
    server = (ROOT / "src" / "vordur" / "gateway" / "server.py").read_text(encoding="utf-8")
    assert '_SESSION_HEADER = "X-Vordur-Session"' in server
    assert "Vörður" not in server.split("\n")[29], "header must not carry the accented form"
