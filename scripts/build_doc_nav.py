"""Insert a breadcrumb and, on long pages, a table of contents.

Individual documentation pages had no navigation: a reader who arrived from a
search result could not get back to an index, and the two longest references
(the API specification and the reproduction guide) ran past five hundred lines
with no way to jump.

Both blocks live between markers and are regenerated, never hand-edited, so a
renamed heading cannot leave a stale entry behind.

    python scripts/build_doc_nav.py           # write
    python scripts/build_doc_nav.py --check   # verify, exit 1 on drift
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAV_START = "<!-- nav:start -->"
NAV_END = "<!-- nav:end -->"
TOC_START = "<!-- toc:start -->"
TOC_END = "<!-- toc:end -->"

# A page long enough that a reader needs to jump within it.
TOC_MIN_LINES = 200


def _pages() -> list[tuple[Path, str]]:
    """Every page that gets a breadcrumb, with the trail to show."""
    docs = ROOT / "docs"
    pages = [
        (path, "[Docs index](README.md)")
        for path in sorted(docs.glob("*.md"))
        if path.name != "README.md"
    ]
    pages += [
        (path, "[Docs index](../README.md) / [Integrations](README.md)")
        for path in sorted((docs / "integrations").glob("*.md"))
        if path.name != "README.md"
    ]
    pages.append((ROOT / "REPRODUCE.md", "[Home](README.md) / [Docs index](docs/README.md)"))
    return pages


def _slug(heading: str) -> str:
    text = re.sub(r"`([^`]*)`", r"\1", heading).strip()
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"[\s]+", "-", text)


def _toc(body: str) -> str:
    """Second and third level headings, skipping fenced code."""
    entries: list[str] = []
    fenced = False
    for line in body.splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        match = re.match(r"^(#{2,3})\s+(.*)$", line)
        if not match:
            continue
        depth, heading = len(match.group(1)), match.group(2).strip()
        indent = "  " * (depth - 2)
        entries.append(f"{indent}- [{heading}](#{_slug(heading)})")
    if not entries:
        return ""
    return (
        f"{TOC_START}\n"
        "<details>\n<summary>On this page</summary>\n\n"
        + "\n".join(entries)
        + f"\n\n</details>\n{TOC_END}"
    )


def _strip(text: str, start: str, end: str) -> str:
    pattern = re.compile(re.escape(start) + ".*?" + re.escape(end) + r"\n?", re.S)
    return pattern.sub("", text)


def render(path: Path, trail: str) -> str:
    original = path.read_text()
    body = _strip(_strip(original, NAV_START, NAV_END), TOC_START, TOC_END)
    lines = body.splitlines()
    # Keep the H1 first; the breadcrumb goes directly beneath it.
    head = 0
    while head < len(lines) and not lines[head].startswith("# "):
        head += 1
    if head == len(lines):
        return original
    title, rest = lines[: head + 1], lines[head + 1 :]
    while rest and not rest[0].strip():
        rest.pop(0)

    blocks = [f"{NAV_START}\n{trail}\n{NAV_END}"]
    if len(lines) >= TOC_MIN_LINES:
        toc = _toc("\n".join(rest))
        if toc:
            blocks.append(toc)
    return "\n".join(title) + "\n\n" + "\n\n".join(blocks) + "\n\n" + "\n".join(rest) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    stale: list[str] = []
    for path, trail in _pages():
        rendered = render(path, trail)
        if args.check:
            if path.read_text() != rendered:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(rendered)

    if args.check:
        if stale:
            print("documentation navigation is stale:\n  " + "\n  ".join(stale))
            return 1
        print("documentation navigation is current")
        return 0
    print(f"updated navigation on {len(_pages())} pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
