"""Check the site Jekyll actually builds, not the Markdown it builds from.

Three defects reached the published site because every assertion was made
against source files: an exclude list that 404'd two published links while the
paths still existed on disk, tables of contents that rendered as literal text
because Kramdown does not process Markdown inside a raw <details>, and table
CSS nobody had seen applied.

Source-level checks cannot see any of that. This runs against `_site`.

    python scripts/check_built_site.py _site
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

# Pages whose absence means the build dropped something published.
REQUIRED = (
    "index.html",
    "docs/index.html",
    "docs/api_spec.html",
    "docs/security.html",
    "docs/threat_model.html",
    "docs/integrations/index.html",
    "tutorials/index.html",
    "benchmarks/published/surface_controls.html",
)

# Pages that must carry a working table of contents.
TOC_PAGES = ("docs/api_spec.html", "REPRODUCE.html")


def _pages(site: Path) -> list[Path]:
    return sorted(site.rglob("*.html"))


def check_required(site: Path) -> list[str]:
    return [f"missing built page: {name}" for name in REQUIRED if not (site / name).exists()]


def check_internal_links(site: Path) -> list[str]:
    """Every internal href must resolve to something the build published."""
    problems: list[str] = []
    for page in _pages(site):
        for href in re.findall(r'href="([^"]+)"', page.read_text(errors="ignore")):
            parsed = urlparse(href)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = unquote(parsed.path)
            base = site if target.startswith("/") else page.parent
            resolved = (base / target.lstrip("/")).resolve()
            if resolved.is_dir():
                resolved = resolved / "index.html"
            if not resolved.exists():
                # Jekyll converts .md to .html; a link to source is a 404.
                problems.append(f"{page.relative_to(site)} -> {href}")
    return problems


def check_toc_anchors(site: Path) -> list[str]:
    """A table of contents must contain real anchors, not literal Markdown."""
    problems: list[str] = []
    for name in TOC_PAGES:
        page = site / name
        if not page.exists():
            problems.append(f"missing page for toc check: {name}")
            continue
        html = page.read_text(errors="ignore")
        match = re.search(r"<details[^>]*>(.*?)</details>", html, re.S)
        if not match:
            problems.append(f"{name}: no details block")
            continue
        block = match.group(1)
        anchors = re.findall(r'<a [^>]*href="#([^"]+)"', block)
        if len(anchors) < 8:
            problems.append(f"{name}: contents has {len(anchors)} anchors, expected many")
        if "](#" in block:
            problems.append(f"{name}: contents rendered as literal Markdown")
        # Each anchor must land on a heading the page actually has.
        ids = set(re.findall(r'id="([^"]+)"', html))
        for anchor in anchors:
            if anchor not in ids:
                problems.append(f"{name}: contents anchor #{anchor} has no target")
    return problems


def check_table_overflow(site: Path) -> list[str]:
    """Wide tables must get a scroll container in the stylesheet the site serves."""
    sheets = list((site / "assets").rglob("*.css")) if (site / "assets").exists() else []
    if not sheets:
        return ["no stylesheet in built site"]
    joined = "\n".join(sheet.read_text(errors="ignore") for sheet in sheets)
    condensed = re.sub(r"\s+", "", joined)
    if "overflow-x:auto" not in condensed:
        return ["built stylesheet has no table overflow rule"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("site", type=Path)
    args = parser.parse_args()
    if not args.site.exists():
        print(f"built site not found: {args.site}")
        return 1

    problems: list[str] = []
    for name, check in (
        ("required pages", check_required),
        ("internal links", check_internal_links),
        ("tables of contents", check_toc_anchors),
        ("table overflow", check_table_overflow),
    ):
        found = check(args.site)
        print(f"{name}: {'ok' if not found else str(len(found)) + ' problem(s)'}")
        problems += found

    if problems:
        print("\n" + "\n".join(sorted(problems)))
        return 1
    print(f"\nbuilt site is sound ({len(_pages(args.site))} pages checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
