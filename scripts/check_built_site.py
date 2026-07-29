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

# Emitted by the theme on every page; not a link this project publishes.
THEME_ASSETS = {"/favicon.ico"}


def _pages(site: Path) -> list[Path]:
    return sorted(site.rglob("*.html"))


def _strip_base(path: str) -> str:
    """Drop the baseurl prefix so a path can be compared against site paths."""
    base = _baseurl().rstrip("/")
    if base and path.startswith(base + "/"):
        return path[len(base) :]
    return path


def _resolve(site: Path, page: Path, ref: str) -> Path:
    """Resolve a site-relative reference, allowing for the configured baseurl.

    Absolute URLs on a project site carry the baseurl prefix, which is not part
    of the path inside _site.
    """
    path = unquote(ref)
    if path.startswith("/"):
        base = _baseurl().rstrip("/")
        if base and path.startswith(base + "/"):
            path = path[len(base) :]
        return (site / path.lstrip("/")).resolve()
    return (page.parent / path).resolve()


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
            # Theme-injected assets are not documentation links. Primer emits a
            # favicon reference on every page; that is one missing file, not 34
            # broken links, and it is the theme's to supply.
            if _strip_base(parsed.path) in THEME_ASSETS:
                continue
            resolved = _resolve(site, page, parsed.path)
            if resolved.is_dir():
                resolved = resolved / "index.html"
            if not resolved.exists():
                # Jekyll converts .md to .html; a link to source is a 404.
                problems.append(f"{page.relative_to(site)} -> {href}")
    return problems


def check_all_anchors(site: Path) -> list[str]:
    """Every in-page anchor, not only the ones in a table of contents.

    The contents check covered the defect that had already happened. A prose
    link to a renamed section fails the same way and was invisible.
    """
    problems: list[str] = []
    for page in _pages(site):
        html = page.read_text(errors="ignore")
        ids = set(re.findall(r'id="([^"]+)"', html)) | set(re.findall(r'name="([^"]+)"', html))
        for anchor in re.findall(r'href="#([^"]+)"', html):
            if unquote(anchor) not in ids:
                problems.append(f"{page.relative_to(site)} -> #{anchor} has no target")
    return problems


def check_duplicate_ids(site: Path) -> list[str]:
    """Two headings sharing an id make one of them unreachable by anchor."""
    problems: list[str] = []
    for page in _pages(site):
        found = re.findall(r'id="([^"]+)"', page.read_text(errors="ignore"))
        for value in {v for v in found if found.count(v) > 1}:
            problems.append(f"{page.relative_to(site)}: id {value!r} appears more than once")
    return problems


def check_assets_resolve(site: Path) -> list[str]:
    """A published page referencing a missing image or stylesheet is broken."""
    problems: list[str] = []
    for page in _pages(site):
        for attr in re.findall(r'(?:src|srcset)="([^"]+)"', page.read_text(errors="ignore")):
            ref = attr.split()[0].split(",")[0]
            parsed = urlparse(ref)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            if _strip_base(parsed.path) in THEME_ASSETS:
                continue
            if not _resolve(site, page, parsed.path).exists():
                problems.append(f"{page.relative_to(site)} -> {ref} (missing asset)")
    return problems


def check_no_markdown_urls(site: Path) -> list[str]:
    """Direct .md URLs serve raw source, so a published page must not link one."""
    problems: list[str] = []
    for page in _pages(site):
        for href in re.findall(r'href="([^"]+\.md)"', page.read_text(errors="ignore")):
            if urlparse(href).scheme:
                continue
            problems.append(f"{page.relative_to(site)} -> {href} (serves raw Markdown)")
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


def _baseurl() -> str:
    config = (Path(__file__).resolve().parents[1] / "_config.yml").read_text()
    match = re.search(r"^baseurl:\s*(\S+)", config, re.M)
    return match.group(1).strip().strip('"') if match else ""


def check_stylesheet_is_linked(site: Path) -> list[str]:
    """A compiled stylesheet nobody links is the same as no stylesheet.

    The previous check found the file in _site and passed while every page
    pointed at a URL that 404'd, so the site rendered unstyled and three
    separate checks reported success.
    """
    problems: list[str] = []
    base = _baseurl().rstrip("/")
    for page in _pages(site):
        html = page.read_text(errors="ignore")
        # The generated demos are self-contained by design: they embed their
        # styles and must keep working from a file:// path with no site around
        # them. Requiring a site stylesheet of them would be wrong.
        if "<style>" in html:
            continue
        hrefs = re.findall(r'<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"', html)
        own = [h for h in hrefs if "/assets/" in h and not urlparse(h).scheme]
        if not own:
            problems.append(f"{page.relative_to(site)}: links no site stylesheet")
            continue
        for href in own:
            path = urlparse(href).path
            if base and path.startswith(base + "/"):
                path = path[len(base) :]
            resolved = (site / unquote(path).lstrip("/")).resolve()
            if not resolved.exists():
                problems.append(f"{page.relative_to(site)} -> {href} (stylesheet 404)")
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
        ("in-page anchors", check_all_anchors),
        ("duplicate ids", check_duplicate_ids),
        ("assets", check_assets_resolve),
        ("markdown urls", check_no_markdown_urls),
        ("stylesheet linked", check_stylesheet_is_linked),
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
