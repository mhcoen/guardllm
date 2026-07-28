"""The built-site checker must actually fail on the defects it exists to catch.

The real Jekyll build runs in CI. These pin the checker's logic against
synthetic sites reproducing each defect that reached production.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _checker():
    name = "guardllm_check_built_site"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "check_built_site.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _site(tmp_path: Path, pages: dict[str, str]) -> Path:
    site = tmp_path / "_site"
    for name, html in pages.items():
        path = site / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html)
    return site


def test_internal_link_check_catches_an_excluded_destination(tmp_path):
    """The examples/ exclusion 404'd links whose source files still existed."""
    checker = _checker()
    site = _site(
        tmp_path,
        {
            "index.html": '<a href="examples/03_web_search.py">example</a>',
            "docs/index.html": '<a href="security.html">ok</a>',
            "docs/security.html": "<h1>fine</h1>",
        },
    )
    problems = checker.check_internal_links(site)
    assert any("examples/03_web_search.py" in p for p in problems)
    # A link that does resolve must not be reported.
    assert not any("security.html" in p for p in problems)


def test_toc_check_catches_literal_markdown(tmp_path):
    """Kramdown left entries as text without markdown="1"."""
    checker = _checker()
    literal = "<details><summary>On this page</summary>- [Scope](#scope)</details>"
    site = _site(tmp_path, {"docs/api_spec.html": literal, "REPRODUCE.html": literal})
    problems = checker.check_toc_anchors(site)
    assert any("literal Markdown" in p for p in problems)


def test_toc_check_catches_an_anchor_with_no_target(tmp_path):
    """A renamed heading leaves the contents pointing at nothing."""
    checker = _checker()
    anchors = "".join(f'<a href="#h{i}">h{i}</a>' for i in range(9))
    headings = "".join(f'<h2 id="h{i}">h{i}</h2>' for i in range(8))
    page = f"<details>{anchors}</details>{headings}"
    site = _site(tmp_path, {"docs/api_spec.html": page, "REPRODUCE.html": page})
    problems = checker.check_toc_anchors(site)
    assert any("#h8 has no target" in p for p in problems)


def test_toc_check_passes_on_a_sound_contents(tmp_path):
    checker = _checker()
    anchors = "".join(f'<a href="#h{i}">h{i}</a>' for i in range(9))
    headings = "".join(f'<h2 id="h{i}">h{i}</h2>' for i in range(9))
    page = f"<details>{anchors}</details>{headings}"
    site = _site(tmp_path, {"docs/api_spec.html": page, "REPRODUCE.html": page})
    assert checker.check_toc_anchors(site) == []


def test_table_overflow_check_reads_the_served_stylesheet(tmp_path):
    checker = _checker()
    without = _site(tmp_path / "a", {"assets/css/style.css": "body{color:red}"})
    assert checker.check_table_overflow(without)

    with_rule = _site(
        tmp_path / "b",
        {"assets/css/style.css": ".markdown-body table { overflow-x: auto; }"},
    )
    assert checker.check_table_overflow(with_rule) == []


def test_required_pages_check_reports_a_dropped_page(tmp_path):
    checker = _checker()
    site = _site(tmp_path, {"index.html": "<h1>home</h1>"})
    problems = checker.check_required(site)
    assert any("docs/index.html" in p for p in problems)


def test_ci_builds_and_checks_the_site():
    """The checker is worthless if nothing runs it."""
    workflow = (ROOT / ".github" / "workflows" / "lint.yml").read_text()
    assert "github-pages build" in workflow
    assert "scripts/check_built_site.py _site" in workflow
    # Pinned, like every other tool in this workflow.
    assert "gem install github-pages -v" in workflow


def test_anchor_check_covers_prose_links_not_only_contents(tmp_path):
    """The contents check only covered the defect that had already happened."""
    checker = _checker()
    site = _site(
        tmp_path,
        {"docs/page.html": '<p>see <a href="#renamed">this</a></p><h2 id="original">x</h2>'},
    )
    problems = checker.check_all_anchors(site)
    assert any("#renamed has no target" in p for p in problems)


def test_duplicate_id_check_flags_an_unreachable_heading(tmp_path):
    checker = _checker()
    site = _site(tmp_path, {"a.html": '<h2 id="dup">one</h2><h2 id="dup">two</h2>'})
    assert any("appears more than once" in p for p in checker.check_duplicate_ids(site))


def test_asset_check_flags_a_missing_image(tmp_path):
    checker = _checker()
    site = _site(tmp_path, {"a.html": '<img src="img/missing.png">'})
    assert any("missing asset" in p for p in checker.check_assets_resolve(site))


def test_markdown_url_check_flags_a_link_to_raw_source(tmp_path):
    """Direct .md URLs serve raw Markdown rather than a rendered page."""
    checker = _checker()
    site = _site(tmp_path, {"a.html": '<a href="docs/security.md">security</a>'})
    assert any("serves raw Markdown" in p for p in checker.check_no_markdown_urls(site))


def test_new_checks_pass_on_sound_input(tmp_path):
    """None of the added checks may be vacuous."""
    checker = _checker()
    site = _site(
        tmp_path,
        {
            "a.html": '<a href="#ok">x</a><h2 id="ok">ok</h2><img src="img/p.png">',
            "img/p.png": "",
        },
    )
    assert checker.check_all_anchors(site) == []
    assert checker.check_duplicate_ids(site) == []
    assert checker.check_assets_resolve(site) == []
    assert checker.check_no_markdown_urls(site) == []


def test_ci_measures_mobile_layout_in_a_browser():
    """A substring in the stylesheet says nothing about a phone."""
    workflow = (ROOT / ".github" / "workflows" / "lint.yml").read_text()
    assert "playwright install" in workflow
    assert "scripts/check_mobile_layout.py _site" in workflow
    script = (ROOT / "scripts" / "check_mobile_layout.py").read_text()
    assert '"width": 390' in script
    # It must measure, not assert on source text.
    assert "scrollWidth" in script and "getComputedStyle" in script
