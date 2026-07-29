"""Load the built site in a real browser at 390px and measure.

Mobile correctness was inferred from a substring in the SCSS source, which
proves nothing about layout. This measures the rendered page: the body must not
scroll sideways, and any table wider than the viewport must sit in a container
that scrolls on its own.

    python scripts/check_mobile_layout.py _site
"""

from __future__ import annotations

import argparse
import functools
import http.server
import re
import socketserver
import sys
import threading
from pathlib import Path

VIEWPORTS = ({"width": 390, "height": 844}, {"width": 1280, "height": 900})

# Pages with the widest tables, which is where clipping showed up.
PAGES = (
    "index.html",
    "docs/security.html",
    "docs/api_spec.html",
    "benchmarks/published/surface_controls.html",
)


def _baseurl() -> str:
    config = (Path(__file__).resolve().parents[1] / "_config.yml").read_text()
    match = re.search(r"^baseurl:\s*(\S+)", config, re.M)
    return match.group(1).strip().strip('"').strip("/") if match else ""


def _serve(site: Path, base: str) -> tuple[str, socketserver.TCPServer]:
    """Serve the built site over HTTP under its real base path.

    file:// cannot resolve the absolute asset URLs the theme emits, so loading
    pages that way silently rendered them unstyled and every measurement was
    taken against a site with no CSS.
    """
    root = site.parent / "_serve_root"
    target = root / base if base else root
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.symlink_to(site.resolve(), target_is_directory=True)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    prefix = f"/{base}" if base else ""
    return f"http://127.0.0.1:{httpd.server_address[1]}{prefix}", httpd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("site", type=Path)
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    base = _baseurl()
    origin, httpd = _serve(args.site, base)
    problems: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for viewport in VIEWPORTS:
            page = browser.new_page(viewport=viewport)
            width = viewport["width"]
            for name in PAGES:
                if not (args.site / name).exists():
                    problems.append(f"missing page: {name}")
                    continue
                page.goto(f"{origin}/{name}")

                # A measurement taken against an unstyled page is worthless, so
                # prove the stylesheet actually loaded before trusting anything.
                styled = page.evaluate(
                    """() => [...document.styleSheets]
                        .some(s => (s.href || '').includes('/assets/css/'))"""
                )
                if not styled:
                    problems.append(f"{name}: site stylesheet did not load")

                # The page itself must never scroll sideways.
                overflow = page.evaluate(
                    "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
                )
                if overflow > 1:  # allow a rounding pixel
                    widest = page.evaluate(
                        """() => [...document.querySelectorAll('body *')]
                            .map(e => ({
                                tag: e.tagName.toLowerCase(),
                                cls: (e.className || '').toString().slice(0, 40),
                                right: Math.round(e.getBoundingClientRect().right),
                            }))
                            .filter(e => e.right > window.innerWidth + 1)
                            .sort((a, b) => b.right - a.right)
                            .slice(0, 5)"""
                    )
                    problems.append(f"{name}: page scrolls sideways by {overflow}px")
                    for element in widest:
                        problems.append(
                            f"    {element['tag']}.{element['cls']} reaches {element['right']}px"
                        )

                # A table wider than the viewport must scroll within its own box.
                bad = page.evaluate(
                    """() => [...document.querySelectorAll('table')]
                        .filter(t => t.scrollWidth > t.clientWidth + 1)
                        .filter(t => getComputedStyle(t).overflowX !== 'auto'
                                  && getComputedStyle(t).overflowX !== 'scroll')
                        .length"""
                )
                if bad:
                    problems.append(
                        f"{name} @{width}: {bad} wide table(s) without their own scroll"
                    )

                # An element overflowing its own box inside an otherwise
                # well-behaved page. A 64 character token in a grid card did this
                # and no check saw it, because the page total stayed fine.
                spills = page.evaluate(
                    """() => [...document.querySelectorAll('body *')]
                        .filter(e => e.scrollWidth > e.clientWidth + 1)
                        .filter(e => {
                            const o = getComputedStyle(e).overflowX;
                            return o !== 'auto' && o !== 'scroll' && o !== 'hidden';
                        })
                        .map(e => `${e.tagName.toLowerCase()}.${(e.className||'').toString().split(' ')[0]}`)
                        .slice(0, 5)"""
                )
                if spills:
                    problems.append(f"{name} @{width}: content overflows {spills}")
                print(f"{name} @{width}: page={overflow}px tables={bad} spills={len(spills)}")
            page.close()
        browser.close()
    httpd.shutdown()

    if problems:
        print("\n" + "\n".join(problems))
        return 1
    print("\nlayout sound at 390px and 1280px")
    return 0


if __name__ == "__main__":
    sys.exit(main())
