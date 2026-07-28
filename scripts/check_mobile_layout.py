"""Load the built site in a real browser at 390px and measure.

Mobile correctness was inferred from a substring in the SCSS source, which
proves nothing about layout. This measures the rendered page: the body must not
scroll sideways, and any table wider than the viewport must sit in a container
that scrolls on its own.

    python scripts/check_mobile_layout.py _site
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

VIEWPORT = {"width": 390, "height": 844}

# Pages with the widest tables, which is where clipping showed up.
PAGES = (
    "index.html",
    "docs/security.html",
    "docs/api_spec.html",
    "benchmarks/published/surface_controls.html",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("site", type=Path)
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    problems: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT)
        for name in PAGES:
            target = (args.site / name).resolve()
            if not target.exists():
                problems.append(f"missing page: {name}")
                continue
            page.goto(target.as_uri())

            # The page itself must never scroll sideways.
            overflow = page.evaluate(
                "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
            )
            if overflow > 1:  # allow a rounding pixel
                problems.append(f"{name}: page scrolls sideways by {overflow}px")

            # A table wider than the viewport must scroll within its own box.
            bad = page.evaluate(
                """() => [...document.querySelectorAll('table')]
                    .filter(t => t.scrollWidth > t.clientWidth + 1)
                    .filter(t => getComputedStyle(t).overflowX !== 'auto'
                              && getComputedStyle(t).overflowX !== 'scroll')
                    .length"""
            )
            if bad:
                problems.append(f"{name}: {bad} wide table(s) without their own scroll")
            print(f"{name}: overflow={overflow}px, unscrollable wide tables={bad}")
        browser.close()

    if problems:
        print("\n" + "\n".join(problems))
        return 1
    print(f"\nmobile layout sound at {VIEWPORT['width']}px")
    return 0


if __name__ == "__main__":
    sys.exit(main())
