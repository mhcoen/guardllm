"""Render a session's decision chain as a self-contained HTML page.

No external assets, no JavaScript, no CDN: a security proxy's own debug page
should not fetch anything, and an operator may well be running it somewhere
with no route to the internet. Everything is one inline stylesheet.

The page is built to make one thing obvious, because it is the thing a
per-request log cannot show: a refusal several turns after the ingest that
caused it, with the state flags visible at every step in between.
"""

from __future__ import annotations

import html
import time
from typing import Any
from urllib.parse import quote

from vordur.gateway.forensics import Chain

#: Colours are tokens with a dark-mode override rather than fixed values.
#: The first version hardcoded greys picked against white, and on a dark theme
#: the muted text landed near 2.9:1 contrast, under the 4.5:1 AA floor. The
#: accent pairs are lightened in dark mode for the same reason: #1565c0 on a
#: near-black background is legible as a badge fill and not as text.
_STYLE = """
:root {
  color-scheme: light dark;
  --fg: #1a1a1a; --muted: #5c5c5c; --faint: #767676;
  --rule: #8884;
  --ok-fg: #1b5e20; --ok-bg: #2e7d3222;
  --info-fg: #0d47a1; --info-bg: #1565c022;
  --warn-fg: #b34700; --warn-bg: #e6510022;
  --stop-fg: #fff; --stop-bg: #c62828;
  --link: #0d47a1;
}
@media (prefers-color-scheme: dark) {
  :root {
    --fg: #e8e8e8; --muted: #b0b0b0; --faint: #9a9a9a;
    --rule: #fff3;
    --ok-fg: #81c995; --ok-bg: #81c99522;
    --info-fg: #8ab4f8; --info-bg: #8ab4f822;
    --warn-fg: #fcad70; --warn-bg: #fcad7022;
    --stop-fg: #fff; --stop-bg: #d93025;
    --link: #8ab4f8;
  }
}
body { font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; margin: 2rem auto;
       max-width: 60rem; padding: 0 1rem; color: var(--fg); }
h1 { font-size: 1.3rem; margin-bottom: .25rem; }
.sub { color: var(--muted); margin-top: 0; font-size: .9rem; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--rule);
         vertical-align: top; }
th { font-weight: 600; font-size: .8rem; text-transform: uppercase;
     letter-spacing: .04em; color: var(--muted); }
td.n { color: var(--faint); width: 2rem; text-align: right; }
code { font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; }
.badge { display: inline-block; padding: .1rem .45rem; border-radius: .25rem;
         font-size: .78rem; font-weight: 600; }
.blocked { background: var(--stop-bg); color: var(--stop-fg); }
.allowed { background: var(--ok-bg); color: var(--ok-fg); }
.recorded { background: var(--info-bg); color: var(--info-fg); }
.flag { font-size: .78rem; padding: .1rem .4rem; border-radius: .25rem;
        background: var(--warn-bg); color: var(--warn-fg); margin-left: .3rem; }
.off { color: var(--faint); background: none; }
.empty { color: var(--muted); font-style: italic; margin-top: 1.5rem; }
.at { color: var(--faint); font-size: .78rem; }
a { color: var(--link); }
"""


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><meta charset=utf-8>"
        f"<title>{html.escape(title)}</title>"
        f"<style>{_STYLE}</style>{body}"
    )


def _flags(contaminated: bool, escalated: bool) -> str:
    out = []
    out.append(
        '<span class="flag">contaminated</span>'
        if contaminated
        else '<span class="flag off">clean</span>'
    )
    if escalated:
        out.append('<span class="flag">escalated</span>')
    return "".join(out)


def render_chain(session_id: str, chain: Chain) -> str:
    """One session's decisions, in order, with the state each one left behind."""
    steps = chain.steps
    if not steps:
        rows = '<tr><td colspan=5 class="empty">No decisions yet.</td></tr>'
    else:
        rows = ""
        first = steps[0].at
        for i, step in enumerate(steps, 1):
            rows += (
                f"<tr><td class=n>{i}</td>"
                f"<td><code>{html.escape(step.stage)}</code></td>"
                f"<td><code>{html.escape(step.detail)}</code></td>"
                f'<td><span class="badge {html.escape(step.outcome)}">'
                f"{html.escape(step.outcome)}</span> "
                f"{_flags(step.contaminated, step.escalated)}</td>"
                f"<td>{html.escape(step.reason)}"
                f'<div class="at">+{step.at - first:.1f}s</div>'
                "</td></tr>"
            )
    blocked = sum(1 for s in steps if s.outcome == "blocked")
    body = (
        f"<h1>Session <code>{html.escape(session_id)}</code></h1>"
        f'<p class="sub">{len(steps)} decision(s), {blocked} blocked. '
        'In memory only, lost on restart. <a href="/forensics">All sessions</a></p>'
        "<table><tr><th></th><th>Stage</th><th>Subject</th>"
        "<th>Outcome and state after</th><th>Reason</th></tr>"
        f"{rows}</table>"
    )
    return _page(f"Vörður session {session_id}", body)


def render_index(rows: list[dict[str, Any]]) -> str:
    """Every live session, so an operator can find the one they want."""
    if not rows:
        table = '<p class="empty">No live sessions. Send a request through the gateway.</p>'
    else:
        cells = ""
        for row in rows:
            sid = str(row["session_id"])
            cells += (
                # quote for the href, escape for the text. They answer
                # different questions and neither substitutes for the other:
                # html.escape stops markup injection but leaves a reserved URL
                # character reserved, so an id containing "?" or "#" produced a
                # link to a *different* session (everything from the "?" became
                # a query string, and from the "#" a fragment the server never
                # sees). The server unquotes this path component, so the two
                # sides round trip.
                f'<tr><td><a href="/forensics/{quote(sid, safe="")}">'
                f"<code>{html.escape(sid)}</code></a></td>"
                f"<td>{row['steps']}</td><td>{row['blocked']}</td>"
                f"<td>{_flags(bool(row['contaminated']), bool(row['escalated']))}</td>"
                f"<td>{row['idle_seconds']}s</td></tr>"
            )
        table = (
            "<table><tr><th>Session</th><th>Decisions</th><th>Blocked</th>"
            f"<th>State</th><th>Idle</th></tr>{cells}</table>"
        )
    body = (
        "<h1>Vörður sessions</h1>"
        f'<p class="sub">{len(rows)} live, in memory only. '
        f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')}.</p>{table}"
    )
    return _page("Vörður sessions", body)


def render_missing(session_id: str) -> str:
    body = (
        "<h1>No such session</h1>"
        f'<p class="sub"><code>{html.escape(session_id)}</code> is not live. '
        "Sessions are held in memory and expire; history across restarts is not "
        'part of this tier. <a href="/forensics">All sessions</a></p>'
    )
    return _page("Vörður: session not found", body)
