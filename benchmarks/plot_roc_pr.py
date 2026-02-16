"""Render ROC and PR visualizations from roc_pr_experiments.json.

Outputs SVG files (no external plotting dependencies required).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from output_layout import RUNS_ROOT, read_latest_pointer

COLORS = [
    "#0b84f3",
    "#f39c12",
    "#27ae60",
    "#e74c3c",
    "#8e44ad",
    "#16a085",
    "#d35400",
]


def _get_methods(payload: dict[str, Any]) -> list[dict[str, Any]]:
    methods = payload.get("methods", [])
    return methods if isinstance(methods, list) else []


def _svg_header(width: int, height: int) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect x="0" y="0" width="100%" height="100%" fill="#ffffff"/>',
    ]


def _map_xy(x: float, y: float, x0: float, y0: float, w: float, h: float) -> tuple[float, float]:
    px = x0 + x * w
    py = y0 + (1.0 - y) * h
    return px, py


def _draw_axes(lines: list[str], title: str, xlabel: str, ylabel: str, x0: float, y0: float, w: float, h: float) -> None:
    lines.append(f'<text x="{x0}" y="34" font-family="Arial" font-size="24" font-weight="bold">{title}</text>')
    lines.append(f'<rect x="{x0}" y="{y0}" width="{w}" height="{h}" fill="#fafafa" stroke="#dddddd"/>')
    for i in range(6):
        t = i / 5.0
        gx = x0 + t * w
        gy = y0 + t * h
        lines.append(f'<line x1="{gx}" y1="{y0}" x2="{gx}" y2="{y0+h}" stroke="#eeeeee" />')
        lines.append(f'<line x1="{x0}" y1="{gy}" x2="{x0+w}" y2="{gy}" stroke="#eeeeee" />')
        lines.append(f'<text x="{gx-10}" y="{y0+h+18}" font-family="Arial" font-size="11" fill="#555">{t:.1f}</text>')
        lines.append(f'<text x="{x0-30}" y="{y0+h-(t*h)+4}" font-family="Arial" font-size="11" fill="#555">{t:.1f}</text>')
    lines.append(f'<line x1="{x0}" y1="{y0+h}" x2="{x0+w}" y2="{y0+h}" stroke="#333"/>')
    lines.append(f'<line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y0+h}" stroke="#333"/>')
    lines.append(f'<text x="{x0+w/2-45}" y="{y0+h+38}" font-family="Arial" font-size="14">{xlabel}</text>')
    lines.append(
        f'<text x="{x0-55}" y="{y0+h/2}" font-family="Arial" font-size="13" transform="rotate(-90 {x0-55} {y0+h/2})">{ylabel}</text>'
    )


def _draw_legend(lines: list[str], labels: list[tuple[str, str]], x: float, y: float) -> None:
    lines.append(f'<rect x="{x}" y="{y}" width="290" height="{52 + 22*len(labels)}" fill="#fff" stroke="#ddd"/>')
    lines.append(f'<text x="{x+10}" y="{y+16}" font-family="Arial" font-size="12" font-weight="bold">Methods</text>')
    for i, (name, color) in enumerate(labels):
        yy = y + 52 + i * 20
        lines.append(f'<line x1="{x+10}" y1="{yy-4}" x2="{x+28}" y2="{yy-4}" stroke="{color}" stroke-width="3"/>')
        lines.append(f'<text x="{x+34}" y="{yy}" font-family="Arial" font-size="11">{name}</text>')
    lines.append(f'<circle cx="{x+16}" cy="{y+34}" r="4.5" fill="#555" stroke="#fff" stroke-width="1"/>')
    lines.append(f'<text x="{x+34}" y="{y+38}" font-family="Arial" font-size="11">Circle = default test operating point</text>')


def _dedupe_points(points: list[tuple[float, float]]) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    seen: set[tuple[float, float]] = set()
    for x, y in points:
        key = (round(x, 6), round(y, 6))
        if key in seen:
            continue
        seen.add(key)
        out.append((x, y))
    return out


def _stepify(points: list[tuple[float, float]]) -> list[tuple[float, float]]:
    if len(points) < 2:
        return points
    pts = sorted(points, key=lambda p: (p[0], p[1]))
    out: list[tuple[float, float]] = [pts[0]]
    for i in range(1, len(pts)):
        px, py = pts[i - 1]
        x, y = pts[i]
        out.append((x, py))
        out.append((x, y))
    return _dedupe_points(out)


def render_curve(
    payload: dict[str, Any],
    *,
    curve_type: str,
    out_path: Path,
    include_methods: set[str] | None = None,
) -> None:
    width = 1100
    height = 760
    x0, y0, w, h = 90.0, 80.0, 800.0, 560.0
    title = "ROC Curve (dev curves)" if curve_type == "roc" else "PR Curve (dev curves)"
    xlabel = "False Positive Rate" if curve_type == "roc" else "Recall"
    ylabel = "True Positive Rate" if curve_type == "roc" else "Precision"
    lines = _svg_header(width, height)
    _draw_axes(lines, title, xlabel, ylabel, x0, y0, w, h)

    methods = _get_methods(payload)
    if include_methods is not None:
        methods = [m for m in methods if str(m.get("name", "")) in include_methods]
    legend: list[tuple[str, str]] = []
    color_idx = 0

    for method in methods:
        name = str(method.get("name", "unknown"))
        color = COLORS[color_idx % len(COLORS)]
        color_idx += 1
        legend.append((name, color))
        curves = method.get("curves")
        if isinstance(curves, dict):
            pts = curves.get("roc_points" if curve_type == "roc" else "pr_points")
            if isinstance(pts, list) and pts:
                xy: list[tuple[float, float]] = []
                for p in pts:
                    if not isinstance(p, dict):
                        continue
                    if curve_type == "roc":
                        x = float(p.get("fpr", 0.0))
                        y = float(p.get("tpr", 0.0))
                    else:
                        x = float(p.get("recall", 0.0))
                        y = float(p.get("precision", 0.0))
                    xy.append((x, y))
                xy = _dedupe_points(xy)
                xy_draw = _stepify(xy)
                coords: list[str] = []
                for x, y in xy_draw:
                    px, py = _map_xy(x, y, x0, y0, w, h)
                    coords.append(f"{px:.2f},{py:.2f}")
                if coords:
                    lines.append(
                        f'<polyline points="{" ".join(coords)}" fill="none" stroke="{color}" stroke-width="3" />'
                    )
                    for x, y in xy:
                        px, py = _map_xy(x, y, x0, y0, w, h)
                        lines.append(f'<circle cx="{px:.2f}" cy="{py:.2f}" r="2.8" fill="{color}" opacity="0.85" />')
                    name = f"{name} ({len(xy)} pts)"
                    legend[-1] = (name, color)
        # Always plot default test point (single-point methods and tuned methods).
        dpt = method.get("default_point_test", {})
        if isinstance(dpt, dict):
            if curve_type == "roc":
                x = float(dpt.get("fpr", 0.0))
                y = float(dpt.get("recall", 0.0))
            else:
                x = float(dpt.get("recall", 0.0))
                y = float(dpt.get("precision", 0.0))
            px, py = _map_xy(x, y, x0, y0, w, h)
            lines.append(f'<circle cx="{px:.2f}" cy="{py:.2f}" r="4.5" fill="{color}" stroke="#fff" stroke-width="1"/>')
            lines.append(f'<circle cx="{px:.2f}" cy="{py:.2f}" r="8.5" fill="none" stroke="{color}" opacity="0.25" />')

    if curve_type == "roc":
        x1, y1 = _map_xy(0.0, 0.0, x0, y0, w, h)
        x2, y2 = _map_xy(1.0, 1.0, x0, y0, w, h)
        lines.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#999" stroke-dasharray="6,6"/>')

    _draw_legend(lines, legend, 910, 90)
    lines.append("</svg>")
    out_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default=None, help="Run id under benchmarks/runs/. Default: runs/LATEST.txt")
    parser.add_argument("--input", default=None)
    parser.add_argument("--out-roc", default=None)
    parser.add_argument("--out-pr", default=None)
    parser.add_argument(
        "--include-method",
        action="append",
        default=[],
        help="Method name to include (repeatable). If omitted, include all methods.",
    )
    args = parser.parse_args()
    run_id = str(args.run_id) if args.run_id else read_latest_pointer()
    if run_id and not (RUNS_ROOT / run_id / "roc_pr_experiments.json").exists() and args.input is None:
        # Fallback to most recently modified run containing roc_pr_experiments.json.
        candidates = sorted(
            [p for p in RUNS_ROOT.glob("*/roc_pr_experiments.json") if p.is_file()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            run_id = candidates[0].parent.name
    if not run_id:
        raise SystemExit("No run id provided and benchmarks/runs/LATEST.txt is missing.")
    run_dir = RUNS_ROOT / run_id
    in_path = Path(args.input) if args.input else (run_dir / "roc_pr_experiments.json")
    out_roc = Path(args.out_roc) if args.out_roc else (run_dir / "roc_curve.svg")
    out_pr = Path(args.out_pr) if args.out_pr else (run_dir / "pr_curve.svg")
    out_roc.parent.mkdir(parents=True, exist_ok=True)
    out_pr.parent.mkdir(parents=True, exist_ok=True)

    with in_path.open() as f:
        payload = json.load(f)
    include = set(str(x) for x in args.include_method) if args.include_method else None
    render_curve(payload, curve_type="roc", out_path=out_roc, include_methods=include)
    render_curve(payload, curve_type="pr", out_path=out_pr, include_methods=include)
    print(f"wrote: {out_roc}")
    print(f"wrote: {out_pr}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
