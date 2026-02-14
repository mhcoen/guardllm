"""Compare GuardLLM against baseline mitigation strategies.

Usage:
  python benchmarks/compare_mitigations.py
  python benchmarks/compare_mitigations.py --suite upstream_bipia
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from guardllm.security.source_gate import check_extraction_allowed
from run_benchmarks import (  # noqa: F401
    BENCH_ROOT,
    RESULTS_DIR,
    CaseResult,
    UPSTREAM_MANIFEST,
    load_cases,
    run_case,
    summarize,
)

COMPARE_JSON = RESULTS_DIR / "comparison.json"
COMPARE_MD = RESULTS_DIR / "comparison.md"


def run_case_no_defense(case: dict[str, Any]) -> CaseResult:
    kind = case.get("kind", "unknown")
    passed = False
    details = "no_defense baseline"

    if kind == "inbound_sanitize":
        content = str(case.get("input", ""))
        passed = True
        for token in case.get("expect_not_contains", []):
            if token in content:
                passed = False
        for token in case.get("expect_contains", []):
            if token not in content:
                passed = False
        if case.get("expect_warning_contains"):
            passed = False
        if case.get("expect_isolated"):
            passed = False
        if "expect_class_hiding_possible" in case and bool(case["expect_class_hiding_possible"]):
            passed = False

    elif kind in {"tool_gate", "tool_gate_auth", "outbound_check", "binding_replay", "action_gate"}:
        passed = bool(case.get("expect_allowed", case.get("expect_confirmed", False)))

    elif kind == "validation":
        passed = bool(case.get("expect_valid", False))

    elif kind == "error_sanitize":
        passed = False

    elif kind == "source_gate":
        passed = case.get("expect_policy") == "allow"

    elif kind == "canary_check":
        direction = case.get("direction", "outbound")
        if direction == "inbound":
            detected = False
            passed = detected is bool(case.get("expect_detected", True))
        else:
            allowed = True
            passed = allowed is bool(case.get("expect_allowed", False))

    elif kind == "rate_limit":
        final_allowed = True
        passed = final_allowed is bool(case.get("expect_final_allowed", False))
        if case.get("expect_any_anomaly_contains") is not None:
            passed = False
        if case.get("expect_retry_after_positive"):
            passed = False

    return CaseResult(
        id=case.get("id", "unknown"),
        suite=case.get("suite", "unknown"),
        kind=kind,
        passed=passed,
        details=details,
    )


def run_case_isolation_only(case: dict[str, Any]) -> CaseResult:
    kind = case.get("kind", "unknown")
    if kind != "inbound_sanitize":
        return run_case_no_defense(case)

    content = str(case.get("input", ""))
    passed = True
    for token in case.get("expect_not_contains", []):
        if token in content:
            passed = False
    for token in case.get("expect_contains", []):
        if token not in content:
            passed = False
    if case.get("expect_warning_contains"):
        passed = False
    if "expect_class_hiding_possible" in case and bool(case["expect_class_hiding_possible"]):
        passed = False
    # Isolation-only baseline assumes wrappers are applied.
    if case.get("expect_isolated") is False:
        passed = False

    return CaseResult(
        id=case.get("id", "unknown"),
        suite=case.get("suite", "unknown"),
        kind=kind,
        passed=passed,
        details="isolation_only baseline",
    )


def run_case_source_gate_only(case: dict[str, Any]) -> CaseResult:
    kind = case.get("kind", "unknown")
    if kind != "source_gate":
        return run_case_no_defense(case)

    result = check_extraction_allowed(case["source_type"], case.get("source_id", ""))
    passed = result.policy.value == case.get("expect_policy")
    return CaseResult(
        id=case.get("id", "unknown"),
        suite=case.get("suite", "unknown"),
        kind=kind,
        passed=passed,
        details="source_gate_only baseline",
    )


def run_strategy(cases: list[dict[str, Any]], strategy: str) -> list[CaseResult]:
    if strategy == "guardllm":
        return [run_case(c) for c in cases]
    if strategy == "no_defense":
        return [run_case_no_defense(c) for c in cases]
    if strategy == "isolation_only":
        return [run_case_isolation_only(c) for c in cases]
    if strategy == "source_gate_only":
        return [run_case_source_gate_only(c) for c in cases]
    raise ValueError(f"Unsupported strategy: {strategy}")


def official_reference_summary() -> dict[str, Any]:
    payload: dict[str, Any] = {"sources": []}
    if not UPSTREAM_MANIFEST.exists():
        return payload

    manifest = json.loads(UPSTREAM_MANIFEST.read_text())
    for src in manifest.get("sources", []):
        snapshot_dir = src.get("snapshot_dir")
        if not snapshot_dir:
            continue
        raw_path = Path(snapshot_dir) / "raw_samples.jsonl"
        if not raw_path.is_absolute():
            raw_path = BENCH_ROOT.parent / raw_path
        if not raw_path.exists():
            continue

        rows: list[dict[str, Any]] = []
        with raw_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))

        suite = src.get("suite", "unknown")
        stats: dict[str, Any] = {"rows": len(rows)}
        if suite == "pint":
            labels = []
            for row in rows:
                rec = row.get("record", row)
                if isinstance(rec, dict) and "label" in rec:
                    labels.append(bool(rec["label"]))
            stats["positive_labels"] = sum(1 for x in labels if x)
            stats["negative_labels"] = sum(1 for x in labels if not x)
        elif suite == "bipia":
            known = 0
            unknown = 0
            for row in rows:
                rec = row.get("record", row)
                ideal = str(rec.get("ideal", "")).strip().lower() if isinstance(rec, dict) else ""
                if ideal == "unknown":
                    unknown += 1
                elif ideal:
                    known += 1
            stats["known_ideal"] = known
            stats["unknown_ideal"] = unknown
        elif suite == "agentdojo":
            by_channel: dict[str, int] = {"calendar": 0, "email": 0, "drive": 0, "other": 0}
            for row in rows:
                rec = row.get("record", row)
                key = str(rec.get("record_key", "")).lower() if isinstance(rec, dict) else ""
                if key.startswith("calendar_"):
                    by_channel["calendar"] += 1
                elif key.startswith("email_"):
                    by_channel["email"] += 1
                elif key.startswith("drive_"):
                    by_channel["drive"] += 1
                else:
                    by_channel["other"] += 1
            stats["channels"] = by_channel

        payload["sources"].append(
            {
                "suite": suite,
                "ref": src.get("ref"),
                "repo": src.get("repo"),
                "snapshot_dir": src.get("snapshot_dir"),
                "stats": stats,
            }
        )
    return payload


def build_table(strategies: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    all_suites = set()
    for item in strategies.values():
        all_suites.update(item["summary"]["by_suite"].keys())

    rows = []
    for suite in sorted(all_suites):
        row = {"suite": suite}
        for name, item in strategies.items():
            suite_stats = item["summary"]["by_suite"].get(suite, {"passed": 0, "total": 0})
            total = suite_stats["total"]
            passed = suite_stats["passed"]
            rate = round((passed / total) * 100, 2) if total else 0.0
            row[name] = {"passed": passed, "total": total, "pass_rate": rate}
        rows.append(row)
    return rows


def write_markdown(
    table_rows: list[dict[str, Any]],
    strategies: dict[str, dict[str, Any]],
    official: dict[str, Any],
) -> None:
    lines: list[str] = []
    lines.append("# Mitigation Comparison")
    lines.append("")
    strategy_names = [x for x in ("guardllm", "isolation_only", "source_gate_only", "no_defense") if x in strategies]
    header = "| suite | " + " | ".join(strategy_names) + " | delta_vs_no_defense |"
    divider = "|---|" + "|".join("---:" for _ in strategy_names) + "|---:|"
    lines.append(header)
    lines.append(divider)
    for row in table_rows:
        parts = []
        for name in strategy_names:
            s = row[name]
            parts.append(f"{s['passed']}/{s['total']} ({s['pass_rate']}%)")
        delta = round(row["guardllm"]["pass_rate"] - row["no_defense"]["pass_rate"], 2)
        lines.append(f"| {row['suite']} | " + " | ".join(parts) + f" | {delta}% |")

    lines.append("")
    lines.append("## Overall")
    lines.append("")
    for name, item in strategies.items():
        summary = item["summary"]
        lines.append(
            f"- `{name}`: {summary['passed']}/{summary['total']} ({summary['pass_rate']}%)"
        )

    lines.append("")
    lines.append("## Official Reference (Pinned Sources)")
    lines.append("")
    lines.append(
        "- These stats are derived from pinned official exports in `benchmarks/upstream/manifest.json`."
    )
    for src in official.get("sources", []):
        lines.append(
            f"- `{src['suite']}` @ `{src.get('ref', 'unknown')}`: "
            f"{json.dumps(src.get('stats', {}), sort_keys=True)}"
        )

    COMPARE_MD.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", default=None, help="Filter to one suite")
    args = parser.parse_args()

    cases = load_cases(args.suite)
    if not cases:
        print("No benchmark cases found.")
        return 1

    strategies = {}
    for name in ("guardllm", "isolation_only", "source_gate_only", "no_defense"):
        results = run_strategy(cases, name)
        strategies[name] = {
            "summary": summarize(results),
            "failed_case_ids": sorted(r.id for r in results if not r.passed),
        }

    table_rows = build_table(strategies)
    official = official_reference_summary()
    payload = {
        "generated_at": int(time.time()),
        "suite_filter": args.suite,
        "strategies": strategies,
        "table_rows": table_rows,
        "official_reference": official,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    COMPARE_JSON.write_text(json.dumps(payload, indent=2) + "\n")
    write_markdown(table_rows=table_rows, strategies=strategies, official=official)

    print(f"comparison json: {COMPARE_JSON}")
    print(f"comparison md:   {COMPARE_MD}")
    print("overall:")
    for name, item in strategies.items():
        s = item["summary"]
        print(f"- {name}: {s['passed']}/{s['total']} ({s['pass_rate']}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
