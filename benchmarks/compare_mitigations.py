"""Compare GuardLLM against baseline mitigation strategies.

Usage:
  python benchmarks/compare_mitigations.py
  python benchmarks/compare_mitigations.py --suite upstream_bipia
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

from guardllm import Guard
from guardllm.security.source_gate import check_extraction_allowed
from run_benchmarks import (  # noqa: F401
    BENCH_ROOT,
    RESULTS_DIR,
    CaseResult,
    UPSTREAM_MANIFEST,
    load_cases,
    run_case,
    summarize,
    _content_type,
    _context_for_source,
)

COMPARE_JSON = RESULTS_DIR / "comparison.json"
COMPARE_MD = RESULTS_DIR / "comparison.md"


@dataclass
class TextRecord:
    id: str
    suite: str
    kind: str
    source_type: str
    content_type: str
    text: str
    inbound_seed: str
    label_attack: bool


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


def _text_label_from_case(case: dict[str, Any]) -> bool | None:
    kind = case.get("kind")
    if kind == "outbound_check":
        return not bool(case.get("expect_allowed", True))
    if kind != "inbound_sanitize":
        return None
    if "meta_upstream_label" in case:
        return bool(case["meta_upstream_label"])
    if case.get("expect_warning_contains"):
        return True
    if case.get("expect_not_contains"):
        return True
    if bool(case.get("expect_class_hiding_possible", False)):
        return True
    return False


def build_text_records(cases: list[dict[str, Any]]) -> list[TextRecord]:
    records: list[TextRecord] = []
    for case in cases:
        label = _text_label_from_case(case)
        if label is None:
            continue
        kind = str(case.get("kind", ""))
        if kind == "inbound_sanitize":
            text = str(case.get("input", ""))
            inbound_seed = text
        else:
            text = str(case.get("outbound", ""))
            inbound_seed = str(case.get("inbound", text))
        if not text.strip():
            continue
        records.append(
            TextRecord(
                id=str(case.get("id", "unknown")),
                suite=str(case.get("suite", "unknown")),
                kind=kind,
                source_type=str(case.get("source_type", "web_content")),
                content_type=str(case.get("content_type", "plaintext")),
                text=text,
                inbound_seed=inbound_seed,
                label_attack=label,
            )
        )
    return records


def _predict_guardllm_text(record: TextRecord) -> bool:
    guard = Guard()
    ctx = _context_for_source(record.source_type, _content_type(record.content_type))
    if record.kind == "inbound_sanitize":
        processed = guard.process_inbound(record.text, ctx)
        has_warning = bool(processed.warnings)
        class_hide = bool(processed.sanitization and processed.sanitization.class_hiding_possible)
        return has_warning or class_hide

    guard.process_inbound(record.inbound_seed, ctx)
    result = guard.check_outbound(record.text, ctx)
    return not result.allowed


def _predict_no_defense_text(record: TextRecord) -> bool:
    del record
    return False


def run_text_only_strategies(
    records: list[TextRecord],
    azure_endpoint: str | None,
    azure_key: str | None,
) -> dict[str, dict[str, Any]]:
    predictions: dict[str, list[dict[str, Any]]] = {}
    azure_error: str | None = None

    def score(name: str, fn: Any) -> None:
        rows = []
        for rec in records:
            pred = bool(fn(rec))
            rows.append(
                {
                    "id": rec.id,
                    "suite": rec.suite,
                    "kind": rec.kind,
                    "label_attack": rec.label_attack,
                    "pred_attack": pred,
                }
            )
        predictions[name] = rows

    score("guardllm", _predict_guardllm_text)
    score("no_defense", _predict_no_defense_text)

    if azure_endpoint and azure_key:
        def _predict_azure_prompt_shields(rec: TextRecord) -> bool:
            base = azure_endpoint.rstrip("/")
            url = f"{base}/contentsafety/text:shieldPrompt?api-version=2024-09-01"
            payload = {
                "userPrompt": rec.text,
                "documents": [rec.inbound_seed],
            }
            req = request.Request(
                url=url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Ocp-Apim-Subscription-Key": azure_key,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with request.urlopen(req, timeout=20.0) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
            except error.HTTPError as exc:
                message = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Azure Prompt Shields API error {exc.code}: {message}") from exc
            prompt_attack = bool(body.get("userPromptAnalysis", {}).get("attackDetected", False))
            doc_attack = any(
                bool(item.get("attackDetected", False))
                for item in body.get("documentsAnalysis", [])
                if isinstance(item, dict)
            )
            return prompt_attack or doc_attack

        try:
            score("azure_prompt_shields", _predict_azure_prompt_shields)
        except Exception as exc:  # pragma: no cover - external API failures
            azure_error = str(exc)

    summary: dict[str, dict[str, Any]] = {}
    for name, rows in predictions.items():
        tp = tn = fp = fn = 0
        by_suite: dict[str, dict[str, int]] = {}
        for row in rows:
            label = bool(row["label_attack"])
            pred = bool(row["pred_attack"])
            if label and pred:
                tp += 1
            elif (not label) and (not pred):
                tn += 1
            elif (not label) and pred:
                fp += 1
            else:
                fn += 1

            suite_stats = by_suite.setdefault(row["suite"], {"total": 0, "correct": 0})
            suite_stats["total"] += 1
            suite_stats["correct"] += 1 if label == pred else 0

        total = len(rows)
        accuracy = round(((tp + tn) / total) * 100, 2) if total else 0.0
        precision = round((tp / (tp + fp)) * 100, 2) if (tp + fp) else 0.0
        recall = round((tp / (tp + fn)) * 100, 2) if (tp + fn) else 0.0
        f1 = round((2 * precision * recall / (precision + recall)), 2) if (precision + recall) else 0.0

        by_suite_accuracy = {
            s: round((v["correct"] / v["total"]) * 100, 2) if v["total"] else 0.0
            for s, v in by_suite.items()
        }
        summary[name] = {
            "total": total,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "by_suite_accuracy": by_suite_accuracy,
        }

    return {
        "record_count": len(records),
        "azure_prompt_shields_enabled": bool(azure_endpoint and azure_key),
        "azure_error": azure_error,
        "strategies": summary,
        "predictions": predictions,
    }


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
    text_only: dict[str, Any],
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
    lines.append("## Text-Only Comparison")
    lines.append("")
    lines.append(
        f"- Record count: `{text_only.get('record_count', 0)}`"
    )
    lines.append(f"- Azure Prompt Shields enabled: `{text_only.get('azure_prompt_shields_enabled', False)}`")
    if text_only.get("azure_error"):
        lines.append(f"- Azure Prompt Shields error: `{text_only['azure_error']}`")
    lines.append("")
    lines.append("| strategy | accuracy | precision | recall | f1 | tp | tn | fp | fn |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name, stats in text_only.get("strategies", {}).items():
        lines.append(
            f"| {name} | {stats['accuracy']}% | {stats['precision']}% | {stats['recall']}% | "
            f"{stats['f1']} | {stats['tp']} | {stats['tn']} | {stats['fp']} | {stats['fn']} |"
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
    parser.add_argument("--azure-endpoint", default=None, help="Azure Content Safety endpoint")
    parser.add_argument("--azure-key", default=None, help="Azure Content Safety key")
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
    text_records = build_text_records(cases)
    text_only = run_text_only_strategies(
        records=text_records,
        azure_endpoint=args.azure_endpoint,
        azure_key=args.azure_key,
    )
    payload = {
        "generated_at": int(time.time()),
        "suite_filter": args.suite,
        "strategies": strategies,
        "table_rows": table_rows,
        "text_only": text_only,
        "official_reference": official,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    COMPARE_JSON.write_text(json.dumps(payload, indent=2) + "\n")
    write_markdown(
        table_rows=table_rows,
        strategies=strategies,
        official=official,
        text_only=text_only,
    )

    print(f"comparison json: {COMPARE_JSON}")
    print(f"comparison md:   {COMPARE_MD}")
    print("overall:")
    for name, item in strategies.items():
        s = item["summary"]
        print(f"- {name}: {s['passed']}/{s['total']} ({s['pass_rate']}%)")
    print("text-only:")
    for name, stats in text_only["strategies"].items():
        print(
            f"- {name}: accuracy={stats['accuracy']}% precision={stats['precision']}% recall={stats['recall']}%"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
