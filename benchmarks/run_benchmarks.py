"""Run guardllm security benchmark cases.

Usage:
  python benchmarks/run_benchmarks.py
  python benchmarks/run_benchmarks.py --suite pint_style
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from _bootstrap import ROOT  # noqa: F401
from guardllm import Guard
from guardllm.security.canary import generate_canary
from guardllm.security.error_sanitizer import (
    InvalidParamsError,
    PermissionDeniedError,
    RateLimitError,
)
from guardllm.security.rate_limiter import RateLimiter
from guardllm.security.source_gate import check_extraction_allowed
from guardllm.security.types import (
    ConfirmationHandler,
    ContentType,
    PolicyConfig,
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)
from output_layout import DATASETS_ROOT, RUNS_ROOT, ensure_run_dir, make_run_id, write_latest_pointer

BENCH_ROOT = Path(__file__).resolve().parent
CASES_DIR = BENCH_ROOT / "cases"
RESULTS_DIR = RUNS_ROOT
UPSTREAM_MANIFEST = BENCH_ROOT / "upstream" / "manifest.json"


@dataclass
class CaseResult:
    id: str
    suite: str
    kind: str
    passed: bool
    details: str


class RejectExternalEmailHandler(ConfirmationHandler):
    async def confirm(self, tool: str, args: dict, context: dict) -> bool:
        recipient = str(args.get("to", ""))
        return recipient.endswith("@example.com")


CHECKPOINT_SCHEMA_VERSION = 1


def _content_type(name: str) -> ContentType:
    mapping = {
        "html": ContentType.HTML,
        "plaintext": ContentType.PLAINTEXT,
        "structured": ContentType.STRUCTURED,
    }
    return mapping[name]


def _context_for_source(source_type: str, content_type: ContentType, policy: PolicyConfig | None = None) -> SecurityContext:
    return SecurityContext(
        mode="client",
        source_type=source_type,
        source_id=source_type,
        trust_level=TrustLevel.UNTRUSTED,
        content_type=content_type,
        policy=policy or PolicyConfig(),
    )


def load_cases(
    suite: str | None,
    *,
    dataset_id: str | None = None,
    dataset_root: Path | None = None,
) -> list[dict[str, Any]]:
    if dataset_id:
        root = dataset_root or DATASETS_ROOT
        dataset_path = root / dataset_id / "cases.jsonl"
        if not dataset_path.exists():
            raise FileNotFoundError(
                f"dataset cases not found: {dataset_path} "
                "(build first with benchmarks/build_dataset.py)"
            )
        loaded: list[dict[str, Any]] = []
        with dataset_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                case = json.loads(line)
                if suite and case.get("suite") != suite:
                    continue
                loaded.append(case)
        return loaded

    case_files = sorted(CASES_DIR.glob("*.jsonl"))
    upstream_files: list[Path] = []
    if UPSTREAM_MANIFEST.exists():
        manifest = json.loads(UPSTREAM_MANIFEST.read_text())
        for src in manifest.get("sources", []):
            snapshot_dir = src.get("snapshot_dir")
            if not snapshot_dir:
                continue
            mapped_path = ROOT / snapshot_dir / "mapped_cases.jsonl"
            if mapped_path.exists():
                upstream_files.append(mapped_path)
    else:
        upstream_files = sorted((BENCH_ROOT / "upstream").glob("**/mapped_cases.jsonl"))
    loaded: list[dict[str, Any]] = []
    for path in [*case_files, *upstream_files]:
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                case = json.loads(line)
                if suite and case.get("suite") != suite:
                    continue
                loaded.append(case)
    return loaded


def run_inbound_sanitize(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    ctx = _context_for_source(
        case["source_type"],
        _content_type(case["content_type"]),
    )
    processed = guard.process_inbound(case["input"], ctx)

    passed = True
    details: list[str] = []

    for token in case.get("expect_not_contains", []):
        if token in processed.content:
            passed = False
            details.append(f"content still contains forbidden token: {token}")

    for token in case.get("expect_contains", []):
        if token not in processed.content:
            passed = False
            details.append(f"missing required token in content: {token}")

    for token in case.get("expect_warning_contains", []):
        if not any(token.lower() in w.lower() for w in processed.warnings):
            passed = False
            details.append(f"missing warning token: {token}")

    if case.get("expect_isolated") and "<untrusted_content" not in processed.content:
        passed = False
        details.append("expected isolation wrapper")

    if "expect_class_hiding_possible" in case:
        expected = bool(case["expect_class_hiding_possible"])
        actual = bool(processed.sanitization and processed.sanitization.class_hiding_possible)
        if actual != expected:
            passed = False
            details.append(f"class_hiding_possible={actual}, expected={expected}")

    return CaseResult(
        id=case["id"],
        suite=case["suite"],
        kind=case["kind"],
        passed=passed,
        details="; ".join(details) or "ok",
    )


def run_tool_gate(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    policy = PolicyConfig(**case.get("policy", {}))
    mode = case.get("mode", "client")
    if mode == "server":
        ctx = SecurityContext(
            mode="server",
            source_type="mcp_client",
            source_id="client-1",
            policy=policy,
        )
    else:
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            policy=policy,
        )

    result = guard.check_tool_call(case["tool"], case["args"], ctx)
    passed = result.allowed is case["expect_allowed"]
    details = f"allowed={result.allowed} reason={result.reason}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_tool_gate_auth(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    policy = PolicyConfig(**case.get("policy", {}))
    mode = case.get("mode", "client")
    if mode == "server":
        ctx = SecurityContext(
            mode="server",
            source_type="mcp_client",
            source_id="client-1",
            policy=policy,
        )
    else:
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            policy=policy,
        )

    auth = Guard.authorize(
        action=case["auth_action"],
        scope=case.get("auth_scope", {}),
        user_message=case.get("message", "authorized message"),
        timestamp=time.time() - case.get("timestamp_offset_sec", 0),
    )
    result = guard.check_tool_call(
        case["tool"],
        case["args"],
        ctx,
        authorization=auth,
    )
    passed = result.allowed is case["expect_allowed"]
    details = f"allowed={result.allowed} reason={result.reason}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_outbound(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    ctx = _context_for_source(case["source_type"], _content_type(case["content_type"]))
    guard.process_inbound(case["inbound"], ctx)
    result = guard.check_outbound(
        case["outbound"],
        ctx,
        has_quoting_directive=case.get("has_quoting_directive", False),
    )
    passed = result.allowed is case["expect_allowed"]
    details = f"allowed={result.allowed} reason={result.reason}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_validation(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    result = guard.validate_tool_args(case["tool"], case["args"])
    passed = result.valid is case["expect_valid"]
    details = f"valid={result.valid} errors={result.errors}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_error(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    error_name = case["error"]
    if error_name == "PermissionDeniedError":
        exc = PermissionDeniedError("blocked")
    elif error_name == "InvalidParamsError":
        exc = InvalidParamsError("thread_handle")
    elif error_name == "RateLimitError":
        exc = RateLimitError(30)
    else:
        exc = RuntimeError("unknown")
    payload = guard.sanitize_exception(exc)
    code = payload.get("error", {}).get("code")
    passed = code == case["expect_code"]
    details = f"code={code}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_source_gate(case: dict[str, Any]) -> CaseResult:
    result = check_extraction_allowed(case["source_type"], case.get("source_id", ""))
    policy = result.policy.value
    passed = policy == case["expect_policy"]
    details = f"policy={policy} reason={result.reason}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_canary(case: dict[str, Any]) -> CaseResult:
    session_id = case.get("session_id", "bench-canary")
    guard = Guard(canary_session_id=session_id)
    ctx = _context_for_source(
        case.get("source_type", "web_content"),
        _content_type(case.get("content_type", "plaintext")),
    )
    canary = generate_canary(session_id)
    direction = case.get("direction", "outbound")

    if direction == "inbound":
        content = case.get("content", f"prefix {canary} suffix")
        processed = guard.process_inbound(content, ctx)
        detected = any("canary token" in w.lower() for w in processed.warnings)
        passed = detected is case.get("expect_detected", True)
        details = f"detected={detected}"
        return CaseResult(case["id"], case["suite"], case["kind"], passed, details)

    content = case.get("content", f"prefix {canary} suffix")
    result = guard.check_outbound(content, ctx)
    expected_allowed = case.get("expect_allowed", False)
    passed = result.allowed is expected_allowed
    details = f"allowed={result.allowed} reason={result.reason}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_rate_limit(case: dict[str, Any]) -> CaseResult:
    limiter = RateLimiter(limits=case.get("limits", {}))
    ctx = _context_for_source("mcp_server", ContentType.PLAINTEXT)
    action = case.get("action", "gmail_send_email")
    sequence = case.get("sequence", ["alice@example.com"])

    results = []
    for recipient in sequence:
        r = limiter.check(action, ctx, recipient=recipient)
        results.append(r)
        if r.allowed:
            limiter.record(action, ctx, recipient=recipient)

    final = results[-1]
    passed = final.allowed is case["expect_final_allowed"]
    details = [f"final_allowed={final.allowed}", f"final_reason={final.reason}"]

    token = case.get("expect_any_anomaly_contains")
    if token is not None:
        found = any(
            token.lower() in anomaly.lower()
            for r in results
            for anomaly in r.anomalies
        )
        if not found:
            passed = False
            details.append(f"missing anomaly token={token}")

    if case.get("expect_retry_after_positive"):
        if not (final.retry_after and final.retry_after > 0):
            passed = False
            details.append("retry_after not positive")

    return CaseResult(case["id"], case["suite"], case["kind"], passed, "; ".join(details))


async def run_action_gate(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    handler = RejectExternalEmailHandler() if case.get("use_handler", True) else None
    ctx = SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="server-1",
        policy=PolicyConfig(enable_destructive=True),
        confirmation_handler=handler,
    )
    confirmed = await guard.confirm_action(
        tool=case["tool"],
        args=case["args"],
        context=ctx,
        summary=case["summary"],
        context_has_web_derived=True,
    )
    passed = confirmed is case["expect_confirmed"]
    details = f"confirmed={confirmed}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_binding_replay(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    ctx = SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="server-1",
        policy=PolicyConfig(**case.get("policy", {})),
    )
    auth = Guard.authorize(
        action=case["tool"],
        scope=case["args"],
        user_message=case["message"],
        timestamp=time.time(),
    )
    binding = Guard.bind_request(
        tool=case["tool"],
        args=case["args"],
        authorization=auth,
    )
    replay = guard.check_tool_call(
        tool=case["tool"],
        args=case["args"],
        context=ctx,
        authorization=auth,
        binding=binding,
        user_message=case["replay_message"],
    )
    passed = replay.allowed is case["expect_allowed"]
    details = f"allowed={replay.allowed} reason={replay.reason}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def _trust_level(name: str) -> TrustLevel:
    return {"trusted": TrustLevel.TRUSTED, "semi_trusted": TrustLevel.SEMI_TRUSTED, "untrusted": TrustLevel.UNTRUSTED}[name]


def _sensitivity_level(name: str) -> SensitivityLevel:
    return {"public": SensitivityLevel.PUBLIC, "none": SensitivityLevel.PUBLIC, "internal": SensitivityLevel.INTERNAL, "sensitive": SensitivityLevel.SENSITIVE}[name]


def run_contaminated_exfil(case: dict[str, Any]) -> CaseResult:
    guard = Guard()
    policy = PolicyConfig(**case.get("policy", {}))

    # Multi-turn steps format
    if "steps" in case:
        return _run_contaminated_exfil_steps(guard, policy, case)

    # Ingest sensitive content (trusted, sensitive)
    sensitive_ctx = SecurityContext(
        mode="client",
        source_type="internal",
        source_id="private-channel",
        trust_level=TrustLevel.TRUSTED,
        sensitivity=SensitivityLevel.SENSITIVE,
        policy=policy,
    )
    guard.process_inbound(case["sensitive"], sensitive_ctx)

    # Optionally ingest untrusted content (sets contamination flag)
    untrusted_text = case.get("untrusted")
    if untrusted_text is not None:
        untrusted_ctx = SecurityContext(
            mode="client",
            source_type="web_content",
            source_id="public-channel",
            trust_level=TrustLevel.UNTRUSTED,
            policy=policy,
        )
        guard.process_inbound(untrusted_text, untrusted_ctx)

    # Check outbound
    out_ctx = SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="email-tool",
        policy=policy,
    )
    result = guard.check_outbound(case["outbound"], out_ctx)
    passed = result.allowed is case["expect_allowed"]
    if "expect_contamination" in case:
        if result.contamination_triggered is not case["expect_contamination"]:
            passed = False
    details = f"allowed={result.allowed} contamination={result.contamination_triggered} reason={result.reason}"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def _run_contaminated_exfil_steps(guard: Guard, policy: PolicyConfig, case: dict[str, Any]) -> CaseResult:
    passed = True
    details_parts: list[str] = []
    for i, step in enumerate(case["steps"]):
        action = step["action"]
        if action == "ingest":
            trust = _trust_level(step.get("trust", "trusted"))
            sensitivity = _sensitivity_level(step.get("sensitivity", "public"))
            source_type = "internal" if trust == TrustLevel.TRUSTED else "web_content"
            source_id = "private-channel" if trust == TrustLevel.TRUSTED else "public-channel"
            ctx = SecurityContext(
                mode="client",
                source_type=source_type,
                source_id=source_id,
                trust_level=trust,
                sensitivity=sensitivity,
                policy=policy,
            )
            guard.process_inbound(step["text"], ctx)
        elif action == "check_outbound":
            out_ctx = SecurityContext(
                mode="client",
                source_type="mcp_server",
                source_id="email-tool",
                policy=policy,
            )
            result = guard.check_outbound(step["text"], out_ctx)
            step_ok = result.allowed is step["expect_allowed"]
            if "expect_contamination" in step:
                if result.contamination_triggered is not step["expect_contamination"]:
                    step_ok = False
            if not step_ok:
                passed = False
            details_parts.append(
                f"step[{i}]: allowed={result.allowed} contamination={result.contamination_triggered}"
            )
    details = "; ".join(details_parts) if details_parts else "no check_outbound steps"
    return CaseResult(case["id"], case["suite"], case["kind"], passed, details)


def run_case(case: dict[str, Any]) -> CaseResult:
    kind = case["kind"]
    if kind == "inbound_sanitize":
        return run_inbound_sanitize(case)
    if kind == "tool_gate":
        return run_tool_gate(case)
    if kind == "tool_gate_auth":
        return run_tool_gate_auth(case)
    if kind == "outbound_check":
        return run_outbound(case)
    if kind == "validation":
        return run_validation(case)
    if kind == "error_sanitize":
        return run_error(case)
    if kind == "binding_replay":
        return run_binding_replay(case)
    if kind == "source_gate":
        return run_source_gate(case)
    if kind == "canary_check":
        return run_canary(case)
    if kind == "rate_limit":
        return run_rate_limit(case)
    if kind == "action_gate":
        return asyncio.run(run_action_gate(case))
    if kind == "contaminated_exfil":
        return run_contaminated_exfil(case)
    return CaseResult(case.get("id", "unknown"), case.get("suite", "unknown"), kind, False, f"unsupported kind: {kind}")


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    by_suite: dict[str, dict[str, int]] = {}
    for r in results:
        suite = by_suite.setdefault(r.suite, {"total": 0, "passed": 0})
        suite["total"] += 1
        suite["passed"] += 1 if r.passed else 0

    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round((passed / total) * 100, 2) if total else 0.0,
        "by_suite": by_suite,
    }


def _dataset_hash(cases: list[dict[str, Any]]) -> str:
    payload = [
        {
            "id": c.get("id"),
            "suite": c.get("suite"),
            "kind": c.get("kind"),
            "source_type": c.get("source_type"),
            "content_type": c.get("content_type"),
        }
        for c in cases
    ]
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def write_report(
    results: list[CaseResult],
    summary: dict[str, Any],
    *,
    run_dir: Path,
    run_id: str,
    suite_filter: str | None,
    cases: list[dict[str, Any]],
) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": int(time.time()),
        "run_id": run_id,
        "suite_filter": suite_filter,
        "dataset_hash": _dataset_hash(cases),
        "summary": summary,
        "results": [r.__dict__ for r in results],
    }
    out = run_dir / "latest.json"
    out.write_text(json.dumps(payload, indent=2) + "\n")
    return out


def build_checkpoint(summary: dict[str, Any], results: list[CaseResult]) -> dict[str, Any]:
    failed_case_ids = sorted(r.id for r in results if not r.passed)
    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "expected_summary": summary,
        "expected_failed_case_ids": failed_case_ids,
    }


def write_checkpoint(path: Path, checkpoint: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(checkpoint, indent=2) + "\n")


def load_checkpoint(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def compare_checkpoint(
    expected: dict[str, Any],
    actual_summary: dict[str, Any],
    actual_results: list[CaseResult],
    allow_extra_suites: bool = False,
) -> list[str]:
    errors: list[str] = []

    if expected.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        errors.append(
            f"unsupported checkpoint schema: {expected.get('schema_version')} (expected {CHECKPOINT_SCHEMA_VERSION})"
        )
        return errors

    expected_summary = expected.get("expected_summary", {})
    expected_failed = sorted(expected.get("expected_failed_case_ids", []))
    actual_failed = sorted(r.id for r in actual_results if not r.passed)

    for key in ("total", "passed", "failed"):
        if expected_summary.get(key) != actual_summary.get(key):
            errors.append(
                f"summary mismatch for {key}: expected={expected_summary.get(key)} actual={actual_summary.get(key)}"
            )

    expected_suites = expected_summary.get("by_suite", {})
    actual_suites = actual_summary.get("by_suite", {})

    for suite, exp_stats in expected_suites.items():
        got = actual_suites.get(suite)
        if got is None:
            errors.append(f"missing suite in run output: {suite}")
            continue
        for key in ("total", "passed"):
            if exp_stats.get(key) != got.get(key):
                errors.append(
                    f"suite mismatch {suite}.{key}: expected={exp_stats.get(key)} actual={got.get(key)}"
                )

    if not allow_extra_suites:
        extra = sorted(set(actual_suites) - set(expected_suites))
        if extra:
            errors.append(f"unexpected suites present in run output: {', '.join(extra)}")

    if expected_failed != actual_failed:
        errors.append(
            "failed-case mismatch: "
            f"expected={expected_failed or '[]'} actual={actual_failed or '[]'}"
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", default=None, help="Filter to one suite")
    parser.add_argument("--dataset-id", default=None, help="Load cases from benchmarks/datasets/<dataset_id>/cases.jsonl")
    parser.add_argument("--dataset-root", default=str(DATASETS_ROOT), help="Dataset root directory (default: benchmarks/datasets)")
    parser.add_argument(
        "--checkpoint",
        default=None,
        help="Validate results against checkpoint JSON file",
    )
    parser.add_argument(
        "--write-checkpoint",
        default=None,
        help="Write checkpoint JSON file from current run",
    )
    parser.add_argument(
        "--allow-extra-suites",
        action="store_true",
        help="When validating checkpoint, do not fail on extra suites in run output",
    )
    parser.add_argument("--run-id", default=None, help="Output run id. Default: generated timestamp+gitsha.")
    args = parser.parse_args()

    dataset_root = Path(args.dataset_root)
    cases = load_cases(args.suite, dataset_id=args.dataset_id, dataset_root=dataset_root)
    if not cases:
        print("No benchmark cases found.")
        return 1

    results = [run_case(c) for c in cases]
    summary = summarize(results)
    run_id = str(args.run_id) if args.run_id else make_run_id("core")
    run_dir = ensure_run_dir(run_id)
    write_latest_pointer(run_id)
    report_path = write_report(
        results,
        summary,
        run_dir=run_dir,
        run_id=run_id,
        suite_filter=args.suite,
        cases=cases,
    )

    print("guardllm benchmark results")
    print("total:", summary["total"], "passed:", summary["passed"], "failed:", summary["failed"], f"pass_rate={summary['pass_rate']}%")
    for suite, stats in summary["by_suite"].items():
        rate = round((stats["passed"] / stats["total"]) * 100, 2) if stats["total"] else 0.0
        print(f"- {suite}: {stats['passed']}/{stats['total']} ({rate}%)")

    failed = [r for r in results if not r.passed]
    if failed:
        print("\nfailed cases:")
        for r in failed:
            print(f"  {r.id}: {r.details}")

    checkpoint_payload = build_checkpoint(summary, results)
    if args.write_checkpoint:
        write_path = Path(args.write_checkpoint)
        write_checkpoint(write_path, checkpoint_payload)
        print(f"checkpoint written: {write_path}")

    if args.checkpoint:
        checkpoint_path = Path(args.checkpoint)
        expected = load_checkpoint(checkpoint_path)
        mismatches = compare_checkpoint(
            expected=expected,
            actual_summary=summary,
            actual_results=results,
            allow_extra_suites=args.allow_extra_suites,
        )
        if mismatches:
            print("\ncheckpoint validation: FAILED")
            for msg in mismatches:
                print(f"  - {msg}")
            print(f"checkpoint: {checkpoint_path}")
            print(f"report: {report_path}")
            return 1
        print(f"\ncheckpoint validation: PASS ({checkpoint_path})")

    print(f"\nrun id: {run_id}")
    print(f"report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
