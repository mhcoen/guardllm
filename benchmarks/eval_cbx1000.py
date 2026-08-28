#!/usr/bin/env python3
"""Evaluate Vörður against the CBX-1000 dataset.

Runs all 1000 contaminated-context exfiltration cases through Vörður and
reports block/allow/FN/FP counts, per-transform breakdown, and per-case_kind
breakdown. Uses default policy thresholds.

Usage:
  python3 benchmarks/eval_cbx1000.py [--path artifacts/cbx1000/cbx_1000_v1_seed20260222.jsonl]
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vordur import Guard
from vordur.security.types import (
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)


def run_case(case: dict) -> dict:
    """Run a single case through Vörður and return observed result."""
    guard = Guard()

    # Ingest sensitive content (trusted, sensitive)
    sensitive_ctx = SecurityContext(
        mode="client",
        source_type="internal",
        source_id="private-channel",
        source_trust=TrustLevel.TRUSTED,
        sensitivity=SensitivityLevel.SENSITIVE,
    )
    guard.process_inbound(case["sensitive"], sensitive_ctx)

    # Ingest untrusted content (sets contamination flag)
    untrusted_text = case.get("untrusted")
    if untrusted_text:
        untrusted_ctx = SecurityContext(
            mode="client",
            source_type="web_content",
            source_id="public-channel",
            source_trust=TrustLevel.UNTRUSTED,
        )
        guard.process_inbound(untrusted_text, untrusted_ctx)

    # Check outbound
    out_ctx = SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="email-tool",
    )
    result = guard.check_outbound(case["outbound"], out_ctx)

    observed = "BLOCK" if not result.allowed else "ALLOW"

    meta = case.get("meta", {})
    transform_prog = meta.get("transform_program", [])
    if isinstance(transform_prog, str):
        import ast

        transform_prog = ast.literal_eval(transform_prog)

    transform = "unknown"
    for step in transform_prog:
        if step.startswith(("select(", "emit(")):
            continue
        if step == "none":
            transform = "none"
        elif step.startswith("refuse"):
            transform = "refuse"
        else:
            transform = step.split("(")[0]
        break

    return {
        "id": case["id"],
        "case_kind": case["case_kind"],
        "ideal": case["ideal_security_decision"],
        "expected_guard": case["expected_guard_decision"],
        "observed": observed,
        "reason": result.reason,
        "transform": transform,
        "echo_detected": result.echo_detected,
        "echo_lcs": result.echo_lcs,
        "provenance_blocked": result.provenance_blocked,
        "contamination_triggered": result.contamination_triggered,
    }


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="artifacts/cbx1000/cbx_1000_v1_seed20260222.jsonl")
    args = ap.parse_args()

    dataset_path = Path(args.path)
    if not dataset_path.exists():
        print(f"ERROR: {dataset_path} not found")
        sys.exit(1)

    cases = []
    with dataset_path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))

    print(f"Loaded {len(cases)} cases from {dataset_path.name}")

    # Distribution
    kind_counts = Counter(c["case_kind"] for c in cases)
    decision_counts = Counter(c["expected_guard_decision"] for c in cases)
    print(f"Case kinds: {dict(kind_counts)}")
    print(f"Expected decisions: {dict(decision_counts)}")

    # Evaluate
    results = []
    for i, case in enumerate(cases):
        results.append(run_case(case))
        if (i + 1) % 200 == 0:
            print(f"  {i + 1}/{len(cases)}...", file=sys.stderr)

    # Report
    expected_block = [r for r in results if r["expected_guard"] == "BLOCK"]
    expected_allow = [r for r in results if r["expected_guard"] == "ALLOW"]
    expected_rl = [r for r in results if r["expected_guard"] == "REPORT_LIMITATION"]

    blocked_of_eb = sum(1 for r in expected_block if r["observed"] == "BLOCK")
    allowed_of_ea = sum(1 for r in expected_allow if r["observed"] == "ALLOW")
    fn = [r for r in expected_block if r["observed"] == "ALLOW"]
    fp = [r for r in expected_allow if r["observed"] == "BLOCK"]
    rl_blocked = sum(1 for r in expected_rl if r["observed"] == "BLOCK")
    rl_allowed = sum(1 for r in expected_rl if r["observed"] == "ALLOW")

    echo_count = sum(1 for r in results if r["echo_detected"])

    print(f"\n{'=' * 70}")
    print("CBX-1000 EVALUATION RESULTS")
    print(f"{'=' * 70}")
    print(f"Total cases: {len(results)}")
    print(f"\n  Expected BLOCK ({len(expected_block)}): blocked {blocked_of_eb}, FN {len(fn)}")
    print(f"  Expected ALLOW ({len(expected_allow)}): allowed {allowed_of_ea}, FP {len(fp)}")
    print(f"  REPORT_LIMITATION ({len(expected_rl)}): blocked {rl_blocked}, allowed {rl_allowed}")
    print(f"  Echo detected: {echo_count} / {len(results)}")

    # Per-case_kind breakdown
    print("\n  Per-case_kind:")
    kind_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0, "fn": 0, "fp": 0})
    for r in results:
        k = kind_stats[r["case_kind"]]
        k["total"] += 1
        k["blocked" if r["observed"] == "BLOCK" else "allowed"] += 1
        if r["expected_guard"] == "BLOCK" and r["observed"] == "ALLOW":
            k["fn"] += 1
        elif r["expected_guard"] == "ALLOW" and r["observed"] == "BLOCK":
            k["fp"] += 1

    print(f"  {'Kind':<16} {'Tot':>5} {'Blk':>5} {'Alw':>5} {'FN':>4} {'FP':>4}")
    print(f"  {'-' * 50}")
    for kind in sorted(kind_stats.keys()):
        k = kind_stats[kind]
        print(
            f"  {kind:<16} {k['total']:>5} {k['blocked']:>5} {k['allowed']:>5} {k['fn']:>4} {k['fp']:>4}"
        )

    # Per-transform breakdown
    transform_stats = defaultdict(
        lambda: {
            "total": 0,
            "blocked": 0,
            "allowed": 0,
            "exp_block": 0,
            "fn": 0,
            "exp_allow": 0,
            "fp": 0,
            "rl": 0,
        }
    )
    for r in results:
        t = r["transform"]
        s = transform_stats[t]
        s["total"] += 1
        s["blocked" if r["observed"] == "BLOCK" else "allowed"] += 1
        if r["expected_guard"] == "BLOCK":
            s["exp_block"] += 1
            if r["observed"] == "ALLOW":
                s["fn"] += 1
        elif r["expected_guard"] == "ALLOW":
            s["exp_allow"] += 1
            if r["observed"] == "BLOCK":
                s["fp"] += 1
        else:
            s["rl"] += 1

    print("\n  Per-transform:")
    print(
        f"  {'Transform':<28} {'Tot':>4} {'Blk':>4} {'Alw':>4} {'ExpB':>5} {'FN':>3} {'ExpA':>5} {'FP':>3} {'RL':>3}"
    )
    print(f"  {'-' * 78}")
    for t in sorted(transform_stats.keys()):
        s = transform_stats[t]
        print(
            f"  {t:<28} {s['total']:>4} {s['blocked']:>4} {s['allowed']:>4} "
            f"{s['exp_block']:>5} {s['fn']:>3} {s['exp_allow']:>5} {s['fp']:>3} {s['rl']:>3}"
        )

    # FN details
    if fn:
        print(f"\n  False negatives ({len(fn)}):")
        for r in fn[:10]:
            print(f"    {r['id']}: transform={r['transform']}, reason={r['reason'][:80]}")
        if len(fn) > 10:
            print(f"    ... and {len(fn) - 10} more")

    # FP details
    if fp:
        print(f"\n  False positives ({len(fp)}):")
        for r in fp[:10]:
            print(f"    {r['id']}: transform={r['transform']}, reason={r['reason'][:80]}")
        if len(fp) > 10:
            print(f"    ... and {len(fp) - 10} more")

    # Summary
    print(f"\n{'=' * 70}")
    if len(fn) == 0 and len(fp) == 0:
        print(f"PASS: {blocked_of_eb}/{len(expected_block)} attacks blocked, 0 FN, 0 FP")
    else:
        print(f"RESULT: {blocked_of_eb}/{len(expected_block)} blocked, {len(fn)} FN, {len(fp)} FP")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
