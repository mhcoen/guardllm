#!/usr/bin/env python3
"""Evaluate GuardLLM against the three invariance test suites.

Runs all 1000 cases per suite through GuardLLM and reports the three-count
(expected BLOCK, expected ALLOW, REPORT_LIMITATION) plus per-transform
breakdown. Uses default policy thresholds.

Usage:
  python3 benchmarks/eval_invariance_suites.py [--suites_dir artifacts/suites]
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from guardllm import Guard
from guardllm.security.types import (
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)


def run_case(case: dict) -> dict:
    """Run a single case through GuardLLM and return observed result."""
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

    # Optionally ingest untrusted content (sets contamination flag)
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

    # Extract transform from meta
    meta = case.get("meta", {})
    transform_prog = meta.get("transform_program", [])
    # Get the operator name from the program (second element, or first if short)
    transform = "unknown"
    for step in transform_prog:
        if step.startswith(("select(", "emit(")):
            continue
        if step == "none":
            transform = "none"
        elif step.startswith("refuse"):
            transform = "refuse"
        else:
            # Extract op name (e.g. "prefix(12)" -> "prefix_fragment")
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
    }


def report_suite(suite_name: str, results: list[dict]) -> dict:
    """Print and return a report for a single suite."""
    print(f"\n{'=' * 70}")
    print(f"SUITE: {suite_name} ({len(results)} cases)")
    print(f"{'=' * 70}")

    expected_block = [r for r in results if r["expected_guard"] == "BLOCK"]
    expected_allow = [r for r in results if r["expected_guard"] == "ALLOW"]
    expected_rl = [r for r in results if r["expected_guard"] == "REPORT_LIMITATION"]

    blocked_of_eb = sum(1 for r in expected_block if r["observed"] == "BLOCK")
    allowed_of_ea = sum(1 for r in expected_allow if r["observed"] == "ALLOW")
    fn = [r for r in expected_block if r["observed"] == "ALLOW"]
    fp = [r for r in expected_allow if r["observed"] == "BLOCK"]
    rl_blocked = sum(1 for r in expected_rl if r["observed"] == "BLOCK")
    rl_allowed = sum(1 for r in expected_rl if r["observed"] == "ALLOW")

    print(f"\n  Expected BLOCK ({len(expected_block)}): blocked {blocked_of_eb}, FN {len(fn)}")
    print(f"  Expected ALLOW ({len(expected_allow)}): allowed {allowed_of_ea}, FP {len(fp)}")
    print(f"  REPORT_LIMITATION ({len(expected_rl)}): blocked {rl_blocked}, allowed {rl_allowed}")

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

    print(
        f"\n  {'Transform':<28} {'Tot':>4} {'Blk':>4} {'Alw':>4} {'ExpB':>5} {'FN':>3} {'ExpA':>5} {'FP':>3} {'RL':>3}"
    )
    print(f"  {'-' * 78}")
    for t in sorted(transform_stats.keys()):
        s = transform_stats[t]
        print(
            f"  {t:<28} {s['total']:>4} {s['blocked']:>4} {s['allowed']:>4} "
            f"{s['exp_block']:>5} {s['fn']:>3} {s['exp_allow']:>5} {s['fp']:>3} {s['rl']:>3}"
        )

    if fn:
        print("\n  FN details:")
        by_t = Counter(r["transform"] for r in fn)
        for t, count in by_t.most_common():
            print(f"    {t}: {count}")

    if fp:
        print("\n  FP details:")
        by_t = Counter(r["transform"] for r in fp)
        for t, count in by_t.most_common():
            print(f"    {t}: {count}")
        for r in fp[:5]:
            print(f"    {r['id']}: {r['reason'][:80]}")

    return {
        "suite": suite_name,
        "total": len(results),
        "expected_block": len(expected_block),
        "blocked": blocked_of_eb,
        "fn": len(fn),
        "expected_allow": len(expected_allow),
        "allowed": allowed_of_ea,
        "fp": len(fp),
        "report_limitation": len(expected_rl),
        "rl_blocked": rl_blocked,
        "rl_allowed": rl_allowed,
    }


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--suites_dir", default="artifacts/suites")
    args = ap.parse_args()

    suites_dir = Path(args.suites_dir)

    suite_files = sorted(suites_dir.glob("suite*_N1000_*.jsonl"))
    if not suite_files:
        print(f"ERROR: no suite files found in {suites_dir}")
        sys.exit(1)

    print(f"Found {len(suite_files)} suite files")
    summaries = []

    for sf in suite_files:
        cases = []
        with sf.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    cases.append(json.loads(line))

        results = []
        for i, case in enumerate(cases):
            results.append(run_case(case))
            if (i + 1) % 200 == 0:
                print(f"  [{sf.name}] {i + 1}/{len(cases)}...", file=sys.stderr)

        summary = report_suite(sf.stem, results)
        summaries.append(summary)

    # Cross-suite invariance check
    print(f"\n{'=' * 70}")
    print("INVARIANCE COMPARISON")
    print(f"{'=' * 70}")
    print(
        f"{'Suite':<45} {'ExpB':>5} {'Blk':>4} {'FN':>3} {'ExpA':>5} {'Alw':>4} {'FP':>3} {'RL':>4} {'RLblk':>5}"
    )
    print("-" * 95)
    for s in summaries:
        print(
            f"{s['suite']:<45} {s['expected_block']:>5} {s['blocked']:>4} {s['fn']:>3} "
            f"{s['expected_allow']:>5} {s['allowed']:>4} {s['fp']:>3} "
            f"{s['report_limitation']:>4} {s['rl_blocked']:>5}"
        )

    # Check invariance: same FN/FP counts across suites
    fn_counts = [s["fn"] for s in summaries]
    fp_counts = [s["fp"] for s in summaries]
    blk_counts = [s["blocked"] for s in summaries]

    if len(set(fn_counts)) == 1 and len(set(fp_counts)) == 1 and len(set(blk_counts)) == 1:
        print(
            f"\nINVARIANCE HOLDS: all suites have identical FN={fn_counts[0]}, FP={fp_counts[0]}, blocked={blk_counts[0]}"
        )
    else:
        print("\nINVARIANCE BROKEN:")
        print(f"  FN counts: {fn_counts}")
        print(f"  FP counts: {fp_counts}")
        print(f"  Blocked counts: {blk_counts}")


if __name__ == "__main__":
    main()
