#!/usr/bin/env python3
"""Evaluate Vörður against the false-positive measurement library.

Every case is expected ALLOW. Any block is a false positive.
Reports per-stratum FP rates.

Usage:
  python3 benchmarks/eval_benign_library.py [--path artifacts/suites/benign_library_N2000_seed20260222.jsonl]
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

    # Ingest sensitive content if present
    sensitive = case.get("sensitive", "")
    if sensitive:
        sensitive_ctx = SecurityContext(
            mode="client",
            source_type="internal",
            source_id="private-channel",
            source_trust=TrustLevel.TRUSTED,
            sensitivity=SensitivityLevel.SENSITIVE,
        )
        guard.process_inbound(sensitive, sensitive_ctx)

    # Ingest untrusted content if present (sets contamination flag)
    untrusted = case.get("untrusted", "")
    if untrusted:
        untrusted_ctx = SecurityContext(
            mode="client",
            source_type="web_content",
            source_id="public-channel",
            source_trust=TrustLevel.UNTRUSTED,
        )
        guard.process_inbound(untrusted, untrusted_ctx)

    # Check outbound
    out_ctx = SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="email-tool",
    )
    result = guard.check_outbound(case["outbound"], out_ctx)

    observed = "BLOCK" if not result.allowed else "ALLOW"
    return {
        "id": case["id"],
        "stratum": case.get("meta", {}).get("stratum", "unknown"),
        "observed": observed,
        "reason": result.reason,
        "secrets_found": result.secrets_found,
        "provenance_blocked": result.provenance_blocked,
        "contamination_triggered": result.contamination_triggered,
    }


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="artifacts/suites/benign_library_N2000_seed20260222.jsonl")
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
    strata = Counter(c.get("meta", {}).get("stratum", "unknown") for c in cases)
    print(f"Strata: {dict(strata)}")

    # Evaluate
    results = []
    for i, case in enumerate(cases):
        results.append(run_case(case))
        if (i + 1) % 500 == 0:
            print(f"  {i + 1}/{len(cases)}...", file=sys.stderr)

    # Report
    total_fp = sum(1 for r in results if r["observed"] == "BLOCK")
    total_allow = sum(1 for r in results if r["observed"] == "ALLOW")

    print(f"\n{'=' * 70}")
    print("FALSE-POSITIVE MEASUREMENT LIBRARY RESULTS")
    print(f"{'=' * 70}")
    print(f"Total cases: {len(results)}")
    print(f"Total ALLOW (correct): {total_allow}")
    print(f"Total BLOCK (false positive): {total_fp}")
    print(f"FP rate: {total_fp / len(results) * 100:.2f}%")

    # Per-stratum
    stratum_stats = defaultdict(lambda: {"total": 0, "fp": 0, "allow": 0})
    for r in results:
        s = stratum_stats[r["stratum"]]
        s["total"] += 1
        if r["observed"] == "BLOCK":
            s["fp"] += 1
        else:
            s["allow"] += 1

    print("\nPer-stratum breakdown:")
    print(f"  {'Stratum':<42} {'Total':>5} {'Allow':>5} {'FP':>4} {'Rate':>7}")
    print(f"  {'-' * 68}")
    for stratum in sorted(stratum_stats.keys()):
        s = stratum_stats[stratum]
        rate = s["fp"] / s["total"] * 100 if s["total"] else 0
        print(f"  {stratum:<42} {s['total']:>5} {s['allow']:>5} {s['fp']:>4} {rate:>6.2f}%")

    # FP details
    fp_cases = [r for r in results if r["observed"] == "BLOCK"]
    if fp_cases:
        print("\nFalse positive details:")
        for r in fp_cases[:20]:
            print(f"  {r['id']}: stratum={r['stratum']}")
            print(f"    reason: {r['reason'][:120]}")
            if r["secrets_found"]:
                print(f"    secrets: {r['secrets_found']}")
            if r["provenance_blocked"]:
                print("    provenance_blocked: True")
            if r["contamination_triggered"]:
                print("    contamination_triggered: True")
        if len(fp_cases) > 20:
            print(f"  ... and {len(fp_cases) - 20} more")

        # Categorize FP causes
        cause_counts = Counter()
        for r in fp_cases:
            if r["secrets_found"]:
                cause_counts["secrets_detected"] += 1
            elif r["provenance_blocked"]:
                cause_counts["provenance_overlap"] += 1
            elif r["contamination_triggered"]:
                cause_counts["contamination"] += 1
            else:
                cause_counts["other"] += 1
        print(f"\nFP causes: {dict(cause_counts)}")
    else:
        print("\nNo false positives detected.")


if __name__ == "__main__":
    main()
