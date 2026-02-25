#!/usr/bin/env python3
"""Evaluate GuardLLM against the CBX-1200 dataset.

Runs each case TWICE through two distinct pipeline configurations:

- Variant A (VA): Guard with NO sensitive buffer. process_inbound is skipped
  for sensitive content, so only secret-pattern regex and entropy scanning
  can fire. No overlap comparison is possible.

- Variant B (VB): Guard with full contaminated-context mechanism. Sensitive
  buffer populated via process_inbound, overlap comparison active.

Reports per-variant block/allow/FN/FP counts with breakdowns by:
- case_kind (ATTACK/BASELINE/NEAR_MISS)
- transform operator
- secret_kind (api_key, bearer_token, webhook_url, pii, internal_id, contract_text)

Usage:
  python3 benchmarks/eval_cbx1200.py [--path artifacts/cbx1200/cbx_1200_v1_seed20260224.jsonl]
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


def _extract_transform(meta: dict) -> str:
    """Extract the primary transform operator name from case metadata."""
    transform_prog = meta.get("transform_program", [])
    if isinstance(transform_prog, str):
        import ast
        transform_prog = ast.literal_eval(transform_prog)
    for step in transform_prog:
        if step.startswith("select(") or step.startswith("emit("):
            continue
        if step == "none":
            return "none"
        if step.startswith("refuse"):
            return "refuse"
        return step.split("(")[0]
    return "unknown"


def _run_outbound(guard: Guard, outbound_text: str) -> dict:
    """Run check_outbound and return a flat dict of result fields."""
    out_ctx = SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="email-tool",
    )
    result = guard.check_outbound(outbound_text, out_ctx)
    return {
        "decision": "BLOCK" if not result.allowed else "ALLOW",
        "reason": result.reason,
        "secrets_found": result.secrets_found,
        "echo_detected": result.echo_detected,
        "echo_lcs": result.echo_lcs,
        "provenance_blocked": result.provenance_blocked,
        "contamination_triggered": result.contamination_triggered,
    }


def run_case(case: dict) -> dict:
    """Run a single case through two independent Guard pipelines."""
    meta = case.get("meta", {})
    transform = _extract_transform(meta)

    # ------------------------------------------------------------------
    # Variant A: no sensitive buffer, no untrusted buffer.
    # Only secret-pattern regex and entropy scanning can fire.
    # ------------------------------------------------------------------
    guard_a = Guard()
    # Skip process_inbound entirely: no sensitive buffer, no untrusted
    # buffer, no contamination flag. Only DLP secret regex + entropy.
    va = _run_outbound(guard_a, case["outbound"])

    # ------------------------------------------------------------------
    # Variant B: full pipeline with contaminated-context mechanism.
    # ------------------------------------------------------------------
    guard_b = Guard()

    sensitive_ctx = SecurityContext(
        mode="client",
        source_type="internal",
        source_id="private-channel",
        trust_level=TrustLevel.TRUSTED,
        sensitivity=SensitivityLevel.SENSITIVE,
    )
    guard_b.process_inbound(case["sensitive"], sensitive_ctx)

    untrusted_text = case.get("untrusted")
    if untrusted_text:
        untrusted_ctx = SecurityContext(
            mode="client",
            source_type="web_content",
            source_id="public-channel",
            trust_level=TrustLevel.UNTRUSTED,
        )
        guard_b.process_inbound(untrusted_text, untrusted_ctx)

    vb = _run_outbound(guard_b, case["outbound"])

    return {
        "id": case["id"],
        "case_kind": case["case_kind"],
        "ideal": case["ideal_security_decision"],
        "expected_guard": case["expected_guard_decision"],
        "transform": transform,
        "secret_kind": meta.get("secret_kind", "unknown"),
        # Variant A fields
        "va_decision": va["decision"],
        "va_reason": va["reason"],
        "va_secrets_found": va["secrets_found"],
        # Variant B fields
        "vb_decision": vb["decision"],
        "vb_reason": vb["reason"],
        "vb_secrets_found": vb["secrets_found"],
        "vb_echo_detected": vb["echo_detected"],
        "vb_echo_lcs": vb["echo_lcs"],
        "vb_provenance_blocked": vb["provenance_blocked"],
        "vb_contamination_triggered": vb["contamination_triggered"],
    }


def _print_variant_report(label: str, results: list, decision_key: str):
    """Print block/allow/FN/FP report for one variant."""
    expected_block = [r for r in results if r["expected_guard"] == "BLOCK"]
    expected_allow = [r for r in results if r["expected_guard"] == "ALLOW"]
    expected_rl = [r for r in results if r["expected_guard"] == "REPORT_LIMITATION"]

    blocked_of_eb = sum(1 for r in expected_block if r[decision_key] == "BLOCK")
    allowed_of_ea = sum(1 for r in expected_allow if r[decision_key] == "ALLOW")
    fn = [r for r in expected_block if r[decision_key] == "ALLOW"]
    fp = [r for r in expected_allow if r[decision_key] == "BLOCK"]
    rl_blocked = sum(1 for r in expected_rl if r[decision_key] == "BLOCK")
    rl_allowed = sum(1 for r in expected_rl if r[decision_key] == "ALLOW")

    print(f"\n  Expected BLOCK ({len(expected_block)}): blocked {blocked_of_eb}, FN {len(fn)}")
    print(f"  Expected ALLOW ({len(expected_allow)}): allowed {allowed_of_ea}, FP {len(fp)}")
    print(f"  REPORT_LIMITATION ({len(expected_rl)}): blocked {rl_blocked}, allowed {rl_allowed}")

    # Per-case_kind
    print(f"\n  Per-case_kind:")
    kind_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0, "fn": 0, "fp": 0})
    for r in results:
        k = kind_stats[r["case_kind"]]
        k["total"] += 1
        k["blocked" if r[decision_key] == "BLOCK" else "allowed"] += 1
        if r["expected_guard"] == "BLOCK" and r[decision_key] == "ALLOW":
            k["fn"] += 1
        elif r["expected_guard"] == "ALLOW" and r[decision_key] == "BLOCK":
            k["fp"] += 1

    print(f"  {'Kind':<16} {'Tot':>5} {'Blk':>5} {'Alw':>5} {'FN':>4} {'FP':>4}")
    print(f"  {'-'*50}")
    for kind in sorted(kind_stats.keys()):
        k = kind_stats[kind]
        print(f"  {kind:<16} {k['total']:>5} {k['blocked']:>5} {k['allowed']:>5} {k['fn']:>4} {k['fp']:>4}")

    # Per-transform
    transform_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0,
                                            "exp_block": 0, "fn": 0,
                                            "exp_allow": 0, "fp": 0, "rl": 0})
    for r in results:
        t = r["transform"]
        s = transform_stats[t]
        s["total"] += 1
        s["blocked" if r[decision_key] == "BLOCK" else "allowed"] += 1
        if r["expected_guard"] == "BLOCK":
            s["exp_block"] += 1
            if r[decision_key] == "ALLOW":
                s["fn"] += 1
        elif r["expected_guard"] == "ALLOW":
            s["exp_allow"] += 1
            if r[decision_key] == "BLOCK":
                s["fp"] += 1
        else:
            s["rl"] += 1

    print(f"\n  Per-transform:")
    print(f"  {'Transform':<28} {'Tot':>4} {'Blk':>4} {'Alw':>4} {'ExpB':>5} {'FN':>3} {'ExpA':>5} {'FP':>3} {'RL':>3}")
    print(f"  {'-'*78}")
    for t in sorted(transform_stats.keys()):
        s = transform_stats[t]
        print(f"  {t:<28} {s['total']:>4} {s['blocked']:>4} {s['allowed']:>4} "
              f"{s['exp_block']:>5} {s['fn']:>3} {s['exp_allow']:>5} {s['fp']:>3} {s['rl']:>3}")

    # Per-secret-kind
    sk_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0})
    for r in results:
        sk = r["secret_kind"]
        s = sk_stats[sk]
        s["total"] += 1
        s["blocked" if r[decision_key] == "BLOCK" else "allowed"] += 1

    print(f"\n  Per-secret-kind:")
    print(f"  {'Secret Kind':<18} {'Tot':>5} {'Blk':>5} {'Alw':>5} {'Blk%':>7}")
    print(f"  {'-'*50}")
    for sk in sorted(sk_stats.keys()):
        s = sk_stats[sk]
        pct = f"{100*s['blocked']/s['total']:.1f}" if s["total"] else "0.0"
        print(f"  {sk:<18} {s['total']:>5} {s['blocked']:>5} {s['allowed']:>5} {pct:>7}")

    # FN details
    if fn:
        print(f"\n  False negatives ({len(fn)}):")
        reason_key = decision_key.replace("_decision", "_reason")
        for r in fn[:10]:
            reason = r.get(reason_key, "")[:60]
            print(f"    {r['id']}: transform={r['transform']}, secret_kind={r['secret_kind']}, reason={reason}")
        if len(fn) > 10:
            print(f"    ... and {len(fn) - 10} more")

    # FP details
    if fp:
        print(f"\n  False positives ({len(fp)}):")
        reason_key = decision_key.replace("_decision", "_reason")
        for r in fp[:10]:
            reason = r.get(reason_key, "")[:60]
            print(f"    {r['id']}: transform={r['transform']}, secret_kind={r['secret_kind']}, reason={reason}")
        if len(fp) > 10:
            print(f"    ... and {len(fp) - 10} more")

    return fn, fp


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="artifacts/cbx1200/cbx_1200_v1_seed20260224.jsonl")
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

    # Evaluate (two runs per case)
    results = []
    for i, case in enumerate(cases):
        results.append(run_case(case))
        if (i + 1) % 200 == 0:
            print(f"  {i+1}/{len(cases)}...", file=sys.stderr)

    # ================================================================
    # Variant A report
    # ================================================================
    print(f"\n{'='*70}")
    print(f"VARIANT A: secret regex + entropy only (no sensitive buffer)")
    print(f"{'='*70}")
    va_fn, va_fp = _print_variant_report("VA", results, "va_decision")

    # ================================================================
    # Variant B report
    # ================================================================
    print(f"\n{'='*70}")
    print(f"VARIANT B: full contaminated-context pipeline")
    print(f"{'='*70}")
    vb_fn, vb_fp = _print_variant_report("VB", results, "vb_decision")

    # ================================================================
    # VA vs VB comparison on ATTACK cases
    # ================================================================
    print(f"\n{'='*70}")
    print(f"VA vs VB COMPARISON (ATTACK cases only)")
    print(f"{'='*70}")

    attack_results = [r for r in results if r["case_kind"] == "ATTACK"]
    sk_cmp = defaultdict(lambda: {
        "total": 0,
        "va_blocked": 0,
        "vb_blocked": 0,
        "both_blocked": 0,
        "neither_blocked": 0,
        "va_only": 0,
        "vb_only": 0,
    })

    for r in attack_results:
        sk = r["secret_kind"]
        s = sk_cmp[sk]
        s["total"] += 1
        va_blk = r["va_decision"] == "BLOCK"
        vb_blk = r["vb_decision"] == "BLOCK"
        if va_blk:
            s["va_blocked"] += 1
        if vb_blk:
            s["vb_blocked"] += 1
        if va_blk and vb_blk:
            s["both_blocked"] += 1
        if not va_blk and not vb_blk:
            s["neither_blocked"] += 1
        if va_blk and not vb_blk:
            s["va_only"] += 1
        if vb_blk and not va_blk:
            s["vb_only"] += 1

    print(f"\n  {'Secret Kind':<18} {'Tot':>4} {'VA':>4} {'VB':>4} {'Both':>5} {'None':>5} {'VA%':>6} {'VB%':>6} {'VA-only':>8} {'VB-only':>8}")
    print(f"  {'-'*90}")
    for sk in sorted(sk_cmp.keys()):
        s = sk_cmp[sk]
        va_pct = f"{100*s['va_blocked']/s['total']:.1f}" if s["total"] else "0.0"
        vb_pct = f"{100*s['vb_blocked']/s['total']:.1f}" if s["total"] else "0.0"
        print(f"  {sk:<18} {s['total']:>4} {s['va_blocked']:>4} {s['vb_blocked']:>4} "
              f"{s['both_blocked']:>5} {s['neither_blocked']:>5} "
              f"{va_pct:>6} {vb_pct:>6} {s['va_only']:>8} {s['vb_only']:>8}")

    # Totals
    totals = defaultdict(int)
    for s in sk_cmp.values():
        for k, v in s.items():
            totals[k] += v
    if totals["total"]:
        va_pct = f"{100*totals['va_blocked']/totals['total']:.1f}"
        vb_pct = f"{100*totals['vb_blocked']/totals['total']:.1f}"
    else:
        va_pct = vb_pct = "0.0"
    print(f"  {'-'*90}")
    print(f"  {'TOTAL':<18} {totals['total']:>4} {totals['va_blocked']:>4} {totals['vb_blocked']:>4} "
          f"{totals['both_blocked']:>5} {totals['neither_blocked']:>5} "
          f"{va_pct:>6} {vb_pct:>6} {totals['va_only']:>8} {totals['vb_only']:>8}")

    # Non-attack FP check
    print(f"\n  Non-attack FP check:")
    non_attack = [r for r in results if r["case_kind"] != "ATTACK"]
    va_fp_na = sum(1 for r in non_attack if r["va_decision"] == "BLOCK")
    vb_fp_na = sum(1 for r in non_attack if r["vb_decision"] == "BLOCK")
    print(f"    Non-attack total: {len(non_attack)}")
    print(f"    VA false positives: {va_fp_na}")
    print(f"    VB false positives: {vb_fp_na}")

    # Summary
    eb = [r for r in results if r["expected_guard"] == "BLOCK"]
    print(f"\n{'='*70}")
    va_blk_eb = sum(1 for r in eb if r["va_decision"] == "BLOCK")
    vb_blk_eb = sum(1 for r in eb if r["vb_decision"] == "BLOCK")
    print(f"VA: {va_blk_eb}/{len(eb)} expected-BLOCK caught, {len(va_fn)} FN, {len(va_fp)} FP")
    print(f"VB: {vb_blk_eb}/{len(eb)} expected-BLOCK caught, {len(vb_fn)} FN, {len(vb_fp)} FP")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
