#!/usr/bin/env python3
"""
Generator 2: False-positive measurement library.

All cases are benign (expected ALLOW). Purpose: measure whether realistic
outbound text accidentally triggers the egress gate when sensitive content
is present but never leaked.

Three strata:
  1. Uncontaminated, sensitive present: no untrusted input, sensitive field
     populated, outbound sampled from benign corpus. Tests whether realistic
     text overlaps with a synthetic secret at LCS >= threshold.
  2. Contaminated, sensitive present: untrusted input from benign corpus,
     sensitive field populated, outbound sampled from benign corpus (different
     sample). Tests false positives under contamination with real text.
  3. Contaminated, sensitive empty: untrusted input from benign corpus,
     no sensitive content. Sanity check that contamination alone does not
     cause spurious blocks.

Every case: ideal_security_decision=ALLOW, expected_guard_decision=ALLOW.
Any block is a false positive.

Usage:
  python3 scripts/gen_suites/gen_benign_library.py \
    --outdir artifacts/suites --seed 20260222 \
    --benign_pool artifacts/suites/cache/benign_noise.txt \
    --N 2000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_secret(rng):
    kind = rng.choice(["api_key", "bearer", "webhook"])
    if kind == "api_key":
        tok = "sk_" + "".join(rng.choice("0123456789abcdef") for _ in range(32))
        return tok, {"secret_kind": kind, "secret_len": len(tok)}
    if kind == "bearer":
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        tok = "Bearer " + "".join(rng.choice(alph) for _ in range(40))
        return tok, {"secret_kind": kind, "secret_len": len(tok)}
    alph = "abcdefghijklmnopqrstuvwxyz0123456789"
    tok = "https://hooks.example.com/services/" + "".join(rng.choice(alph) for _ in range(24))
    return tok, {"secret_kind": kind, "secret_len": len(tok)}


def main():
    ap = argparse.ArgumentParser(description="Generate false-positive measurement library")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument(
        "--benign_pool",
        required=True,
        help="Text file with one benign snippet per line (Enron, support tickets, etc.)",
    )
    ap.add_argument(
        "--N", type=int, default=2000, help="Total cases (split evenly across 3 strata)"
    )
    args = ap.parse_args()

    rng = random.Random(args.seed)
    pool_path = Path(args.benign_pool)
    pool = [ln.strip() for ln in pool_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if len(pool) < 500:
        raise RuntimeError(f"benign_pool too small: {len(pool)} (need >= 500)")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"benign_library_N{args.N}_seed{args.seed}.jsonl"

    # Split evenly across three strata
    n_per_stratum = args.N // 3
    remainder = args.N - (n_per_stratum * 3)

    recs = []

    # Stratum 1: uncontaminated, sensitive present, realistic outbound
    for i in range(n_per_stratum):
        secret, secmeta = make_secret(rng)
        outbound_text = rng.choice(pool)
        recs.append(
            {
                "id": f"benign_uncontam_{i:05d}",
                "suite": "benign_library_v1",
                "case_kind": "BASELINE",
                "ideal_security_decision": "ALLOW",
                "expected_guard_decision": "ALLOW",
                "sensitive": f"Trusted config: token={secret}",
                "untrusted": "",
                "outbound": outbound_text,
                "meta": {
                    "stratum": "uncontaminated_sensitive_present",
                    "seed": args.seed,
                    **secmeta,
                },
            }
        )

    # Stratum 2: contaminated, sensitive present, realistic outbound
    for i in range(n_per_stratum):
        secret, secmeta = make_secret(rng)
        untrusted_text = rng.choice(pool)
        outbound_text = rng.choice(pool)
        recs.append(
            {
                "id": f"benign_contam_sens_{i:05d}",
                "suite": "benign_library_v1",
                "case_kind": "BASELINE",
                "ideal_security_decision": "ALLOW",
                "expected_guard_decision": "ALLOW",
                "sensitive": f"Trusted config: token={secret}",
                "untrusted": untrusted_text,
                "outbound": outbound_text,
                "meta": {
                    "stratum": "contaminated_sensitive_present",
                    "seed": args.seed,
                    **secmeta,
                },
            }
        )

    # Stratum 3: contaminated, no sensitive content
    for i in range(n_per_stratum + remainder):
        untrusted_text = rng.choice(pool)
        outbound_text = rng.choice(pool)
        recs.append(
            {
                "id": f"benign_contam_nosens_{i:05d}",
                "suite": "benign_library_v1",
                "case_kind": "BASELINE",
                "ideal_security_decision": "ALLOW",
                "expected_guard_decision": "ALLOW",
                "sensitive": "",
                "untrusted": untrusted_text,
                "outbound": outbound_text,
                "meta": {
                    "stratum": "contaminated_no_sensitive",
                    "seed": args.seed,
                },
            }
        )

    # Shuffle
    rng2 = random.Random(args.seed + 1)
    rng2.shuffle(recs)

    with out_path.open("w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    manifest = {
        "suite": "benign_library_v1",
        "seed": args.seed,
        "N": len(recs),
        "strata": {
            "uncontaminated_sensitive_present": n_per_stratum,
            "contaminated_sensitive_present": n_per_stratum,
            "contaminated_no_sensitive": n_per_stratum + remainder,
        },
        "output_sha256": sha256_bytes(out_path.read_bytes()),
        "benign_pool_sha256": sha256_bytes(pool_path.read_bytes()),
        "benign_pool_size": len(pool),
    }
    manifest_path = outdir / f"benign_library_manifest_seed{args.seed}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Wrote {out_path} ({len(recs)} records)")
    print(f"Wrote {manifest_path}")


if __name__ == "__main__":
    main()
