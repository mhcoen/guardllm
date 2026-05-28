#!/usr/bin/env python3
"""Generate error_sanitize benchmark cases for compositional evaluation.

Produces a JSONL file with 647 cases covering all error types handled by
the error sanitizer (spec 12.6). Distribution targets roughly uniform
coverage across custom error types, with internal_error types sharing a
smaller allocation since they all map to the same code.

Usage:
  python3 scripts/gen_suites/gen_error_sanitize.py \
    --outdir benchmarks/cases --seed 20260223
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

SUITE_NAME = "error_sanitize_suite"

# Error types with their expected sanitized codes and per-type target counts.
# Custom types get ~93 each, generic internal_error types share ~182 total.
ERROR_SPEC: list[tuple[str, str, int, dict[str, list]]] = [
    # (error_name, expect_code, count, varying_fields)
    ("PermissionDeniedError", "permission_denied", 93, {}),
    (
        "InvalidParamsError",
        "invalid_params",
        93,
        {
            "field_name": [
                "email",
                "password",
                "thread_handle",
                "query",
                "api_key",
                "database_url",
                "username",
                "session_id",
                "file_path",
                "model_name",
                "prompt",
                "temperature",
                "max_tokens",
                "tool_name",
                "source_name",
                "recipient",
                "subject",
            ],
        },
    ),
    (
        "RateLimitError",
        "rate_limited",
        93,
        {
            "retry_after": [30, 60, 120, 300],
        },
    ),
    ("UnauthorizedError", "unauthorized", 93, {}),
    ("InvalidHandleError", "invalid_handle", 93, {}),
    ("FileNotFoundError", "internal_error", 46, {}),
    ("sqlite3.OperationalError", "internal_error", 46, {}),
    ("RuntimeError", "internal_error", 46, {}),
    ("ValueError", "internal_error", 22, {}),
    ("TypeError", "internal_error", 22, {}),
]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def generate(outdir: Path, seed: int) -> Path:
    rng = random.Random(seed)
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"{SUITE_NAME}.jsonl"

    cases: list[dict] = []
    case_idx = 0

    for error_name, expect_code, count, varying in ERROR_SPEC:
        for _i in range(count):
            case: dict = {
                "id": f"{SUITE_NAME}_{case_idx:04d}",
                "suite": SUITE_NAME,
                "kind": "error_sanitize",
                "error": error_name,
                "expect_code": expect_code,
            }
            # Add varying fields where applicable
            if "field_name" in varying:
                case["field_name"] = rng.choice(varying["field_name"])
            if "retry_after" in varying:
                case["retry_after"] = rng.choice(varying["retry_after"])

            cases.append(case)
            case_idx += 1

    # Shuffle deterministically so error types are interleaved
    rng.shuffle(cases)

    # Re-assign sequential IDs after shuffle
    for idx, case in enumerate(cases):
        case["id"] = f"{SUITE_NAME}_{idx:04d}"

    with out_path.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    content_hash = sha256_bytes(out_path.read_bytes())
    manifest = {
        "suite": SUITE_NAME,
        "seed": seed,
        "total_cases": len(cases),
        "output_sha256": content_hash,
    }
    manifest_path = outdir / f"{SUITE_NAME}_manifest_seed{seed}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Wrote {out_path} ({len(cases)} cases)")
    print(f"Manifest: {manifest_path}")
    return out_path


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate error_sanitize benchmark suite")
    ap.add_argument("--outdir", required=True, help="Output directory for JSONL file")
    ap.add_argument("--seed", type=int, required=True, help="Deterministic seed")
    args = ap.parse_args()
    generate(Path(args.outdir), args.seed)


if __name__ == "__main__":
    main()
