"""Build a canonical benchmark dataset package with stable manifests and hashes.

Usage:
  python benchmarks/build_dataset.py --dataset-id canonical-v1
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from _bootstrap import ROOT  # noqa: F401
from compare_mitigations import TEXT_SCOPE_INCLUDED_SUITES, build_text_records
from output_layout import BENCH_ROOT, ensure_run_dir, git_sha_short
from run_benchmarks import CASES_DIR, UPSTREAM_MANIFEST


DATASETS_ROOT = BENCH_ROOT / "datasets"


def _sha256_json(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _iter_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _line_count_jsonl(path: Path) -> int:
    count = 0
    with path.open() as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def _sorted_sources(manifest_path: Path) -> list[Path]:
    sources: list[Path] = []
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        for src in manifest.get("sources", []):
            snapshot_dir = src.get("snapshot_dir")
            if not snapshot_dir:
                continue
            mapped_path = ROOT / snapshot_dir / "mapped_cases.jsonl"
            if mapped_path.exists():
                sources.append(mapped_path)
    return sorted(sources)


def _manifest_source_audit(manifest_path: Path) -> list[dict[str, Any]]:
    if not manifest_path.exists():
        return []
    payload = json.loads(manifest_path.read_text())
    rows: list[dict[str, Any]] = []
    for src in payload.get("sources", []):
        suite = str(src.get("suite", "unknown"))
        snapshot_dir_raw = str(src.get("snapshot_dir", ""))
        if not snapshot_dir_raw:
            continue
        snapshot_dir = ROOT / snapshot_dir_raw
        raw_path = snapshot_dir / "raw_samples.jsonl"
        mapped_path = snapshot_dir / "mapped_cases.jsonl"
        readme_path = snapshot_dir / "README.md"
        row = {
            "suite": suite,
            "repo": str(src.get("repo", "")),
            "ref": str(src.get("ref", "")),
            "snapshot_dir": snapshot_dir_raw,
            "source_export": str(src.get("source_export", "")),
            "manifest_imported_raw_records": src.get("imported_raw_records"),
            "manifest_mapped_cases": src.get("mapped_cases"),
            "raw_samples_present": raw_path.exists(),
            "mapped_cases_present": mapped_path.exists(),
            "readme_present": readme_path.exists(),
            "raw_samples_sha256": _sha256_file(raw_path) if raw_path.exists() else None,
            "mapped_cases_sha256": _sha256_file(mapped_path) if mapped_path.exists() else None,
            "raw_samples_line_count": _line_count_jsonl(raw_path) if raw_path.exists() else None,
            "mapped_cases_line_count": _line_count_jsonl(mapped_path) if mapped_path.exists() else None,
        }
        rows.append(row)
    rows.sort(key=lambda x: x["suite"])
    return rows


def _local_case_paths() -> list[Path]:
    return sorted(CASES_DIR.glob("*.jsonl"))


def _canonical_case(case: dict[str, Any]) -> dict[str, Any]:
    # Stable key order via dumps(sort_keys=True) at write time.
    return case


def _source_label(path: Path) -> str:
    rel = path.relative_to(ROOT)
    if "benchmarks/cases/" in str(rel):
        return "local_fixture"
    if "benchmarks/upstream/" in str(rel):
        return "upstream_snapshot"
    return "unknown"


def _load_cases_with_provenance(manifest_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in [*_local_case_paths(), *_sorted_sources(manifest_path)]:
        for case in _iter_jsonl(path):
            rows.append(
                {
                    "source_file": str(path.relative_to(ROOT)),
                    "source_class": _source_label(path),
                    "case": _canonical_case(case),
                }
            )
    rows.sort(
        key=lambda r: (
            str(r["case"].get("suite", "")),
            str(r["case"].get("id", "")),
            str(r["case"].get("kind", "")),
            str(r["source_file"]),
        )
    )
    return rows


def _content_hash_case(case: dict[str, Any]) -> str:
    return _sha256_json(case)


def _dataset_hash(cases: list[dict[str, Any]]) -> str:
    payload = [_canonical_case(c) for c in cases]
    return _sha256_json(payload)


def _text_dataset_hash(cases: list[dict[str, Any]]) -> str:
    text_records = build_text_records(cases, text_scope="injection")
    text_records = [r for r in text_records if r.suite in TEXT_SCOPE_INCLUDED_SUITES]
    payload = [{"id": r.id, "suite": r.suite, "kind": r.kind, "label_attack": r.label_attack, "text": r.text} for r in text_records]
    return _sha256_json(payload)


def _git_sha() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            v = proc.stdout.strip()
            if v:
                return v
    except Exception:
        pass
    return "unknown"


def build_dataset(dataset_id: str, manifest_path: Path, output_root: Path) -> Path:
    out_dir = output_root / dataset_id
    out_dir.mkdir(parents=True, exist_ok=True)
    source_date_epoch_raw = os.getenv("SOURCE_DATE_EPOCH")
    source_date_epoch = int(source_date_epoch_raw) if source_date_epoch_raw is not None else None
    built_at_unix = source_date_epoch if source_date_epoch is not None else int(time.time())
    built_at_iso_utc = dt.datetime.fromtimestamp(built_at_unix, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with_prov = _load_cases_with_provenance(manifest_path)
    cases = [row["case"] for row in with_prov]
    dataset_hash = _dataset_hash(cases)
    text_hash = _text_dataset_hash(cases)

    suite_counts = Counter(str(c.get("suite", "unknown")) for c in cases)
    kind_counts = Counter(str(c.get("kind", "unknown")) for c in cases)

    text_records = build_text_records(cases, text_scope="injection")
    text_records = [r for r in text_records if r.suite in TEXT_SCOPE_INCLUDED_SUITES]
    label_counts = Counter("attack" if bool(r.label_attack) else "benign" for r in text_records)
    text_suite_counts = Counter(r.suite for r in text_records)

    case_manifest: list[dict[str, Any]] = []
    id_collisions: dict[str, list[str]] = defaultdict(list)
    for row in with_prov:
        case = row["case"]
        cid = str(case.get("id", ""))
        id_collisions[cid].append(str(row["source_file"]))
        case_manifest.append(
            {
                "id": cid,
                "suite": str(case.get("suite", "")),
                "kind": str(case.get("kind", "")),
                "source_file": str(row["source_file"]),
                "source_class": str(row["source_class"]),
                "case_sha256": _content_hash_case(case),
            }
        )
    case_manifest.sort(key=lambda r: (r["suite"], r["id"], r["kind"], r["source_file"]))

    collision_rows = [
        {"id": cid, "source_files": sorted(paths)}
        for cid, paths in sorted(id_collisions.items())
        if len(set(paths)) > 1
    ]

    cases_jsonl = out_dir / "cases.jsonl"
    with cases_jsonl.open("w") as f:
        for case in cases:
            f.write(json.dumps(case, ensure_ascii=True, sort_keys=True) + "\n")

    manifest_json = out_dir / "case_manifest.json"
    manifest_json.write_text(json.dumps(case_manifest, indent=2, sort_keys=True) + "\n")

    metadata = {
        "dataset_id": dataset_id,
        "dataset_hash_sha256": dataset_hash,
        "text_injection_dataset_hash_sha256": text_hash,
        "manifest_path": str(manifest_path.relative_to(ROOT)) if manifest_path.is_absolute() else str(manifest_path),
        "case_count_total": len(cases),
        "suite_counts": dict(sorted(suite_counts.items())),
        "kind_counts": dict(sorted(kind_counts.items())),
        "text_scope": "injection",
        "text_record_count": len(text_records),
        "text_label_counts": dict(sorted(label_counts.items())),
        "text_suite_counts": dict(sorted(text_suite_counts.items())),
        "case_manifest_sha256": _sha256_text(manifest_json.read_text()),
        "cases_jsonl_sha256": _sha256_text(cases_jsonl.read_text()),
        "duplicate_case_ids_across_sources": collision_rows,
        "source_date_epoch": source_date_epoch,
        "built_at_unix": built_at_unix,
        "built_at_iso_utc": built_at_iso_utc,
        "git_sha": _git_sha(),
        "git_sha_short": git_sha_short(),
        "upstream_sources": _manifest_source_audit(manifest_path),
    }
    (out_dir / "METADATA.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return out_dir


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-id", default="canonical")
    parser.add_argument("--output-root", default=str(DATASETS_ROOT))
    parser.add_argument("--manifest", default=str(UPSTREAM_MANIFEST))
    parser.add_argument("--run-id", default=None, help="Optional run id. If set, also writes benchmarks/runs/<run_id>/METADATA.json.")
    args = parser.parse_args()

    output_root = Path(args.output_root)
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path

    out_dir = build_dataset(
        dataset_id=str(args.dataset_id),
        manifest_path=manifest_path,
        output_root=output_root,
    )
    meta = json.loads((out_dir / "METADATA.json").read_text())
    if args.run_id:
        run_dir = ensure_run_dir(str(args.run_id))
        run_meta = dict(meta)
        run_meta["dataset_dir"] = str(out_dir.relative_to(ROOT))
        (run_dir / "METADATA.json").write_text(json.dumps(run_meta, indent=2, sort_keys=True) + "\n")
        print(f"run metadata: {run_dir / 'METADATA.json'}")
    print(f"dataset dir: {out_dir}")
    print(f"dataset hash: {meta['dataset_hash_sha256']}")
    print(f"text dataset hash: {meta['text_injection_dataset_hash_sha256']}")
    print(f"case count: {meta['case_count_total']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
