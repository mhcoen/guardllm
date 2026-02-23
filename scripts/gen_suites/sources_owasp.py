#!/usr/bin/env python3
"""Build owasp_payload.txt pool from OWASP CRS regression tests and PayloadsAllTheThings.

Sources:
  1. OWASP Core Rule Set regression tests (Apache 2.0)
     https://github.com/coreruleset/coreruleset
     Extracts input.data from YAML test cases in tests/regression/tests/.

  2. PayloadsAllTheThings (MIT)
     https://github.com/swisskyrepo/PayloadsAllTheThings
     Reads line-per-payload text files from Intruder/ directories across
     SQLi, XSS, command injection, LDAP, XXE, NoSQL, directory traversal.

Writes one payload per line to cache/owasp_payload.txt.
Writes provenance metadata to cache/owasp_payload_provenance.json.

Usage:
  python3 scripts/gen_suites/sources_owasp.py --cache_dir artifacts/suites/cache
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPOS = {
    "coreruleset": "https://github.com/coreruleset/coreruleset.git",
    "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
}
DEFAULT_CLONE_ROOT = Path("/tmp")

# PayloadsAllTheThings directories to read (relative to repo root).
# Each entry: (subdirectory containing Intruder/*.txt, category label)
PATT_DIRS = [
    ("SQL Injection/Intruder", "sqli"),
    ("XSS Injection/Intruders", "xss"),
    ("Command Injection/Intruder", "cmdi"),
    ("LDAP Injection/Intruder", "ldapi"),
    ("XXE Injection/Intruders", "xxe"),
    ("NoSQL Injection/Intruder", "nosqli"),
    ("Directory Traversal/Intruder", "pathtraver"),
    ("CRLF Injection/Files", "crlf"),
    ("Server Side Include Injection/Files", "ssi"),
]

# CRS test directories to read (relative to tests/regression/tests/).
CRS_DIRS = [
    "REQUEST-930-APPLICATION-ATTACK-LFI",
    "REQUEST-931-APPLICATION-ATTACK-RFI",
    "REQUEST-932-APPLICATION-ATTACK-RCE",
    "REQUEST-933-APPLICATION-ATTACK-PHP",
    "REQUEST-934-APPLICATION-ATTACK-GENERIC",
    "REQUEST-941-APPLICATION-ATTACK-XSS",
    "REQUEST-942-APPLICATION-ATTACK-SQLI",
    "REQUEST-944-APPLICATION-ATTACK-JAVA",
]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def clone_or_update(name: str, url: str, root: Path) -> tuple[Path, str]:
    """Clone or update a repo. Returns (path, HEAD commit)."""
    dest = root / name
    if dest.exists():
        subprocess.run(
            ["git", "fetch", "--all", "--prune"],
            cwd=str(dest), capture_output=True,
        )
    else:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            capture_output=True, check=True,
        )
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(dest), capture_output=True, text=True, check=True,
    )
    return dest, result.stdout.strip()


def extract_crs_payloads(repo: Path) -> list[tuple[str, str]]:
    """Extract input.data payloads from CRS YAML regression tests.

    Returns (category, payload) pairs.
    """
    try:
        import yaml
    except ImportError:
        print("  WARNING: PyYAML not installed, skipping CRS extraction", file=sys.stderr)
        return []

    test_root = repo / "tests" / "regression" / "tests"
    if not test_root.exists():
        print(f"  WARNING: {test_root} not found", file=sys.stderr)
        return []

    entries: list[tuple[str, str]] = []
    for crs_dir_name in CRS_DIRS:
        crs_dir = test_root / crs_dir_name
        if not crs_dir.exists():
            continue
        # Derive a short category label from the directory name
        # e.g. REQUEST-942-APPLICATION-ATTACK-SQLI -> sqli
        parts = crs_dir_name.split("-")
        category = parts[-1].lower() if parts else "unknown"

        for yaml_file in sorted(crs_dir.glob("*.yaml")):
            try:
                with yaml_file.open("r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
            except Exception:
                continue
            if not isinstance(doc, dict):
                continue
            for test in doc.get("tests", []):
                for stage in test.get("stages", []):
                    inp = stage.get("input", {})
                    data = inp.get("data", "")
                    if isinstance(data, str) and data.strip():
                        entries.append((category, data.strip()))
                    # Also grab URI if it looks like an attack vector
                    uri = inp.get("uri", "")
                    if isinstance(uri, str) and len(uri) > 5 and uri != "/post":
                        entries.append((category, uri.strip()))

    return entries


def extract_patt_payloads(repo: Path) -> list[tuple[str, str]]:
    """Extract payloads from PayloadsAllTheThings text files.

    Returns (category, payload) pairs.
    """
    entries: list[tuple[str, str]] = []
    for subdir, category in PATT_DIRS:
        full_dir = repo / subdir
        if not full_dir.exists():
            continue
        for txt_file in sorted(full_dir.glob("*.txt")):
            try:
                lines = txt_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            for line in lines:
                line = line.strip()
                if line:
                    entries.append((category, line))

    return entries


def main():
    ap = argparse.ArgumentParser(
        description="Build owasp_payload.txt pool from CRS + PayloadsAllTheThings"
    )
    ap.add_argument("--cache_dir", required=True)
    ap.add_argument("--clone_root", default=str(DEFAULT_CLONE_ROOT))
    args = ap.parse_args()

    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    clone_root = Path(args.clone_root)

    # Clone / update repos
    provenance: dict[str, dict] = {}
    for name, url in REPOS.items():
        print(f"  Cloning/updating {name}...", file=sys.stderr)
        repo_path, commit = clone_or_update(name, url, clone_root)
        provenance[name] = {
            "repo_url": url,
            "commit": commit,
            "path": str(repo_path),
        }

    crs_repo = clone_root / "coreruleset"
    patt_repo = clone_root / "PayloadsAllTheThings"

    # Extract
    crs_entries = extract_crs_payloads(crs_repo)
    print(f"  CRS payloads extracted: {len(crs_entries)}", file=sys.stderr)

    patt_entries = extract_patt_payloads(patt_repo)
    print(f"  PayloadsAllTheThings extracted: {len(patt_entries)}", file=sys.stderr)

    all_entries = crs_entries + patt_entries

    # Per-category counts before dedup
    from collections import Counter
    cat_counts_raw = Counter(c for c, _ in all_entries)
    print(f"  Per-category (raw):", file=sys.stderr)
    for cat, count in cat_counts_raw.most_common():
        print(f"    {cat}: {count}", file=sys.stderr)

    # Deduplicate by payload text, collapse whitespace
    seen: set[str] = set()
    deduped: list[str] = []
    cat_counts: Counter = Counter()
    for category, text in all_entries:
        clean = " ".join(text.split())
        if not clean or len(clean) < 3:
            continue
        h = sha256_bytes(clean.encode("utf-8"))
        if h in seen:
            continue
        seen.add(h)
        deduped.append(clean)
        cat_counts[category] += 1

    print(f"  Total unique payloads: {len(deduped)}", file=sys.stderr)
    print(f"  Per-category (deduped):", file=sys.stderr)
    for cat, count in cat_counts.most_common():
        print(f"    {cat}: {count}", file=sys.stderr)

    # Cap directory traversal to avoid overwhelming the pool
    # (dotdotpwn.txt alone has ~20k entries)
    MAX_PER_CATEGORY = 300
    if cat_counts.get("pathtraver", 0) > MAX_PER_CATEGORY:
        # Re-filter: keep only MAX_PER_CATEGORY pathtraver entries
        import random
        rng = random.Random(20260222)
        final: list[str] = []
        pathtraver_entries: list[str] = []
        seen2: set[str] = set()
        for category, text in all_entries:
            clean = " ".join(text.split())
            if not clean or len(clean) < 3:
                continue
            h = sha256_bytes(clean.encode("utf-8"))
            if h in seen2:
                continue
            seen2.add(h)
            if category == "pathtraver":
                pathtraver_entries.append(clean)
            else:
                final.append(clean)
        rng.shuffle(pathtraver_entries)
        final.extend(pathtraver_entries[:MAX_PER_CATEGORY])
        rng.shuffle(final)
        deduped = final
        print(f"  After capping pathtraver to {MAX_PER_CATEGORY}: {len(deduped)} total", file=sys.stderr)

    # Write output
    out_path = cache_dir / "owasp_payload.txt"
    with out_path.open("w", encoding="utf-8") as f:
        for line in deduped:
            f.write(line + "\n")

    # Write provenance
    meta = {
        "sources": provenance,
        "crs_test_dirs": CRS_DIRS,
        "patt_intruder_dirs": [d for d, _ in PATT_DIRS],
        "total_lines": len(deduped),
        "category_counts": dict(cat_counts.most_common()),
        "output_sha256": sha256_bytes(out_path.read_bytes()),
    }
    meta_path = cache_dir / "owasp_payload_provenance.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"Wrote {out_path}: {len(deduped)} lines", file=sys.stderr)
    print(f"Wrote {meta_path}", file=sys.stderr)
    if len(deduped) < 200:
        print(f"WARNING: only {len(deduped)} lines (need >= 200)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
