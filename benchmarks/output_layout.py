from __future__ import annotations

import datetime as _dt
import subprocess
from pathlib import Path


BENCH_ROOT = Path(__file__).resolve().parent
RUNS_ROOT = BENCH_ROOT / "runs"
CACHE_ROOT = BENCH_ROOT / "cache"
DATASETS_ROOT = BENCH_ROOT / "datasets"
LATEST_PTR = RUNS_ROOT / "LATEST.txt"


def git_sha_short(default: str = "unknown") -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=BENCH_ROOT.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            out = proc.stdout.strip()
            if out:
                return out
    except Exception:
        pass
    return default


def make_run_id(prefix: str) -> str:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{ts}-{git_sha_short()}"


def ensure_run_dir(run_id: str) -> Path:
    run_dir = RUNS_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def ensure_cache_dir() -> Path:
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    return CACHE_ROOT


def ensure_dataset_dir(dataset_id: str) -> Path:
    dataset_dir = DATASETS_ROOT / dataset_id
    dataset_dir.mkdir(parents=True, exist_ok=True)
    return dataset_dir


def write_latest_pointer(run_id: str) -> None:
    RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    LATEST_PTR.write_text(run_id + "\n")


def read_latest_pointer() -> str | None:
    if not LATEST_PTR.exists():
        return None
    value = LATEST_PTR.read_text().strip()
    return value or None
