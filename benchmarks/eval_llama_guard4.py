"""Evaluate Llama Guard 4 (12B) as a text-only prompt-injection detector.

Standalone script designed for GPU execution (e.g. RunPod with A6000/A100).
Results can be merged into the main comparison table via:
  python benchmarks/compare_mitigations.py --llama-guard-results <results.json>

Usage:
  python benchmarks/eval_llama_guard4.py --run-id <run_id>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from _bootstrap import ROOT  # noqa: F401
from output_layout import ensure_cache_dir, ensure_run_dir, git_sha_short
from run_benchmarks import load_cases
from compare_mitigations import build_text_records, TextRecord


DEFAULT_MODEL_ID = "meta-llama/Llama-Guard-4-12B"
DEFAULT_MAX_NEW_TOKENS = 20
DEFAULT_DTYPE = "bf16"
DEFAULT_TEXT_SCOPE = "injection"


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _repo_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except Exception:
        return str(path)


def _parse_guard_response(raw: str) -> tuple[bool, str | None]:
    """Parse Llama Guard 4 output into (pred_attack, category_code).

    Returns (False, None) for "safe", (True, <codes>) for "unsafe\\nS<N>".
    """
    lines = raw.strip().splitlines()
    if not lines:
        return False, None
    first = lines[0].strip().lower()
    if first == "safe":
        return False, None
    if first == "unsafe":
        category = lines[1].strip() if len(lines) > 1 else None
        return True, category
    # Fallback: treat unrecognized output as safe (conservative)
    return False, None


class LlamaGuard4Classifier:
    """Lazy-loading wrapper around Llama Guard 4 for text classification."""

    def __init__(
        self,
        *,
        model_id: str,
        hf_revision: str | None,
        cache_dir: Path,
        max_new_tokens: int = DEFAULT_MAX_NEW_TOKENS,
        dtype: str = DEFAULT_DTYPE,
    ) -> None:
        self.model_id = model_id
        self.hf_revision_requested = hf_revision
        self.hf_revision_resolved = hf_revision or "unknown"
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_new_tokens = int(max_new_tokens)
        self.dtype = dtype

        self._loaded = False
        self._processor: Any = None
        self._model: Any = None
        self._torch: Any = None

    def _resolve_hf_revision(self) -> None:
        if self.hf_revision_requested:
            self.hf_revision_resolved = self.hf_revision_requested
            return
        try:
            from huggingface_hub import model_info  # type: ignore

            info = model_info(self.model_id)
            sha = getattr(info, "sha", None)
            if isinstance(sha, str) and sha:
                self.hf_revision_resolved = sha
        except Exception:
            pass

    def _load(self) -> None:
        if self._loaded:
            return
        try:
            import torch  # type: ignore
            from transformers import AutoProcessor, Llama4ForConditionalGeneration  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "Missing dependencies for Llama Guard 4. "
                "Install: pip install torch transformers huggingface_hub"
            ) from exc

        self._resolve_hf_revision()

        dtype_map = {
            "bf16": torch.bfloat16,
            "bfloat16": torch.bfloat16,
            "fp16": torch.float16,
            "float16": torch.float16,
        }
        torch_dtype = dtype_map.get(self.dtype, torch.bfloat16)

        model_kwargs: dict[str, Any] = {"device_map": "cuda", "dtype": torch_dtype}
        proc_kwargs: dict[str, Any] = {}
        if self.hf_revision_requested:
            model_kwargs["revision"] = self.hf_revision_requested
            proc_kwargs["revision"] = self.hf_revision_requested

        self._processor = AutoProcessor.from_pretrained(self.model_id, **proc_kwargs)
        self._model = Llama4ForConditionalGeneration.from_pretrained(self.model_id, **model_kwargs)

        # Llama Guard 4 is pruned from Llama 4 Scout which uses chunked attention,
        # but the Guard config may omit attention_chunk_size. Patch it if missing.
        cfg = self._model.config
        text_cfg = getattr(cfg, "text_config", cfg)
        if not getattr(text_cfg, "attention_chunk_size", None):
            text_cfg.attention_chunk_size = 8192

        self._model.eval()
        self._torch = torch

        commit_hash = getattr(getattr(self._model, "config", None), "_commit_hash", None)
        if isinstance(commit_hash, str) and commit_hash:
            self.hf_revision_resolved = commit_hash

        self._loaded = True

    def _cache_key(self, record: TextRecord) -> str:
        material = json.dumps(
            {
                "model_id": self.model_id,
                "hf_revision": self.hf_revision_resolved,
                "record_id": record.id,
                "record_text": record.text,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return _sha256_text(material)

    def classify(self, record: TextRecord) -> dict[str, Any]:
        """Classify a single TextRecord. Returns a result dict with caching."""
        self._resolve_hf_revision()
        key = self._cache_key(record)
        cache_file = self.cache_dir / f"{key}.json"

        if cache_file.exists():
            cached = json.loads(cache_file.read_text())
            cached["cache_hit"] = True
            return cached

        self._load()

        messages = [{"role": "user", "content": [{"type": "text", "text": record.text}]}]
        inputs = self._processor.apply_chat_template(
            messages,
            tokenize=True,
            return_tensors="pt",
            return_dict=True,
        ).to(self._model.device)

        t0 = time.perf_counter()
        with self._torch.no_grad():
            output_ids = self._model.generate(
                **inputs,
                do_sample=False,
                max_new_tokens=self.max_new_tokens,
            )
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        prompt_len = int(inputs["input_ids"].shape[1])
        gen_ids = output_ids[0][prompt_len:]
        raw_response = self._processor.decode(gen_ids, skip_special_tokens=True).strip()

        pred_attack, category = _parse_guard_response(raw_response)

        result = {
            "cache_key": key,
            "model_id": self.model_id,
            "hf_revision": self.hf_revision_resolved,
            "record_id": record.id,
            "pred_attack": pred_attack,
            "raw_response": raw_response,
            "category": category,
            "latency_ms": latency_ms,
            "created_at_utc": _iso_utc_now(),
            "cache_hit": False,
        }
        cache_file.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        return result


def _write_results_md(
    *,
    out_path: Path,
    run_id: str,
    model_id: str,
    hf_revision: str,
    record_count: int,
    tp: int,
    tn: int,
    fp: int,
    fn: int,
    accuracy: float,
    precision: float,
    recall: float,
    f1: float,
    cache_hits: int,
    cache_writes: int,
    elapsed_s: float,
) -> None:
    lines = [
        "# Llama Guard 4 Evaluation Results",
        "",
        f"- run_id: `{run_id}`",
        f"- model: `{model_id}`",
        f"- hf_revision: `{hf_revision}`",
        f"- record_count: `{record_count}`",
        f"- elapsed: `{elapsed_s:.1f}s`",
        f"- cache: `{cache_hits} hits, {cache_writes} writes`",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|--------|------:|",
        f"| TP | {tp} |",
        f"| TN | {tn} |",
        f"| FP | {fp} |",
        f"| FN | {fn} |",
        f"| Accuracy | {accuracy}% |",
        f"| Precision | {precision}% |",
        f"| Recall | {recall}% |",
        f"| F1 | {f1}% |",
        "",
    ]
    out_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Llama Guard 4 on text benchmark records.")
    parser.add_argument("--run-id", required=True, help="Run identifier for output directory.")
    parser.add_argument("--suite", default=None, help="Filter to one suite.")
    parser.add_argument("--text-scope", default=DEFAULT_TEXT_SCOPE, choices=["injection", "all"],
                        help="Scope for text benchmark records.")
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID, help="HuggingFace model identifier.")
    parser.add_argument("--hf-revision", default=None, help="Specific HF model revision/commit.")
    parser.add_argument("--cache-dir", default="benchmarks/cache/llama_guard4_eval/",
                        help="Directory for per-record inference cache.")
    parser.add_argument("--max-new-tokens", type=int, default=DEFAULT_MAX_NEW_TOKENS,
                        help="Maximum tokens to generate per record.")
    parser.add_argument("--dtype", default=DEFAULT_DTYPE, choices=["bf16", "bfloat16", "fp16", "float16"],
                        help="Model precision.")
    parser.add_argument("--progress-seconds", type=float, default=30.0,
                        help="Emit progress updates every N seconds (0 disables).")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit to first N records (0 = all, useful for dev).")
    args = parser.parse_args()

    ensure_cache_dir()
    run_dir = ensure_run_dir(args.run_id) / "llama_guard4_eval"
    run_dir.mkdir(parents=True, exist_ok=True)

    cache_dir = Path(args.cache_dir)
    if not cache_dir.is_absolute():
        cache_dir = ROOT / cache_dir
    cache_dir.mkdir(parents=True, exist_ok=True)

    cases = load_cases(args.suite)
    if not cases:
        print("No benchmark cases found.")
        return 1

    records = build_text_records(cases, text_scope=args.text_scope)
    if args.limit > 0:
        records = records[: args.limit]

    print(f"Records to evaluate: {len(records)}")
    print(f"Model: {args.model_id}")
    print(f"Cache dir: {_repo_rel(cache_dir)}")
    print(f"Output dir: {_repo_rel(run_dir)}")

    classifier = LlamaGuard4Classifier(
        model_id=args.model_id,
        hf_revision=args.hf_revision,
        cache_dir=cache_dir,
        max_new_tokens=args.max_new_tokens,
        dtype=args.dtype,
    )

    predictions: list[dict[str, Any]] = []
    cache_hits = 0
    cache_writes = 0
    latencies: list[float] = []

    started = time.perf_counter()
    last_progress = started

    for idx, record in enumerate(records, start=1):
        result = classifier.classify(record)

        if result.get("cache_hit"):
            cache_hits += 1
        else:
            cache_writes += 1

        latency = result.get("latency_ms", 0.0)
        if not result.get("cache_hit"):
            latencies.append(latency)

        predictions.append({
            "id": record.id,
            "suite": record.suite,
            "kind": record.kind,
            "label_attack": record.label_attack,
            "pred_attack": result["pred_attack"],
            "raw_response": result.get("raw_response", ""),
            "category": result.get("category"),
            "latency_ms": latency,
        })

        now = time.perf_counter()
        if args.progress_seconds > 0 and (now - last_progress >= args.progress_seconds or idx == len(records)):
            elapsed = now - started
            rate = idx / elapsed if elapsed > 0 else 0
            print(
                f"[progress] {idx}/{len(records)} records, "
                f"elapsed={elapsed:.1f}s, rate={rate:.1f}/s, "
                f"cache_hits={cache_hits}, cache_writes={cache_writes}",
                flush=True,
            )
            last_progress = now

    elapsed_total = time.perf_counter() - started

    # Compute metrics
    tp = tn = fp = fn = 0
    by_suite: dict[str, dict[str, int]] = {}
    for row in predictions:
        label = bool(row["label_attack"])
        pred = bool(row["pred_attack"])
        if label and pred:
            tp += 1
        elif (not label) and (not pred):
            tn += 1
        elif (not label) and pred:
            fp += 1
        else:
            fn += 1

        suite_stats = by_suite.setdefault(row["suite"], {"total": 0, "correct": 0})
        suite_stats["total"] += 1
        suite_stats["correct"] += 1 if label == pred else 0

    total = len(predictions)
    accuracy = round(((tp + tn) / total) * 100, 2) if total else 0.0
    precision = round((tp / (tp + fp)) * 100, 2) if (tp + fp) else 0.0
    recall = round((tp / (tp + fn)) * 100, 2) if (tp + fn) else 0.0
    f1 = round((2 * precision * recall / (precision + recall)), 2) if (precision + recall) else 0.0

    by_suite_accuracy = {
        s: round((v["correct"] / v["total"]) * 100, 2) if v["total"] else 0.0
        for s, v in by_suite.items()
    }

    # Latency stats
    latency_stats: dict[str, float] = {}
    if latencies:
        sorted_lat = sorted(latencies)
        latency_stats = {
            "avg": round(sum(sorted_lat) / len(sorted_lat), 2),
            "p50": round(sorted_lat[len(sorted_lat) // 2], 2),
            "p95": round(sorted_lat[min(len(sorted_lat) - 1, int(round((len(sorted_lat) - 1) * 0.95)))], 2),
            "max": round(sorted_lat[-1], 2),
        }

    payload = {
        "run_id": args.run_id,
        "timestamp_utc": _iso_utc_now(),
        "model_id": args.model_id,
        "hf_revision_resolved": classifier.hf_revision_resolved,
        "text_scope": args.text_scope,
        "dtype": args.dtype,
        "max_new_tokens": args.max_new_tokens,
        "record_count": total,
        "metrics": {
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "by_suite_accuracy": by_suite_accuracy,
        },
        "latency_ms": latency_stats,
        "cache": {
            "dir": _repo_rel(cache_dir),
            "hits": cache_hits,
            "writes": cache_writes,
        },
        "elapsed_seconds": round(elapsed_total, 2),
        "predictions": predictions,
        "script": {
            "path": "benchmarks/eval_llama_guard4.py",
            "git_sha_short": git_sha_short(),
        },
    }

    results_json = run_dir / "results.json"
    results_md = run_dir / "results.md"
    manifest_json = run_dir / "MANIFEST.json"

    results_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    _write_results_md(
        out_path=results_md,
        run_id=args.run_id,
        model_id=args.model_id,
        hf_revision=classifier.hf_revision_resolved,
        record_count=total,
        tp=tp, tn=tn, fp=fp, fn=fn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        cache_hits=cache_hits,
        cache_writes=cache_writes,
        elapsed_s=elapsed_total,
    )

    manifest = {
        "run_id": args.run_id,
        "generated_at_utc": _iso_utc_now(),
        "results_json_sha256": _sha256_file(results_json),
        "results_md_sha256": _sha256_file(results_md),
    }
    manifest_json.write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"wrote {_repo_rel(results_json)}")
    print(f"wrote {_repo_rel(results_md)}")
    print(f"wrote {_repo_rel(manifest_json)}")
    print(
        f"metrics: accuracy={accuracy}% precision={precision}% "
        f"recall={recall}% f1={f1}%"
    )
    print(f"confusion: tp={tp} tn={tn} fp={fp} fn={fn}")
    print(f"cache: hits={cache_hits} writes={cache_writes}")
    print(f"elapsed: {elapsed_total:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
