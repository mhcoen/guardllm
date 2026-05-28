#!/usr/bin/env python3
"""Build llm_injection.txt pool from InjecAgent, AgentDojo, PINT, Giskard.

Reuses the same repos as gen_cbx1000.py (expects them at /tmp/cbx_repos/).
Writes one attack string per line to the cache directory.

Usage:
  python3 scripts/gen_suites/sources_llm.py --cache_dir artifacts/suites/cache
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_DIR = Path("/tmp/cbx_repos")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_jsonl_texts(path: Path, text_fields: list[str]) -> list[str]:
    out: list[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            for tf in text_fields:
                v = obj.get(tf)
                if isinstance(v, str) and v.strip():
                    out.append(v.strip())
    return out


def read_csv_column(path: Path, colname: str) -> list[str]:
    out: list[str] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            v = row.get(colname, "")
            if isinstance(v, str) and v.strip():
                out.append(v.strip())
    return out


def extract_agentdojo_attacks(ad: Path) -> list[str]:
    """Extract attack strings from AgentDojo Python source."""
    templates: list[str] = []
    attack_dir = ad / "src" / "agentdojo" / "attacks"
    if not attack_dir.exists():
        return []

    for pyfile in sorted(attack_dir.glob("*.py")):
        content = pyfile.read_text(encoding="utf-8")
        for m in re.finditer(
            r'super\(\)\.__init__\(\s*\n?\s*"((?:[^"\\]|\\.)*)"\s*,',
            content,
        ):
            tpl = m.group(1).replace("\\n", "\n").replace('\\"', '"')
            if "{goal}" in tpl and len(tpl) > 5:
                templates.append(tpl)
        for m in re.finditer(
            r'_(?:JB|DOS)_STRING\s*=\s*\(\s*((?:\s*"(?:[^"\\]|\\.)*"\s*)+)\)',
            content,
        ):
            raw_parts = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
            tpl = "".join(raw_parts).replace("\\n", "\n").replace('\\"', '"')
            if "{goal}" in tpl and len(tpl) > 10:
                templates.append(tpl)

    goals: list[str] = []
    suites_dir = ad / "src" / "agentdojo" / "default_suites" / "v1"
    if suites_dir.exists():
        for suite_dir in sorted(suites_dir.iterdir()):
            task_file = suite_dir / "injection_tasks.py"
            if not task_file.exists():
                continue
            content = task_file.read_text(encoding="utf-8")
            for m in re.finditer(r'GOAL\s*=\s*f?"((?:[^"\\]|\\.)*)"', content):
                g = m.group(1).strip()
                if g:
                    goals.append(g)
            for m in re.finditer(r"GOAL\s*=\s*f?'((?:[^'\\]|\\.)*)'", content):
                g = m.group(1).strip()
                if g:
                    goals.append(g)

    def fill_goal(goal: str) -> str:
        goal = re.sub(r"\{_?ATTACKER_IBAN\}", "GB82WEST12345698765432", goal)
        goal = re.sub(r"\{_RECIPIENT\}", "attacker@evil.com", goal)
        goal = re.sub(r"\{_TEXT\}", "sensitive internal data", goal)
        goal = re.sub(r"\{_SUBJECT\}", "urgent request", goal)
        goal = re.sub(r"\{_SENDER\}", "admin@company.com", goal)
        goal = re.sub(r"\{_FILE_ID\}", "file_abc123", goal)
        goal = re.sub(r"\{_PARTICIPANT\}", "attacker@evil.com", goal)
        goal = re.sub(r"\{_START_TIME\}", "2024-05-01 10:00", goal)
        goal = re.sub(r"\{_TITLE\}", "Team Sync", goal)
        goal = re.sub(r"\{_NEW_PASSWORD\}", "hacked123!", goal)
        goal = re.sub(r"\{_ATTACKER_USER\}", "attacker_user", goal)
        goal = re.sub(r"\{_ATTACKER_EMAIL\}", "attacker@evil.com", goal)
        goal = re.sub(r"\{_TARGET\}", "Hotel Paradiso", goal)
        goal = re.sub(r"\{[^}]+\}", "TARGET_VALUE", goal)
        return goal

    results = []
    for tpl in templates:
        for goal in goals:
            attack = tpl.replace("{goal}", fill_goal(goal))
            attack = attack.replace("{user}", "Emma Johnson")
            attack = attack.replace("{model}", "the AI assistant")
            attack = attack.replace("{task}", "the current task")
            results.append(attack.strip())

    return results


def read_yaml_texts(path: Path) -> list[str]:
    """Read injection-labeled text entries from PINT YAML files."""
    try:
        import yaml
    except ImportError:
        out: list[str] = []
        content = path.read_text(encoding="utf-8")
        for m in re.finditer(r'-\s+text:\s*"((?:[^"\\]|\\.)*)"', content):
            txt = m.group(1).strip()
            if txt:
                out.append(txt)
        return out
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if isinstance(item, dict):
            txt = item.get("text", "")
            if isinstance(txt, str) and txt.strip():
                if item.get("label") is True:
                    out.append(txt.strip())
    return out


def main():
    ap = argparse.ArgumentParser(description="Build llm_injection.txt pool")
    ap.add_argument("--cache_dir", required=True)
    ap.add_argument("--repo_dir", default=str(REPO_DIR))
    args = ap.parse_args()

    cache_dir = Path(args.cache_dir)
    repo_dir = Path(args.repo_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    all_texts: list[str] = []

    # InjecAgent
    inj = repo_dir / "injecagent"
    if inj.exists():
        for p in [
            inj / "data" / "attacker_cases_ds.jsonl",
            inj / "data" / "attacker_cases_dh.jsonl",
        ]:
            if p.exists():
                all_texts.extend(
                    read_jsonl_texts(
                        p, ["Attacker Instruction", "attack", "attacker_prompt", "prompt", "text"]
                    )
                )
        print(f"  InjecAgent: {len(all_texts)} texts so far", file=sys.stderr)

    # AgentDojo
    ad = repo_dir / "agentdojo"
    if ad.exists():
        before = len(all_texts)
        all_texts.extend(extract_agentdojo_attacks(ad))
        print(f"  AgentDojo: {len(all_texts) - before} texts", file=sys.stderr)

    # PINT
    pint = repo_dir / "pint"
    if pint.exists():
        before = len(all_texts)
        for p in pint.rglob("*.jsonl"):
            all_texts.extend(read_jsonl_texts(p, ["prompt", "attack", "text", "input"]))
        for p in pint.rglob("*.csv"):
            try:
                all_texts.extend(read_csv_column(p, "prompt"))
            except Exception:
                pass
        for p in pint.rglob("*.yaml"):
            all_texts.extend(read_yaml_texts(p))
        print(f"  PINT: {len(all_texts) - before} texts", file=sys.stderr)

    # Giskard
    gk = repo_dir / "giskard"
    if gk.exists():
        before = len(all_texts)
        for p in gk.rglob("*.csv"):
            if p.name.lower() == "prompt_injections.csv":
                all_texts.extend(read_csv_column(p, "prompt"))
        print(f"  Giskard: {len(all_texts) - before} texts", file=sys.stderr)

    # Deduplicate and clean: one-line entries (replace newlines with spaces)
    seen: set[str] = set()
    deduped: list[str] = []
    for t in all_texts:
        clean = " ".join(t.split())  # collapse whitespace to single spaces
        if not clean or len(clean) < 10:
            continue
        h = sha256_bytes(clean.encode("utf-8"))
        if h in seen:
            continue
        seen.add(h)
        deduped.append(clean)

    out_path = cache_dir / "llm_injection.txt"
    with out_path.open("w", encoding="utf-8") as f:
        for t in deduped:
            f.write(t + "\n")

    print(f"Wrote {out_path}: {len(deduped)} lines", file=sys.stderr)
    if len(deduped) < 200:
        print(f"WARNING: only {len(deduped)} lines (need >= 200)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
