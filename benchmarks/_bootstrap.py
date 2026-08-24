"""Import bootstrap for benchmark scripts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def dataset_hash(cases: list[dict]) -> str:
    """The one dataset hash. Every producer and consumer must use this.

    Three copies existed and two disagreed: the builder serialized with
    compact separators and ensure_ascii=False, while the evaluators used
    default separators and ensure_ascii=True. Identical case lists therefore
    produced different hashes depending on which script wrote them, so the
    value in METADATA.json could never be compared to the one in
    comparison.json and neither could confirm the other had evaluated the same
    data. That is the whole purpose of the field.

    Hashes the full case dicts, content and expected outcomes included, not
    just identity fields: a hash that cannot detect a changed input or a
    flipped label does not pin what was evaluated. Enumerating content fields
    was the original mistake, since the schema carries a different set per
    kind, so the whole dict is hashed with sorted keys instead.
    """
    raw = json.dumps(cases, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()
