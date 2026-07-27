from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"


def test_generated_demos_are_current_and_self_contained():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_demos.py"), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    fixture = json.loads((DEMO / "guardllm_demo_fixtures.json").read_text())
    assert fixture["scenarios"]["rag"]["derived_metrics"]["display_percentage"] == 31
    assert fixture["scenarios"]["escalation"]["fresh_search"]["allowed"] is True
    assert fixture["scenarios"]["escalation"]["escalated_search"]["allowed"] is False
    assert fixture["scenarios"]["dlp_canary"]["canary_result"]["canary_detected"] is True

    for path in DEMO.glob("*.html"):
        page = path.read_text()
        assert "fetch(" not in page
        assert "setTimeout(" not in page
        assert "prefers-reduced-motion" in page
        assert page.count("Boundary 1") == 1
        assert page.count("Boundary 2") == 1
        assert page.count("Boundary 3") == 1
        assert page.count("Boundary 4") == 1
        assert "Per-flow context" in page
        assert "Per-session state" in page
        if path.name != "guardllm_surface_map.html":
            assert 'id="guardllm-behavior"' in page
            assert 'class="evidence-strip"' in page
            assert "Exact test:" in page
            assert "On this path" in page

    spine = (DEMO / "guardllm_demos.html").read_text()
    for heading in (
        "The job",
        "The attack surface",
        "What the demo application sends",
        "The unprotected run",
        "The protected run",
        "Generalize",
        "Why detection is not the whole design",
    ):
        assert heading in spine
    assert spine.count('class="message"') == 3

    binding = (DEMO / "guardllm_request_binding_demo.html").read_text()
    policy = (DEMO / "guardllm_policy_matrix_demo.html").read_text()
    assert 'class="controls"' not in binding
    assert 'class="controls"' not in policy


def test_superseded_policy_variants_are_absent():
    assert not (DEMO / "guardllm_policy_matrix_demo_v2.html").exists()
    assert not (DEMO / "guardllm_policy_matrix_demo_v3.html").exists()
