from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

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
    assert fixture["schema_version"] == 4
    assert fixture["library_version"] == version("guardllm")
    assert fixture["scenarios"]["rag"]["derived_metrics"]["display_percentage"] == 31
    assert fixture["scenarios"]["escalation"]["fresh_search"]["allowed"] is True
    assert fixture["scenarios"]["escalation"]["escalated_search"]["allowed"] is False
    assert fixture["scenarios"]["dlp_canary"]["canary_result"]["canary_detected"] is True

    for path in DEMO.glob("*.html"):
        page = path.read_text()
        assert "fetch(" not in page
        assert "setTimeout(" not in page
        assert "prefers-reduced-motion" in page
        if path.name in {"guardllm_demos.html", "guardllm_surface_map.html"}:
            assert page.count("Boundary 1") == 1
            assert page.count("Boundary 2") == 1
            assert page.count("Boundary 3") == 1
            assert page.count("Boundary 4") == 1
            assert "Per-flow context" in page
            assert "Per-session state" in page
        else:
            assert '<div class="path-strip"' in page
            assert "You are here" in page
            assert "Boundary 1" not in page
        if path.name != "guardllm_surface_map.html":
            assert 'id="guardllm-behavior"' in page
            assert 'class="evidence-strip"' in page
            assert "Exact fixture test:" in page
            sections = re.findall(r"<section class=\"step\"[^>]*>", page)
            assert sections
            assert all(" hidden" not in section for section in sections)
            assert all("aria-current" not in section for section in sections)

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
    assert "Processed email tool message" in spine
    assert "&lt;untrusted_content" in spine
    assert 'class="controls" hidden' in spine
    assert "show(0,false)" in spine
    assert "if(moveFocus)steps[current].focus()" in spine
    assert spine.index('<div class="steps">') < spine.index('<div class="system-map"')

    binding = (DEMO / "guardllm_request_binding_demo.html").read_text()
    policy = (DEMO / "guardllm_policy_matrix_demo.html").read_text()
    dlp = (DEMO / "guardllm_canary_demos.html").read_text()
    rag = (DEMO / "guardllm_rag_demos.html").read_text()
    assert 'class="controls"' not in binding
    assert 'class="controls"' not in policy
    assert "Binding expired (TTL exceeded)" in binding
    assert '<table><thead><tr><th scope="col">' in policy
    assert '<th scope="row">' in policy
    assert "Tool &#x27;search&#x27; not in session allowlist" in policy
    assert "independent comparisons, not one five-step session" in dlp
    assert "One pipeline registers the retrieved span once" in rag


def test_superseded_policy_variants_are_absent():
    assert not (DEMO / "guardllm_policy_matrix_demo_v2.html").exists()
    assert not (DEMO / "guardllm_policy_matrix_demo_v3.html").exists()


def test_interaction_script_keyboard_focus_and_announcements():
    if shutil.which("node") is None:
        pytest.skip("Node.js is not available for the interaction behavior check")

    page = (DEMO / "guardllm_demos.html").read_text()
    behavior = "const steps=" + page.split("const steps=", 1)[1].split("</script>", 1)[0]
    harness = r"""
const assert = require('node:assert/strict');
function step(title) {
  return {
    hidden: false,
    attributes: new Set(),
    focusCount: 0,
    toggleAttribute(name, enabled) { enabled ? this.attributes.add(name) : this.attributes.delete(name); },
    querySelector() { return {textContent: title}; },
    focus() { this.focusCount += 1; },
  };
}
const fakeSteps = [step('1. First'), step('2. Second'), step('3. Third')];
const controls = {hidden: true};
const elements = {
  back: {disabled: false}, next: {disabled: false}, restart: {},
  status: {textContent: ''}, raw: {textContent: ''},
  'guardllm-behavior': {textContent: '{}'},
};
let keyHandler = null;
global.document = {
  querySelectorAll() { return fakeSteps; },
  querySelector() { return controls; },
  getElementById(id) { return elements[id]; },
  addEventListener(type, handler) { if (type === 'keydown') keyHandler = handler; },
};
eval(process.argv[1]);
assert.equal(controls.hidden, false);
assert.deepEqual(fakeSteps.map(s => s.hidden), [false, true, true]);
assert.equal(fakeSteps[0].focusCount, 0);
assert.equal(elements.status.textContent, 'Step 1 of 3: First');
elements.next.onclick();
assert.deepEqual(fakeSteps.map(s => s.hidden), [true, false, true]);
assert.equal(fakeSteps[1].focusCount, 1);
assert.equal(elements.status.textContent, 'Step 2 of 3: Second');
keyHandler({defaultPrevented: false, key: 'ArrowRight'});
assert.equal(fakeSteps[2].focusCount, 1);
elements.back.onclick();
assert.equal(fakeSteps[1].focusCount, 2);
elements.restart.onclick();
assert.equal(fakeSteps[0].focusCount, 1);
"""
    result = subprocess.run(
        ["node", "-e", harness, behavior],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
