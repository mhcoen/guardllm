from __future__ import annotations

import importlib.util
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
    # The map is now the persistent flow above the acts rather than a diagram
    # buried in one of them, so it precedes the steps and the rail sits between.
    assert spine.index('<div class="system-map"') < spine.index('<nav class="act-rail"')
    assert spine.index('<nav class="act-rail"') < spine.index('<div class="steps ')

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


def _load_generator():
    """Import the generator so the destination table can be asserted directly."""
    name = "guardllm_build_demos"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "build_demos.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MAP_PAGES = ("guardllm_surface_map.html", "guardllm_demos.html")


def _map_nav(page: str) -> str:
    """The architecture navigation landmark, which is the whole interactive map."""
    match = re.search(r'<nav class="system-map-nav".*?</nav>', page, re.S)
    assert match, "the surface map should render inside a navigation landmark"
    return match.group(0)


def test_map_regions_link_to_real_destinations():
    generator = _load_generator()
    destinations = generator.MAP_DESTINATIONS

    # The reduced link set: every mechanism-bearing region, and nothing else.
    # Adding a link here is a deliberate design change, not an accident. Policy
    # is deliberately absent: the Authorization boundary and the policy card
    # already open it, so a per-flow rail link would be a third path to one page.
    assert len(destinations) == 13
    assert "policy" not in destinations
    for key, (href, label) in destinations.items():
        assert (DEMO / href).exists(), f"{key} points at a missing page: {href}"
        assert label, f"{key} has no destination label"

    nav = _map_nav((DEMO / "guardllm_surface_map.html").read_text())
    hrefs = [h for h in re.findall(r'<a [^>]*href="([^"]+)"', nav) if not h.startswith("#")]
    assert len(hrefs) == 13
    assert set(hrefs) == {href for href, _ in destinations.values()}
    for href in hrefs:
        assert (DEMO / href).exists()


def test_every_map_link_names_its_destination():
    """A link that does not say where it goes recreates the guessing problem."""
    generator = _load_generator()
    labels = dict(generator.MAP_DESTINATIONS.values())
    nav = _map_nav((DEMO / "guardllm_surface_map.html").read_text())
    anchors = re.findall(r"<a class=\"[^\"]*(?:map-region|rail-pill)[^\"]*\".*?</a>", nav, re.S)
    assert len(anchors) == 13
    for anchor in anchors:
        href = re.search(r'href="([^"]+)"', anchor).group(1)
        expected = labels[href]
        assert expected in anchor, f"link to {href} does not name {expected!r}"
        assert re.search(r"[Oo]pen ", anchor), f"link to {href} has no open affordance"


def test_inert_map_regions_are_not_links():
    """Connectors, lanes, endpoints and repeated source labels stay inert."""
    generator = _load_generator()
    for name in MAP_PAGES:
        nav = _map_nav((DEMO / name).read_text())
        for label in generator.INERT_MAP_LABELS:
            linked = re.search(r"<a\b[^>]*>(?:(?!</a>).)*" + re.escape(label), nav, re.S)
            assert not linked, f"{label} should not be a link on {name}"


def test_map_skip_link_has_a_real_target():
    """Landmarks do not shorten the Tab sequence, so a skip link must exist."""
    generator = _load_generator()
    target = generator.SKIP_MAP_TARGET
    for name in MAP_PAGES:
        page = (DEMO / name).read_text()
        nav = _map_nav(page)
        assert f'<a class="skip-map" href="#{target}">' in nav
        assert "Skip architecture links" in nav
        # The target sits after the landmark so skipping clears every map link.
        assert f'<span id="{target}" tabindex="-1"></span>' in page
        assert page.index(f'id="{target}"') > page.index('class="system-map-nav"')


def test_current_page_regions_are_marked_not_linked():
    """The map renders on two pages, so it must never link to the page it is on."""
    page = (DEMO / "guardllm_demos.html").read_text()
    nav = _map_nav(page)
    assert 'href="guardllm_demos.html"' not in nav
    assert nav.count('aria-current="page"') == 2
    assert "You are viewing this" in nav

    # The surface map is not itself a demo destination, so nothing is current.
    surface = _map_nav((DEMO / "guardllm_surface_map.html").read_text())
    assert 'aria-current="page"' not in surface
    assert 'href="guardllm_surface_map.html"' not in surface


def test_map_focus_and_outcome_colors_are_preserved():
    page = (DEMO / "guardllm_surface_map.html").read_text()
    # One consistent focus ring, never themed per region.
    assert ":focus-visible{outline:2px solid var(--focus)" in page
    assert page.count("--focus:") == 1
    # Red, green and amber stay reserved for deny, allow and warn.
    for tint in re.findall(r"\.region-[a-z]+\{background:(#[0-9a-f]{6})\}", page):
        r, g, b = (int(tint[i : i + 2], 16) for i in (1, 3, 5))
        assert b >= r and b >= g, f"region tint {tint} is not a desaturated cool tone"
    assert ".allow{color:var(--green)}" in page
    assert ".deny{color:var(--red)}" in page
    assert ".warn{color:var(--amber)}" in page


def test_surface_map_promotes_the_primary_narrative():
    page = (DEMO / "guardllm_surface_map.html").read_text()
    assert '<a class="cta" href="guardllm_demos.html">' in page
    assert "Start here" in page
    # Promoted out of the equal-weight card grid rather than duplicated into it.
    cards = page.split('<div class="cards">', 1)[1]
    assert 'href="guardllm_demos.html"' not in cards
    assert page.index('class="cta"') < page.index('<div class="cards">')


def test_rails_state_their_own_lifecycle():
    """The two rails differ in treatment, so each says why rather than leaving
    the difference to be guessed. Per-flow terms are prose, not pills: a pill
    border on an unlinked term reads as a disabled control."""
    for name in MAP_PAGES:
        page = (DEMO / name).read_text()
        rails = page.split('<div class="rails">', 1)[1].split("</nav>", 1)[0]
        assert "Provided by the host on each flow" in rails
        assert "Retained by GuardLLM across calls" in rails

        flow = rails.split('<div class="rail">')[1]
        # The five fields share one destination, so the rail is labelled once at
        # its heading. The terms themselves stay prose: no link, no pill.
        assert flow.count("<a ") == 1
        assert 'href="guardllm_security_context_demo.html"' in flow
        assert "rail-pill" not in flow, "unlinked terms must not wear the pill affordance"
        assert '<span class="rail-terms">' in flow
        terms = flow.split('<span class="rail-terms">', 1)[1]
        assert "<a " not in terms, "per-flow context fields are prose, not links"

        session = rails.split('<div class="rail">')[2]
        assert len(re.findall(r'class="rail-pill[^"]*"', session)) == 6
        if name == "guardllm_surface_map.html":
            assert session.count('<a class="rail-pill"') == 6
        else:
            # escalation opens the page this map is drawn on, so it is marked
            # as current rather than linking the reader back to where they are.
            assert session.count('<a class="rail-pill"') == 5
            assert 'class="rail-pill is-current"' in session


# Every page states a shape, and no two mechanisms are drawn the same way
# unless they genuinely share one. The stepper is reserved for the narrative,
# where causality actually unfolds over time.
LAYOUTS = {
    "guardllm_demos.html": ("layout-stepper", 0),
    "guardllm_pipeline_demo.html": ("layout-pipeline", 0),
    "guardllm_rag_demos.html": ("layout-comparison has-lead", 0),
    "guardllm_policy_matrix_demo.html": ("layout-stack", 0),
    "guardllm_canary_demos.html": ("layout-taxonomy", 0),
    "guardllm_tool_feedback_demo.html": ("layout-contrast", 2),
    "guardllm_security_context_demo.html": ("layout-contrast", 2),
    "guardllm_request_binding_demo.html": ("layout-branch", 2),
    "guardllm_rate_limit_demo.html": ("layout-timeline", 2),
}


def test_pages_declare_their_layout_and_groups():
    assert LAYOUTS.keys() == {
        path.name for path in DEMO.glob("*.html") if path.name != "guardllm_surface_map.html"
    }
    # Only the narrative keeps the stepper.
    steppers = [name for name, (css, _) in LAYOUTS.items() if css == "layout-stepper"]
    assert steppers == ["guardllm_demos.html"]
    for name, (css_class, group_count) in LAYOUTS.items():
        page = (DEMO / name).read_text()
        assert f'<div class="steps {css_class}"' in page, name
        assert ('class="controls"' in page) == (css_class == "layout-stepper"), name
        assert len(re.findall(r'<h2 class="group-head">', page)) == group_count, name
        # Grouped layouts run in parallel, so each path numbers from one. A
        # single running count would imply an order across them.
        if group_count:
            assert page.count("<h3>1.") == group_count, name


def test_layout_must_match_the_execution_metadata():
    """A page cannot claim a shape its own fixture does not support."""
    generator = _load_generator()
    scenarios = json.loads((DEMO / "guardllm_demo_fixtures.json").read_text())["scenarios"]

    # The shapes actually shipped.
    generator.validate_page_layout("branch", scenarios["request_binding"], ("a", "b"))
    generator.validate_page_layout("comparison", scenarios["rag"], ())
    generator.validate_page_layout("timeline", scenarios["rate_limit"], ("a", "b"))

    # A fork needs distinct artifact paths.
    with pytest.raises(ValueError, match="artifact"):
        generator.validate_page_layout("branch", scenarios["rag"], ("a", "b"))
    with pytest.raises(ValueError, match="declares 1 groups"):
        generator.validate_page_layout("branch", scenarios["request_binding"], ("one",))

    # A timeline claims order in time, so continuation on one object is not
    # enough: a factory feeding a verifier has that shape and is not a timeline.
    with pytest.raises(ValueError, match="record the time"):
        generator.validate_page_layout("timeline", scenarios["request_binding"], ("a", "b"))
    with pytest.raises(ValueError, match="declares 1 tracks"):
        generator.validate_page_layout("timeline", scenarios["rate_limit"], ("one",))

    # Side by side reads as independent, so it needs one genuinely shared object.
    with pytest.raises(ValueError, match="independent objects"):
        generator.validate_page_layout("comparison", scenarios["rate_limit"], ())

    with pytest.raises(ValueError, match="Unknown page layout"):
        generator.validate_page_layout("carousel", scenarios["rag"], ())


def test_new_layouts_reject_shapes_their_fixtures_do_not_support():
    generator = _load_generator()
    scenarios = json.loads((DEMO / "guardllm_demo_fixtures.json").read_text())["scenarios"]
    check = generator.validate_page_layout

    # Shapes actually shipped.
    check("pipeline", scenarios["ingress"], (), displayed=len(scenarios["ingress"]["steps"]))
    check("taxonomy", scenarios["dlp_canary"], ())
    check("contrast", scenarios["tool_feedback"], ("open", "closed"))
    check("contrast", scenarios["security_context"], ("untrusted", "trusted"))
    check("comparison", scenarios["policy"], ())

    # A drawn pipeline draws every instrumented site. Five rows for seven sites
    # presents an abridged pipeline as the pipeline.
    with pytest.raises(ValueError, match="every site has to appear"):
        check("pipeline", scenarios["ingress"], (), displayed=5)
    # Only nested call sites inside one enclosing call are a pipeline.
    with pytest.raises(ValueError, match="nested call site"):
        check("pipeline", scenarios["policy"], ())

    # A grid of peers claims no cell depends on another.
    with pytest.raises(ValueError, match="stand alone"):
        check("taxonomy", scenarios["policy"], ())
    with pytest.raises(ValueError, match="nested call site"):
        check("pipeline", scenarios["dlp_canary"], ())
    # No shipped scenario is all-independent while reusing one object, so the
    # distinct-object rule needs a constructed case to be exercised at all.
    shared_object = {
        "steps": [
            {"execution": "independent", "pipeline_id": "one"},
            {"execution": "independent", "pipeline_id": "one"},
            {"execution": "independent", "pipeline_id": "two"},
        ]
    }
    with pytest.raises(ValueError, match="its own object"):
        check("taxonomy", shared_object, ())

    # A contrast needs two objects, one created to be compared with the other.
    with pytest.raises(ValueError, match="exactly two objects"):
        check("contrast", scenarios["dlp_canary"], ("a", "b"))
    with pytest.raises(ValueError, match="exactly one branch step"):
        check("contrast", scenarios["request_binding"], ("a", "b"))
    with pytest.raises(ValueError, match="needs two"):
        check("contrast", scenarios["security_context"], ("only one",))

    # A lead step is a setup plus the compared cases, not one of them.
    with pytest.raises(ValueError, match="lead step needs"):
        check("comparison", scenarios["rag"], (), lead_step=True, displayed=3)


def test_page_chrome_stays_out_of_the_way():
    """Furniture sits below the demonstration, not above it."""
    for name in LAYOUTS:
        page = (DEMO / name).read_text()
        lead = re.search(r'<p class="lead">(.*?)</p>', page, re.S).group(1)
        assert len(lead) <= 200, (name, len(lead))
        assert lead.count(". ") <= 1, f"{name} lead runs past two sentences"

        # The evidence chips and any scope notes live inside the drawer.
        head, drawer = page.split("<details>", 1)
        assert 'class="evidence-strip"' not in head, name
        assert 'class="evidence-strip"' in drawer, name
        assert 'class="caveats"' not in head, name

        # The narrative is the entry point; reference cards sit a step quieter.
        supporting = 'class="wrap supporting"' in page
        assert supporting == (name != "guardllm_demos.html"), name


def test_relocated_scope_notes_survive_in_the_drawer():
    """Shortening a lead must move its caveats, not delete them."""
    expected = {
        "guardllm_canary_demos.html": "independent comparisons, not one five-step session",
        "guardllm_rag_demos.html": "One pipeline registers the retrieved span once",
        "guardllm_rate_limit_demo.html": "leave a burst of exactly three silent",
        "guardllm_pipeline_demo.html": "require explicit instrumentation",
        "guardllm_policy_matrix_demo.html": "have not already denied the call",
    }
    for name, sentence in expected.items():
        page = (DEMO / name).read_text()
        drawer = page.split("<details>", 1)[1]
        assert sentence in drawer, name


def test_outcome_badges_match_the_fixture_outcomes():
    """Badge counts are derived from the fixture, not restated from the page.

    Badges are authored per displayed row, so nothing stops one from claiming
    ALLOWED over a denial. For the pages whose rows correspond one-to-one with
    fixture results, the expected counts come from the results themselves.
    """
    scenarios = json.loads((DEMO / "guardllm_demo_fixtures.json").read_text())["scenarios"]

    dlp = scenarios["dlp_canary"]
    dlp_results = [
        dlp["canary_result"],
        dlp["known_pattern"],
        dlp["entropy"]["result"],
        dlp["split_entropy"]["result"],
        dlp["hex_entropy"]["result"],
    ]
    page = (DEMO / "guardllm_canary_demos.html").read_text()
    assert page.count("BLOCKED") == sum(1 for r in dlp_results if not r["allowed"])
    assert page.count("ALLOWED") == sum(1 for r in dlp_results if r["allowed"])

    policy = scenarios["policy"]
    policy_results = [
        policy[key]
        for key in (
            "safe_no_auth",
            "empty_allowlist",
            "destructive_disabled",
            "destructive_no_auth",
            "destructive_verified",
        )
    ]
    page = (DEMO / "guardllm_policy_matrix_demo.html").read_text()
    # The gate path badges each denial at the gate that closed, and each pass at
    # the end, so the counts still come from the five verdicts.
    assert page.count("BLOCKED") == sum(1 for r in policy_results if not r["allowed"])
    assert page.count("ALLOWED") == sum(1 for r in policy_results if r["allowed"])
    # The matrix stays the reference view and still carries every decision.
    assert page.count('<th scope="row">') == len(policy_results)

    rate = scenarios["rate_limit"]
    page = (DEMO / "guardllm_rate_limit_demo.html").read_text()
    expected_anomalies = sum(1 for e in rate["burst_sequence"] if e["result"]["anomalies"])
    assert page.count("ANOMALY") == expected_anomalies
    assert page.count("BLOCKED") == (0 if rate["hard_cap"]["allowed"] else 1)


BADGE_RE = re.compile(
    r'<span class="badge badge-(\w+)"><span aria-hidden="true">([^<]*)</span> ([A-Z ]+)</span>'
)


def test_badges_do_not_rely_on_color_alone():
    """Every badge carries its glyph and its word, so meaning survives without color."""
    generator = _load_generator()
    seen = 0
    for name in LAYOUTS:
        page = (DEMO / name).read_text()
        # The count of parsed badges must equal the count of badge elements, or
        # the parse is silently skipping some and proving nothing.
        assert len(BADGE_RE.findall(page)) == page.count('<span class="badge badge-'), name
        for outcome, glyph, label in BADGE_RE.findall(page):
            assert (glyph, label) == generator.OUTCOME_BADGES[outcome], (name, outcome)
            seen += 1
    assert seen == 35, seen


def test_demo_content_containers_wrap_long_tokens():
    """A 64 character hash has no break opportunity and overflows its box.

    The egress display showed a SHA-256 digest running past the card. Only
    .result carried a wrap rule; .step-body and .message, which hold the same
    kind of generated value, did not.
    """
    page = (DEMO / "guardllm_canary_demos.html").read_text()
    for selector in (".step-body{", ".message{", ".result{"):
        rule = re.search(re.escape(selector) + r"[^}]*}", page)
        assert rule, selector
        assert "overflow-wrap" in rule.group(0), selector

    # The digest that exposed it must still be displayed, not shortened away.
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in page


def test_every_demo_page_links_back_to_the_project():
    """A reader arriving at a demo from a link had no route anywhere else.

    The demo nav pointed only at other demos, and the surface map lost its nav
    entirely when the entry-point CTA replaced it, so the index had none.
    """
    pages = sorted(DEMO.glob("*.html"))
    assert len(pages) == 10
    for path in pages:
        page = path.read_text()
        assert 'href="https://github.com/mhcoen/guardllm"' in page, path.name
        nav = re.search(r"<nav[^>]*>.*?</nav>", page, re.S)
        assert nav, path.name
        # It comes first in the trail, before the other demo links.
        assert "github.com/mhcoen/guardllm" in nav.group(0), path.name

    # The link is absolute on purpose: these pages must keep working opened
    # directly from disk, where a relative path to the project has no target.
    for path in pages:
        assert "fetch(" not in path.read_text()
