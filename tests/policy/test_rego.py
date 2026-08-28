"""Rego policy evaluation, and the ordering that keeps it from weakening anything.

The WASM cases compile `example.rego` with the OPA binary at run time rather
than committing a .wasm blob, so what a reviewer reads is the policy source.
They skip where `opa` is absent; CI installs it so the path is exercised.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from vordur.policy import PolicyDecision, RegoPolicy, build_input, decide

_HERE = Path(__file__).parent
_OPA = shutil.which("opa")
_needs_opa = pytest.mark.skipif(_OPA is None, reason="the opa compiler is not installed")

pytest.importorskip("wasmtime", reason="wasmtime is not installed")


@pytest.fixture(scope="module")
def policy(tmp_path_factory) -> RegoPolicy:
    bundle = tmp_path_factory.mktemp("rego") / "bundle.tar.gz"
    subprocess.run(  # noqa: S603 - fixed argv, no shell, path from shutil.which
        [_OPA, "build", "-t", "wasm", "-e", "vordur/deny", "example.rego", "-o", str(bundle)],
        cwd=_HERE,
        check=True,
        capture_output=True,
    )
    return RegoPolicy(bundle)


class TestInputDocument:
    """The schema is the interface. A rule is written against this shape."""

    def test_it_carries_the_facts_no_other_engine_can_know(self):
        doc = build_input(
            tool="wire_funds",
            args={"amount": 100},
            contaminated=True,
            escalated=True,
            untrusted_sources=["web_search", "email"],
            injection_detected=True,
            canary_detected=True,
            binding_valid=False,
        )
        assert doc["tool"] == "wire_funds"
        assert doc["args"] == {"amount": 100}
        assert doc["vordur"] == {
            "session_contaminated": True,
            "session_escalated": True,
            # Sorted so a policy comparing the list is not at the mercy of
            # ingest order.
            "untrusted_sources": ["email", "web_search"],
            "injection_detected": True,
            "canary_detected": True,
            "binding_valid": False,
        }

    def test_roles_is_always_present_so_a_rule_cannot_fail_open(self):
        """An undefined reference in Rego makes the rule body undefined.

        `not "admin" in input.user.roles` against a user with no `roles` key
        therefore does not deny, it fails to fire, and an access rule that
        fails to fire fails OPEN. The schema is total so no policy author has
        to know that.
        """
        assert build_input(tool="x")["user"] == {"roles": []}
        assert build_input(tool="x", user={"id": "alice"})["user"] == {
            "id": "alice",
            "roles": [],
        }
        # A host that supplies roles keeps them.
        assert build_input(tool="x", user={"roles": ["admin"]})["user"]["roles"] == ["admin"]

    def test_the_defaults_are_the_safe_ones(self):
        doc = build_input(tool="x")
        facts = doc["vordur"]
        assert facts["session_contaminated"] is False
        assert facts["session_escalated"] is False
        assert facts["untrusted_sources"] == []


class TestOrdering:
    """A Rego allow must never overturn a Vörður deny."""

    class _AlwaysAllows:
        def evaluate(self, _doc):
            return PolicyDecision(allowed=True)

    class _AlwaysDenies:
        def evaluate(self, _doc):
            return PolicyDecision(allowed=False, reasons=("policy says no",))

    def test_a_vordur_deny_is_final_and_the_policy_is_not_consulted(self):
        """The policy is not merely overruled here, it is never asked.

        A policy able to overturn a Vörður deny would be a way to configure
        the enforcement off, so the call is not made at all.
        """
        asked = []

        class _Records:
            def evaluate(self, doc):
                asked.append(doc)
                return PolicyDecision(allowed=True)

        verdict = decide(
            guard_allowed=False,
            guard_reason="session escalated=deny",
            policy=_Records(),
            document=build_input(tool="wire_funds"),
        )
        assert verdict.allowed is False
        assert verdict.reasons == ("session escalated=deny",)
        assert asked == [], "the policy was consulted on a Vörður deny"

    def test_a_policy_may_narrow_an_allow(self):
        verdict = decide(
            guard_allowed=True,
            guard_reason="implicit allow",
            policy=self._AlwaysDenies(),
            document=build_input(tool="wire_funds"),
        )
        assert verdict.allowed is False
        assert "policy says no" in verdict.reason

    def test_no_policy_leaves_the_verdict_alone(self):
        verdict = decide(
            guard_allowed=True,
            guard_reason="implicit allow",
            policy=None,
            document=build_input(tool="x"),
        )
        assert verdict.allowed is True

    def test_both_allowing_allows(self):
        verdict = decide(
            guard_allowed=True,
            guard_reason="implicit allow",
            policy=self._AlwaysAllows(),
            document=build_input(tool="x"),
        )
        assert verdict.allowed is True


@_needs_opa
class TestCompiledPolicy:
    """Real Rego, compiled to WASM by OPA, evaluated in process."""

    def test_a_rule_reading_session_state_denies(self, policy):
        """The rule a customer cannot write without Vörður.

        OPA has no way to learn that this session ingested untrusted content
        three turns ago; that fact only exists because the library computed it.
        """
        denied = policy.evaluate(build_input(tool="wire_funds", contaminated=True))
        assert denied.allowed is False
        assert "contaminated" in denied.reason

        allowed = policy.evaluate(build_input(tool="wire_funds"))
        assert allowed.allowed is True

    def test_escalation_is_readable_too(self, policy):
        denied = policy.evaluate(build_input(tool="send_email", escalated=True))
        assert denied.allowed is False
        assert "escalated" in denied.reason

    def test_ordinary_access_control_works_alongside(self, policy):
        assert policy.evaluate(build_input(tool="delete_account")).allowed is False
        assert (
            policy.evaluate(build_input(tool="delete_account", user={"roles": ["admin"]})).allowed
            is True
        )

    def test_an_unrelated_tool_is_untouched(self, policy):
        assert policy.evaluate(build_input(tool="search", contaminated=True)).allowed is True

    def test_evaluation_is_repeatable(self, policy):
        """The same instance is reused across calls, so state must not leak."""
        doc = build_input(tool="wire_funds", contaminated=True)
        first = policy.evaluate(doc)
        for _ in range(50):
            assert policy.evaluate(doc) == first
        # And a clean document still allows after all of those.
        assert policy.evaluate(build_input(tool="wire_funds")).allowed is True

    def test_a_bare_wasm_file_loads_too(self, policy, tmp_path):
        """Both shapes a person ends up with: the bundle and the raw module."""
        import tarfile

        bundle = tmp_path / "b.tar.gz"
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            [_OPA, "build", "-t", "wasm", "-e", "vordur/deny", "example.rego", "-o", str(bundle)],
            cwd=_HERE,
            check=True,
            capture_output=True,
        )
        raw = tmp_path / "policy.wasm"
        with tarfile.open(bundle) as archive:
            raw.write_bytes(archive.extractfile("/policy.wasm").read())
        assert (
            RegoPolicy(raw).evaluate(build_input(tool="wire_funds", contaminated=True)).allowed
            is False
        )


class TestLoadErrors:
    def test_a_bundle_without_a_policy_is_refused(self, tmp_path):
        import tarfile

        empty = tmp_path / "empty.tar.gz"
        with tarfile.open(empty, "w:gz") as archive:
            archive.add(_HERE / "example.rego", arcname="/example.rego")
        with pytest.raises(ValueError, match="no policy.wasm"):
            RegoPolicy(empty)


class TestInputVersion:
    """The interface with the longest life: a customer's rules live in their repo.

    A field cannot be renamed once anyone has read it, and a customer-hosted
    deployment runs a release for years. The version travels inside the
    document so a policy can branch on it and keep working across an increment,
    rather than failing at the first changed field.
    """

    def test_the_document_carries_its_version(self):
        from vordur.policy import POLICY_INPUT_VERSION

        assert POLICY_INPUT_VERSION == 1
        assert build_input(tool="x")["version"] == POLICY_INPUT_VERSION

    def test_the_version_does_not_disturb_the_rest_of_the_schema(self):
        doc = build_input(tool="x")
        assert set(doc) == {"version", "user", "tool", "args", "vordur"}

    @_needs_opa
    def test_a_policy_can_branch_on_it(self, policy):
        """What the field is for, exercised by a rule that reads it.

        A rule gated on `input.version >= 1` fires today and would keep firing
        after an increment, which is the whole point: adding a fact must not
        break a policy that does not know about it.
        """
        denied = policy.evaluate(build_input(tool="export_all", contaminated=True))
        assert denied.allowed is False
        assert "bulk export" in denied.reason
        # The gate is on the session fact, not merely on the version.
        assert policy.evaluate(build_input(tool="export_all")).allowed is True
        # And the rules written before the version existed are unaffected.
        assert policy.evaluate(build_input(tool="wire_funds", contaminated=True)).allowed is False


# ---------------------------------------------------------------------------
# The two ways this used to fail open, and the leak underneath them
# ---------------------------------------------------------------------------

#: A rule whose only condition lives in the bundle's own data document. It
#: needs no builtin, so it loads; if the data is not there, the reference is
#: undefined, the rule body is undefined, and the deny does not fire.
_DATA_POLICY = """package vordur

deny contains msg if {
    some blocked in data.config.blocked_tools
    input.tool == blocked
    msg := "tool is blocked by bundle data"
}
"""

#: `sprintf` is not compiled into the WASM module; OPA expects the host to
#: supply it. It is the common case, because it is how a deny message
#: interpolates what it objected to.
_BUILTIN_POLICY = """package vordur

deny contains msg if {
    input.tool == "wire_funds"
    msg := sprintf("tool %v is refused", [input.tool])
}
"""


def _build(tmp_path, source: str, data: str | None = None) -> Path:
    """Compile a bundle the way an operator would, from a directory."""
    (tmp_path / "policy.rego").write_text(source)
    if data is not None:
        (tmp_path / "config").mkdir(exist_ok=True)
        (tmp_path / "config" / "data.json").write_text(data)
    bundle = tmp_path / "bundle.tar.gz"
    subprocess.run(  # noqa: S603 - fixed argv, no shell, path from shutil.which
        [_OPA, "build", "-t", "wasm", "-b", ".", "-e", "vordur/deny", "-o", str(bundle)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    return bundle


@_needs_opa
class TestBundleData:
    """A rule reading `data.` must see the bundle's data document.

    It did not. The data document is a caller-supplied argument in the WASM
    ABI and nothing is compiled into the module, so passing `{}` left every
    such rule undefined -- which for a deny rule is an allow, silently.
    """

    def test_a_rule_reading_bundle_data_denies(self, tmp_path):
        bundle = _build(tmp_path, _DATA_POLICY, '{"blocked_tools": ["search"]}')
        policy = RegoPolicy(bundle)
        verdict = policy.evaluate({"tool": "search"})
        assert verdict.allowed is False
        assert "blocked by bundle data" in verdict.reason

    def test_it_agrees_with_opa_itself(self, tmp_path):
        """The ground truth: what `opa eval` says about the same bundle.

        This is the assertion that would have caught the original defect. The
        policy denied under `opa eval` and allowed under RegoPolicy.
        """
        bundle = _build(tmp_path, _DATA_POLICY, '{"blocked_tools": ["search"]}')
        document = {"tool": "search"}
        native = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [_OPA, "eval", "-b", ".", "-I", "data.vordur.deny"],
            cwd=tmp_path,
            input=json.dumps(document),
            capture_output=True,
            text=True,
            check=True,
        )
        opa_denials = json.loads(native.stdout)["result"][0]["expressions"][0]["value"]
        verdict = RegoPolicy(bundle).evaluate(document)
        assert bool(opa_denials) is (not verdict.allowed)
        assert sorted(opa_denials) == sorted(verdict.reasons)

    def test_a_rule_reading_absent_data_still_allows(self, tmp_path):
        """No data.json in the bundle is not an error, just nothing to read."""
        bundle = _build(tmp_path, _DATA_POLICY)
        assert RegoPolicy(bundle).evaluate({"tool": "search"}).allowed is True


@_needs_opa
class TestUnsupportedBuiltins:
    def test_a_policy_needing_a_host_builtin_is_refused_at_load(self, tmp_path):
        """Loudly, once, and before the policy is trusted with a decision.

        Answering the call with 0 instead made it read as undefined, which
        made the rule body undefined, which made a deny rule allow.
        """
        bundle = _build(tmp_path, _BUILTIN_POLICY)
        with pytest.raises(ValueError, match="builtins this build does not implement"):
            RegoPolicy(bundle)

    def test_the_refusal_names_the_builtin_and_the_way_out(self, tmp_path):
        bundle = _build(tmp_path, _BUILTIN_POLICY)
        with pytest.raises(ValueError) as caught:
            RegoPolicy(bundle)
        assert "sprintf" in str(caught.value)
        assert "literal deny message" in str(caught.value)

    def test_a_policy_needing_none_is_unaffected(self, policy):
        """The fixture policy in this repository requires no host builtin."""
        assert policy.evaluate(build_input(tool="wire_funds", contaminated=True)).allowed is False


@_needs_opa
class TestHeapDiscipline:
    def test_the_heap_does_not_grow_across_evaluations(self, policy):
        """It grew about 2.2 KB per call and was never reclaimed.

        A gateway evaluates a policy on every tool call and runs for weeks, so
        a per-call leak in the policy engine is an availability failure in the
        security layer.
        """
        memory = policy._memory
        for _ in range(200):
            policy.evaluate(build_input(tool="wire_funds", contaminated=True))
        settled = memory.data_len(policy._store)
        for _ in range(5_000):
            policy.evaluate(build_input(tool="wire_funds", contaminated=True))
        assert memory.data_len(policy._store) == settled

    def test_verdicts_stay_correct_while_the_heap_is_reused(self, policy):
        """Winding the heap back must not corrupt what the next call reads."""
        for i in range(2_000):
            contaminated = bool(i % 2)
            verdict = policy.evaluate(build_input(tool="wire_funds", contaminated=contaminated))
            assert verdict.allowed is not contaminated


@_needs_opa
class TestBundleDataLayout:
    """`opa build` merges data into one root document; other tooling need not.

    Reading only the root would silently drop a nested data file, and a rule
    reading it would meet an undefined reference, fail to fire, and allow the
    call: the same fail-open the root loader exists to close.
    """

    def test_opa_merges_nested_data_into_the_root_document(self, tmp_path):
        """The premise. If this ever stops holding, the refusal below is wrong."""
        (tmp_path / "policy.rego").write_text(_DATA_POLICY)
        for sub in ("config", "deep/nested"):
            d = tmp_path / sub
            d.mkdir(parents=True)
            (d / "data.json").write_text('{"blocked_tools": ["search"]}')
        bundle = tmp_path / "bundle.tar.gz"
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            [_OPA, "build", "-t", "wasm", "-b", ".", "-e", "vordur/deny", "-o", str(bundle)],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )
        with tarfile.open(bundle) as tar:
            names = [n for n in tar.getnames() if n.rsplit("/", 1)[-1] == "data.json"]
        assert names == ["/data.json"]
        assert RegoPolicy(bundle).evaluate({"tool": "search"}).allowed is False

    def test_a_bundle_with_data_outside_the_root_is_refused(self, tmp_path):
        """Refused rather than merged: guessing at a layout opa did not write
        is how the two come to disagree in the first place."""
        bundle = _build(tmp_path, _DATA_POLICY, '{"blocked_tools": ["search"]}')
        handmade = tmp_path / "handmade.tar.gz"
        with tarfile.open(bundle) as src, tarfile.open(handmade, "w:gz") as dst:
            for member in src.getmembers():
                extracted = src.extractfile(member)
                dst.addfile(member, io.BytesIO(extracted.read()) if extracted else None)
            payload = b'{"blocked_tools": ["search"]}'
            info = tarfile.TarInfo("config/data.json")
            info.size = len(payload)
            dst.addfile(info, io.BytesIO(payload))
        with pytest.raises(ValueError, match="carries data outside the bundle root"):
            RegoPolicy(handmade)
