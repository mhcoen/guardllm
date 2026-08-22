"""Rego policy evaluation, and the ordering that keeps it from weakening anything.

The WASM cases compile `example.rego` with the OPA binary at run time rather
than committing a .wasm blob, so what a reviewer reads is the policy source.
They skip where `opa` is absent; CI installs it so the path is exercised.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from guardllm.policy import PolicyDecision, RegoPolicy, build_input, decide

_HERE = Path(__file__).parent
_OPA = shutil.which("opa")
_needs_opa = pytest.mark.skipif(_OPA is None, reason="the opa compiler is not installed")

pytest.importorskip("wasmtime", reason="wasmtime is not installed")


@pytest.fixture(scope="module")
def policy(tmp_path_factory) -> RegoPolicy:
    bundle = tmp_path_factory.mktemp("rego") / "bundle.tar.gz"
    subprocess.run(  # noqa: S603 - fixed argv, no shell, path from shutil.which
        [_OPA, "build", "-t", "wasm", "-e", "guardllm/deny", "example.rego", "-o", str(bundle)],
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
        assert doc["guardllm"] == {
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
        facts = doc["guardllm"]
        assert facts["session_contaminated"] is False
        assert facts["session_escalated"] is False
        assert facts["untrusted_sources"] == []


class TestOrdering:
    """A Rego allow must never overturn a GuardLLM deny."""

    class _AlwaysAllows:
        def evaluate(self, _doc):
            return PolicyDecision(allowed=True)

    class _AlwaysDenies:
        def evaluate(self, _doc):
            return PolicyDecision(allowed=False, reasons=("policy says no",))

    def test_a_guardllm_deny_is_final_and_the_policy_is_not_consulted(self):
        """The policy is not merely overruled here, it is never asked.

        A policy able to overturn a GuardLLM deny would be a way to configure
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
        assert asked == [], "the policy was consulted on a GuardLLM deny"

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
        """The rule a customer cannot write without GuardLLM.

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
            [_OPA, "build", "-t", "wasm", "-e", "guardllm/deny", "example.rego", "-o", str(bundle)],
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
