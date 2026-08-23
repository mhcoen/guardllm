"""The support bundle: what it collects, and what it refuses to carry.

A diagnostic that leaks is worse than no diagnostic, because it is produced by
an operator who has been told it is safe to attach to a ticket. So the tests
that matter here are the ones about what stays out.
"""

from __future__ import annotations

import json

import pytest

from guardllm.gateway.forensics import Chain
from guardllm.security.types import PolicyConfig
from guardllm.support import (
    BUNDLE_VERSION,
    UnsafeBundleError,
    build_bundle,
    render_bundle,
    write_bundle,
)

# Split so the literal is not itself a scannable credential in this file.
KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz1234"
#: The RFC 4648 Base32 alphabet, which is also a valid TOTP shared secret.
#: Recognized as credential material that no span can safely replace.
ALPHABET = "234567ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class _Guard:
    """Enough of a Guard for Chain.record to read session state from."""

    _pipeline = None


class TestWhatTheBundleAnswers:
    def test_it_reports_which_settings_were_changed(self):
        """The commonest ticket is a setting the operator believes is in force.

        Reading 25 resolved values to find the one that is not stock is work
        the bundle can do, so it does it.
        """
        report = build_bundle(policy=PolicyConfig(server_default_deny=True))["policy"]
        assert report["changed_from_default"] == ["server_default_deny"]
        assert report["resolved"]["server_default_deny"] is True
        # And the rest is still there, because "what is everything set to" is
        # the second question.
        assert "contaminated_tool_policy" in report["resolved"]

    def test_it_never_reports_the_absence_of_a_policy(self):
        """Found by running a live gateway with no policy file.

        It reported `policy: null`, which reads as "no policy in force" when
        the defaults are in force and are what refused the call. A bundle whose
        job is to say what is in force must never be silent about it.
        """
        report = build_bundle()["policy"]
        assert report["source"] == "defaults"
        assert report["changed_from_default"] == []
        # And the settings themselves are there to read.
        assert report["resolved"]["contaminated_tool_policy"]

    def test_it_says_where_the_policy_came_from(self, tmp_path):
        path = tmp_path / "p.yaml"
        path.write_text("policy:\n  server_default_deny: true\n")
        assert build_bundle(policy_path=path)["policy"]["source"] == "file"
        assert build_bundle(policy=PolicyConfig())["policy"]["source"] == "explicit"

    def test_it_reports_whether_an_optional_extra_can_actually_be_imported(self):
        """A Rego policy that never ran and a YAML file that was never read
        both look like a policy that did not fire, and both are one line."""
        optional = build_bundle()["optional_dependencies"]
        assert set(optional) == {"yaml", "wasmtime", "cryptography"}
        for entry in optional.values():
            assert set(entry) == {"importable", "version", "needed_for"}
            assert isinstance(entry["importable"], bool)

    def test_it_carries_the_decision_chain(self):
        """The piece no other tool can supply: a block explained by an earlier
        ingest, which no per-request log relates."""
        chain = Chain()
        chain.record(
            stage="ingest",
            detail="web_search",
            outcome="recorded",
            reason="untrusted source",
            guard=_Guard(),
        )
        chain.record(
            stage="tool_call",
            detail="wire_funds",
            outcome="blocked",
            reason="session contaminated",
            guard=_Guard(),
        )
        chain = build_bundle(chain=chain)["decision_chain"]
        assert chain["step_count"] == 2
        assert chain["blocked_count"] == 1
        assert [s["stage"] for s in chain["steps"]] == ["ingest", "tool_call"]

    def test_it_is_versioned_like_the_other_long_lived_interfaces(self):
        """A bundle arriving in a ticket may predate the build reading it."""
        assert build_bundle()["version"] == BUNDLE_VERSION

    def test_it_renders_as_json(self):
        parsed = json.loads(render_bundle(build_bundle(policy=PolicyConfig())))
        assert parsed["guardllm"]["version"]
        assert parsed["environment"]["python"]

    def test_a_policy_file_is_read_from_its_path(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text("policy:\n  server_default_deny: true\n")
        bundle = build_bundle(policy_path=path)
        assert bundle["policy"]["changed_from_default"] == ["server_default_deny"]
        assert bundle["policy_file"] == str(path)


class TestWhatTheBundleRefusesToCarry:
    def test_environment_variables_appear_by_name_and_never_by_value(self, monkeypatch):
        """Whether GUARDLLM_UPSTREAM was set is a real question. What it was
        set to can carry a key inside a URL, and no diagnostic needs it."""
        monkeypatch.setenv("GUARDLLM_UPSTREAM", f"https://example.test/v1?token={KEY}")
        env = build_bundle()["environment"]
        assert "GUARDLLM_UPSTREAM" in env["guardllm_env_vars_set"]
        assert KEY not in json.dumps(env)

    def test_a_credential_in_a_config_value_is_redacted_out(self):
        """The bundle is scanned by the same passes that guard egress, so a
        secret that reached a setting cannot leave in a diagnostic."""
        text = render_bundle(build_bundle(policy=PolicyConfig(client_id=KEY)))
        assert KEY not in text
        assert "[redacted: credential]" in text

    def test_credential_material_that_cannot_be_located_is_a_refusal(self):
        """The rule the whole module turns on.

        Attribution says which characters can be replaced; recognition says a
        credential is present. When recognition fires and attribution has
        nothing to replace, redacting would produce a file that looks cleaned
        and is not, so nothing is written at all.
        """
        with pytest.raises(UnsafeBundleError, match="cannot be removed exactly"):
            render_bundle(build_bundle(policy=PolicyConfig(client_id=ALPHABET)))

    def test_one_locatable_secret_does_not_excuse_an_unlocatable_one(self):
        """The case an earlier count-comparing version let through.

        One key that can be located and one that cannot scored one against one
        and wrote the file. Any recognition left after masking is a refusal,
        whatever else was successfully replaced.
        """
        policy = PolicyConfig(client_id=KEY, contaminated_action=ALPHABET)
        with pytest.raises(UnsafeBundleError):
            render_bundle(build_bundle(policy=policy))

    def test_a_refusal_writes_no_file_at_all(self, tmp_path):
        """Not a truncated one, and not a partly-redacted one."""
        target = tmp_path / "bundle.json"
        with pytest.raises(UnsafeBundleError):
            write_bundle(target, policy=PolicyConfig(client_id=ALPHABET))
        assert not target.exists()

    def test_no_message_content_reaches_the_bundle(self):
        """The chain names stages, tools and verdicts and holds no text."""
        chain = Chain()
        chain.record(
            stage="egress",
            detail="model",
            outcome="blocked",
            reason="verbatim overlap with sensitive source",
            guard=_Guard(),
        )
        rendered = render_bundle(build_bundle(chain=chain))
        step = json.loads(rendered)["decision_chain"]["steps"][0]
        assert set(step) == {
            "stage",
            "detail",
            "outcome",
            "reason",
            "contaminated",
            "escalated",
            "at",
        }


class TestTheCommand:
    def test_it_writes_a_file_and_reports_where(self, tmp_path, capsys):
        from guardllm.support import main

        target = tmp_path / "b.json"
        assert main(["-o", str(target)]) == 0
        assert json.loads(target.read_text())["version"] == BUNDLE_VERSION
        assert str(target) in capsys.readouterr().out

    def test_it_writes_to_stdout_on_dash(self, capsys):
        from guardllm.support import main

        assert main(["-o", "-"]) == 0
        assert json.loads(capsys.readouterr().out)["guardllm"]["deployment"] == "library"

    def test_a_refusal_exits_nonzero_and_says_why(self, tmp_path, capsys):
        """An operator who is refused must be told what to do about it."""
        from guardllm.support import main

        policy = tmp_path / "policy.yaml"
        policy.write_text(f"policy:\n  client_id: {ALPHABET}\n")
        target = tmp_path / "b.json"
        assert main(["-o", str(target), "--policy", str(policy)]) == 2
        assert not target.exists()
        assert "refused to write" in capsys.readouterr().err

    def test_a_broken_policy_file_is_reported_not_raised(self, tmp_path, capsys):
        """A diagnostic tool that needs debugging is not one."""
        from guardllm.support import main

        policy = tmp_path / "policy.yaml"
        policy.write_text("policy:\n  enable_destrucive: true\n")
        assert main(["-o", "-", "--policy", str(policy)]) == 1
        assert "unknown policy setting" in capsys.readouterr().err
