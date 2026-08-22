"""Policy files: what they express, and what they refuse.

The refusals matter more than the round trip. A policy file is read by an
operator who cannot see the dataclass behind it, so anything this accepts and
does not honour is a setting somebody believes is in force.
"""

from __future__ import annotations

import pytest

from guardllm.config import load_policy, parse_policy
from guardllm.security.types import ExtractionPolicy, PolicyConfig, TrustLevel


class TestPolicyFileExpresses:
    def test_every_shape_the_dataclass_needs(self):
        """Including the two YAML cannot write directly: tuple keys and enums."""
        policy = parse_policy(
            """
            policy:
              enable_destructive: false
              server_default_deny: true
              tool_allowlist: [search_knowledge, read_file]
              untrusted_deny_tools: [send_email]
              require_source_id_for: [web]
              confirm_all_below: semi_trusted
              contaminated_tool_policy: deny
              escalated_tool_policy: deny
              dlp_verbatim_lcs_min: 20
              dlp_ngram_overlap_min: 0.5
              capability_scopes:
                search: {scope: read}
              rate_limit_overrides:
                untrusted: {emails_per_hour: 10}
              source_gate_overrides:
                - source_type: web
                  source_trust: untrusted
                  policy: quarantine
            """
        )
        # A tuple-keyed allowlist, written as a plain list.
        assert policy.tool_allowlist == {("search_knowledge",): True, ("read_file",): True}
        assert policy.untrusted_deny_tools == frozenset({"send_email"})
        assert policy.require_source_id_for == frozenset({"web"})
        # Enums, written as their values.
        assert policy.confirm_all_below is TrustLevel.SEMI_TRUSTED
        assert policy.rate_limit_overrides == {TrustLevel.UNTRUSTED: {"emails_per_hour": 10}}
        assert policy.source_gate_overrides == {
            ("web", TrustLevel.UNTRUSTED): ExtractionPolicy.QUARANTINE
        }
        assert policy.server_default_deny is True
        assert policy.dlp_verbatim_lcs_min == 20
        assert policy.dlp_ngram_overlap_min == 0.5

    def test_an_empty_file_is_the_default_policy(self):
        assert parse_policy("") == PolicyConfig()
        assert parse_policy("policy:") == PolicyConfig()

    def test_absent_and_empty_are_not_the_same_allowlist(self):
        """The difference between no allowlist and denying everything.

        Unset means no allowlist, so a non-destructive tool is implicitly
        allowed. An empty list is an allowlist that lists nothing. Collapsing
        them turns the fail-closed setting into the fail-open one.
        """
        assert parse_policy("policy: {tool_allowlist: null}").tool_allowlist is None
        assert parse_policy("policy: {tool_allowlist: []}").tool_allowlist == {}
        assert parse_policy("policy: {capability_scopes: null}").capability_scopes is None
        assert parse_policy("policy: {capability_scopes: {}}").capability_scopes == {}

    def test_load_from_a_path(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text("policy:\n  server_default_deny: true\n")
        assert load_policy(path).server_default_deny is True


class TestPolicyFileRefuses:
    def test_a_typo_is_an_error_not_a_default(self):
        """The failure this file format exists to avoid.

        A misspelled setting that is ignored leaves the default in force and an
        operator believing otherwise. The same shape has been fixed twice in
        this library already, in SecurityContext.mode and in class_policy.
        """
        with pytest.raises(ValueError, match="unknown policy setting"):
            parse_policy("policy: {enable_destrucive: true}")
        # And it points at the field that was probably meant.
        with pytest.raises(ValueError, match="enable_destructive"):
            parse_policy("policy: {enable_destrucive: true}")

    def test_a_quoted_false_does_not_enable_anything(self):
        """YAML 1.1 reads `off` as false and `"false"` as a truthy string.

        Coercing here would make `enable_destructive: "false"` enable
        destructive tools, so nothing coerces.
        """
        assert parse_policy("policy: {enable_destructive: off}").enable_destructive is False
        assert parse_policy("policy: {enable_destructive: no}").enable_destructive is False
        with pytest.raises(ValueError, match="expected true or false"):
            parse_policy('policy: {enable_destructive: "false"}')

    def test_a_boolean_is_not_an_integer(self):
        """bool subclasses int, so an unguarded check reads `true` as 1."""
        with pytest.raises(ValueError, match="got a boolean"):
            parse_policy("policy: {dlp_verbatim_lcs_min: true}")

    @pytest.mark.parametrize(
        "text, match",
        [
            ("policy: {confirm_all_below: sort_of_trusted}", "not a valid trust level"),
            ("policy: {untrusted_deny_tools: send_email}", "expected a list of strings"),
            ("policy: {untrusted_deny_tools: [1]}", "found int"),
            ("policy: {source_gate_overrides: [{source_type: web}]}", "missing"),
            (
                "policy: {source_gate_overrides: [{source_type: web, source_trust: untrusted,"
                " policy: quarantine, extra: 1}]}",
                "unknown key",
            ),
            ("policy: {rate_limit_overrides: {nobody: {emails_per_hour: 1}}}", "trust level"),
            ("policy: {capability_scopes: 3}", "expected a mapping"),
            ("policy: [1, 2]", "expected a mapping"),
            ("badkey: {}", "unknown top-level key"),
        ],
    )
    def test_malformed_values(self, text, match):
        with pytest.raises(ValueError, match=match):
            parse_policy(text)

    def test_a_reserved_field_is_refused_rather_than_accepted(self):
        """directive_patterns is a constructor field the engine never reads.

        Accepting it from a file would let an operator write an access rule
        that does nothing, which is worse than having no way to write it.
        """
        with pytest.raises(ValueError, match="reserved"):
            parse_policy("policy: {directive_patterns: {send: '^send'}}")

    def test_the_dataclass_still_validates_what_it_owns(self):
        """The loader does not restate rules PolicyConfig already enforces."""
        with pytest.raises(ValueError, match="contaminated_tool_policy"):
            parse_policy("policy: {contaminated_tool_policy: sometimes}")
        with pytest.raises(ValueError, match="rate_limit_overrides"):
            parse_policy("policy: {rate_limit_overrides: {untrusted: {made_up: 1}}}")

    def test_only_safe_load_is_used(self):
        """A policy file must not be able to construct Python objects.

        `yaml.load` with the default loader does, which would make the config
        format an execution vector in the library whose job is to stop that.
        """
        with pytest.raises(Exception) as caught:
            parse_policy("policy: !!python/object/apply:os.system ['echo pwned']")
        assert "python/object" in str(caught.value) or "could not determine" in str(caught.value)
