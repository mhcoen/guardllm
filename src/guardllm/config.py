"""Load a PolicyConfig from YAML.

A deployment that runs GuardLLM behind a process boundary has nowhere to put a
Python dataclass, so policy has to be expressible as a file. This reads one.

Three rules govern everything below, and all three exist because a security
policy that is quietly not in force is worse than no policy at all:

**An unknown key is an error.** Not a warning, not ignored. ``enable_destrucive``
is a typo that leaves destructive tools disabled and an operator believing they
enabled them, and the same shape has already been fixed twice in this library:
``SecurityContext.mode`` accepted a typo and fell through to client mode, and
``class_policy`` accepted an entry that could never take effect.

**A value of the wrong type is an error.** YAML 1.1 reads ``off`` and ``no`` as
false, which is convenient, but it reads ``"false"`` as a non-empty string, and
a non-empty string is truthy. ``enable_destructive: "false"`` must not enable
destructive tools. Nothing here coerces; a bool field takes a bool.

**Absent and empty are different.** ``tool_allowlist:`` with no value leaves it
unset, which means no allowlist and every non-destructive tool implicitly
allowed. ``tool_allowlist: []`` is an empty allowlist, which denies everything.
Collapsing those two would turn the fail-closed setting into the fail-open one.

Only ``PolicyConfig`` is covered. ``PrivacyConfig`` holds detector instances and
class-to-policy mappings that no file can name, so it stays a Python object.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from guardllm.security.types import (
    ExtractionPolicy,
    PolicyConfig,
    TrustLevel,
)

__all__ = ["POLICY_FILE_VERSION", "SUPPORTED_POLICY_FILE_VERSIONS", "load_policy", "parse_policy"]

#: The policy-file format this build writes and understands.
#:
#: Versioned because a customer-hosted deployment runs a release for years and
#: cannot be forced forward, so this format is a long-lived interface rather
#: than an implementation detail. The direction that needs guarding is an OLD
#: build reading a NEW file: it would otherwise see settings it does not
#: implement, reject them as unknown keys, and report a typo when the truth is
#: that the operator's policy is not being enforced as written.
#:
#: Within a version, settings may be ADDED. None is ever removed, renamed, or
#: given a new meaning; that requires an increment.
POLICY_FILE_VERSION = 1

#: Every version this build accepts. An absent ``version:`` means 1, so files
#: written before the key existed keep working and no boilerplate is required
#: of anyone. An unrecognized version is refused rather than guessed at.
SUPPORTED_POLICY_FILE_VERSIONS = frozenset({1})


def _yaml():
    """PyYAML, imported here so the core install does not require it.

    Only ``safe_load`` is ever used. ``yaml.load`` with the default loader
    constructs arbitrary Python objects, which would make a policy file a code
    execution vector in the one library whose job is to stop that.
    """
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on install
        raise ModuleNotFoundError(
            "Reading a policy file needs PyYAML, which is not part of the core "
            "install. Add it with: pip install 'guardllm[yaml]'"
        ) from exc
    return yaml


# Fields taken as-is once their type is checked.
_BOOL_FIELDS = frozenset(
    {
        "enable_destructive",
        "server_default_deny",
        "escalation_gate_enabled",
        "untrusted_require_auth",
        "auto_confirm_destructive",
    }
)
_INT_FIELDS = frozenset(
    {"dlp_verbatim_lcs_min", "dlp_sensitive_lcs_min", "provenance_verbatim_lcs_min"}
)
_FLOAT_FIELDS = frozenset({"dlp_ngram_overlap_min", "provenance_ngram_overlap_min"})
_STR_FIELDS = frozenset(
    {
        "client_id",
        "contaminated_action",
        "contaminated_tool_policy",
        "escalated_tool_policy",
        "require_message_binding",
    }
)
#: Lists of tool or source names that become frozensets.
_STR_SET_FIELDS = frozenset({"untrusted_deny_tools", "require_source_id_for"})
#: Host-shaped mappings the library does not interpret here. Their contents are
#: validated where they are used, not on the way in.
_MAPPING_FIELDS = frozenset({"capability_scopes", "rate_limits", "argument_limits"})
#: Handled individually below.
_SPECIAL_FIELDS = frozenset(
    {
        "tool_allowlist",
        "confirm_all_below",
        "source_gate_overrides",
        "rate_limit_overrides",
    }
)
#: Accepted by the constructor but never read. Silently accepting it in a file
#: would let an operator write an access rule that does nothing.
_REFUSED_FIELDS = {
    "directive_patterns": (
        "directive_patterns is reserved and not consulted by the policy engine. "
        "Authorization-event origin is a host obligation; see A-AS8 in "
        "docs/threat_model.md."
    )
}

_KNOWN_FIELDS = (
    _BOOL_FIELDS
    | _INT_FIELDS
    | _FLOAT_FIELDS
    | _STR_FIELDS
    | _STR_SET_FIELDS
    | _MAPPING_FIELDS
    | _SPECIAL_FIELDS
)


def _fail(where: str, message: str) -> None:
    raise ValueError(f"policy.{where}: {message}")


def _check(where: str, value: object, want: type, name: str) -> Any:
    # bool is a subclass of int, so an unguarded int check accepts `true` for
    # a threshold and reads it as 1.
    if want is not bool and isinstance(value, bool):
        _fail(where, f"expected {name}, got a boolean")
    if not isinstance(value, want):
        _fail(where, f"expected {name}, got {type(value).__name__}")
    return value


def _enum(where: str, value: object, enum: type, name: str) -> Any:
    if not isinstance(value, str):
        _fail(where, f"expected one of {[e.value for e in enum]}, got {type(value).__name__}")
    try:
        return enum(value)
    except ValueError:
        _fail(where, f"{value!r} is not a valid {name}: {[e.value for e in enum]}")


def _string_list(where: str, value: object) -> list[str]:
    if not isinstance(value, list):
        _fail(where, f"expected a list of strings, got {type(value).__name__}")
    for item in value:
        if not isinstance(item, str):
            _fail(where, f"expected a list of strings, found {type(item).__name__}")
    return value


def _tool_allowlist(value: object) -> dict[tuple, Any] | None:
    """A list of tool names, or an empty list to deny everything.

    The engine keys this by tuple and reads only the first element, so a name
    becomes ``("name",)``. Written as a plain list here because a file should
    not have to know that.
    """
    if value is None:
        return None
    names = _string_list("tool_allowlist", value)
    return {(name,): True for name in names}


def _source_gate_overrides(value: object) -> dict[tuple[str, TrustLevel], ExtractionPolicy]:
    """A list of rows, because the key is a pair and YAML has no tuple keys."""
    where = "source_gate_overrides"
    if not isinstance(value, list):
        _fail(where, f"expected a list of entries, got {type(value).__name__}")
    out: dict[tuple[str, TrustLevel], ExtractionPolicy] = {}
    for i, row in enumerate(value):
        at = f"{where}[{i}]"
        if not isinstance(row, dict):
            _fail(at, f"expected a mapping, got {type(row).__name__}")
        missing = {"source_type", "source_trust", "policy"} - set(row)
        if missing:
            _fail(at, f"missing {sorted(missing)}")
        extra = set(row) - {"source_type", "source_trust", "policy"}
        if extra:
            _fail(at, f"unknown key(s) {sorted(extra)}")
        source_type = _check(f"{at}.source_type", row["source_type"], str, "a string")
        trust = _enum(f"{at}.source_trust", row["source_trust"], TrustLevel, "trust level")
        policy = _enum(f"{at}.policy", row["policy"], ExtractionPolicy, "extraction policy")
        out[(source_type, trust)] = policy
    return out


def _rate_limit_overrides(value: object) -> dict[TrustLevel, dict[str, int]]:
    where = "rate_limit_overrides"
    if not isinstance(value, dict):
        _fail(where, f"expected a mapping keyed by trust level, got {type(value).__name__}")
    out: dict[TrustLevel, dict[str, int]] = {}
    for key, limits in value.items():
        trust = _enum(f"{where}.{key}", key, TrustLevel, "trust level")
        at = f"{where}.{key}"
        if not isinstance(limits, dict):
            _fail(at, f"expected a mapping of limit name to integer, got {type(limits).__name__}")
        for name, limit in limits.items():
            _check(f"{at}.{name}", limit, int, "an integer")
        out[trust] = dict(limits)
    return out


def _build(data: object) -> PolicyConfig:
    if data is None:
        return PolicyConfig()
    if not isinstance(data, dict):
        raise ValueError(f"policy: expected a mapping, got {type(data).__name__}")

    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        if key in _REFUSED_FIELDS:
            _fail(key, _REFUSED_FIELDS[key])
        if key not in _KNOWN_FIELDS:
            near = sorted(f for f in _KNOWN_FIELDS if f.startswith(key[:4]))
            hint = f" Did you mean one of {near}?" if near else ""
            _fail(key, f"unknown policy setting.{hint}")

        if key in _BOOL_FIELDS:
            kwargs[key] = _check(key, value, bool, "true or false")
        elif key in _INT_FIELDS:
            kwargs[key] = _check(key, value, int, "an integer")
        elif key in _FLOAT_FIELDS:
            kwargs[key] = float(_check(key, value, (int, float), "a number"))
        elif key in _STR_FIELDS:
            kwargs[key] = _check(key, value, str, "a string")
        elif key in _STR_SET_FIELDS:
            kwargs[key] = frozenset(_string_list(key, value))
        elif key in _MAPPING_FIELDS:
            if value is not None and not isinstance(value, dict):
                _fail(key, f"expected a mapping, got {type(value).__name__}")
            kwargs[key] = value
        elif key == "tool_allowlist":
            kwargs[key] = _tool_allowlist(value)
        elif key == "confirm_all_below":
            kwargs[key] = None if value is None else _enum(key, value, TrustLevel, "trust level")
        elif key == "source_gate_overrides":
            kwargs[key] = _source_gate_overrides(value)
        elif key == "rate_limit_overrides":
            kwargs[key] = _rate_limit_overrides(value)

    # PolicyConfig.__post_init__ validates the option strings it owns, so a bad
    # contaminated_tool_policy raises there rather than being restated here.
    return PolicyConfig(**kwargs)


def _check_version(document: dict[str, Any]) -> None:
    """Refuse a file this build cannot read, and say which way the gap runs.

    The two directions fail differently and the message has to distinguish
    them, because the remedy is opposite: a newer file needs a newer GuardLLM,
    a retired version needs the file migrating.
    """
    if "version" not in document:
        return  # absent means 1: files written before the key keep working
    version = document["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError(f"policy file: version must be an integer, got {type(version).__name__}")
    if version in SUPPORTED_POLICY_FILE_VERSIONS:
        return
    if version > POLICY_FILE_VERSION:
        raise ValueError(
            f"policy file: version {version} is newer than this build understands "
            f"(supports {sorted(SUPPORTED_POLICY_FILE_VERSIONS)}). Upgrade guardllm "
            "rather than editing the file: settings it adds would otherwise be "
            "silently unenforced."
        )
    raise ValueError(
        f"policy file: version {version} is no longer supported "
        f"(supports {sorted(SUPPORTED_POLICY_FILE_VERSIONS)})."
    )


def parse_policy(text: str) -> PolicyConfig:
    """Build a PolicyConfig from YAML text.

    The document is a mapping with a ``policy`` key and an optional ``version``,
    so a future section can be added without changing the shape of every file
    already written.
    """
    document = _yaml().safe_load(text)
    if document is None:
        return PolicyConfig()
    if not isinstance(document, dict):
        raise ValueError(f"policy file: expected a mapping, got {type(document).__name__}")
    unknown = set(document) - {"policy", "version"}
    if unknown:
        raise ValueError(
            f"policy file: unknown top-level key(s) {sorted(unknown)}; "
            "expected 'policy' and optionally 'version'"
        )
    _check_version(document)
    return _build(document.get("policy"))


def load_policy(path: str | Path) -> PolicyConfig:
    """Build a PolicyConfig from a YAML file."""
    return parse_policy(Path(path).read_text(encoding="utf-8"))
