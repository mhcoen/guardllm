"""A diagnostic bundle a customer can attach to a support ticket.

Customer-hosted delivery means the failing system is one nobody here can look
at. When an operator reports that GuardLLM refused a legitimate call, the whole
evidence base is what they can be talked through producing, so the alternative
to this file is a long thread of "run this, paste the output". One command that
writes one file replaces it.

What goes in is chosen by what actually closes tickets. Most "why was this
blocked" reports resolve to a setting the operator believes is in force and is
not, so the bundle reports the RESOLVED policy and names every field that
differs from the default. The next commonest is an extra that was never
installed, so a Rego policy was never consulted and a YAML file was never read:
both fail quietly by design, and both are one line here.

What stays out matters more, and is the reason this lives in the library rather
than in a support runbook. A diagnostic that scoops up prompts, tool arguments
or restored values turns a support ticket into an unplanned data transfer, in
the one product whose subject is exactly that. Three rules hold:

**No content, ever.** The decision chain names stages, tools and verdicts, and
holds no message text; the reason strings come from the library and are already
written to exclude the values they describe. Nothing here reaches for a prompt.

**Environment variables by name, never by value.** Whether ``GUARDLLM_UPSTREAM``
was set answers a real question. What it was set to can carry a key in a query
string, and no bundle needs it.

**The bundle is scanned before it is written**, by the same two passes that
guard egress, so a credential that reached a config value cannot leave in a
diagnostic. Attribution replaces what it can locate exactly. Recognition is the
half that decides: a credential recognized with no span to replace makes
``build_bundle`` REFUSE rather than write a file that might carry it. That is
the same rule the library applies at the model boundary, and it is why the
refusal is not a bug to work around.
"""

from __future__ import annotations

import dataclasses
import json
import os
import platform
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from guardllm.security.outbound_dlp import scan_secret_spans
from guardllm.security.types import PolicyConfig

__all__ = [
    "BUNDLE_VERSION",
    "UnsafeBundleError",
    "build_bundle",
    "render_bundle",
    "write_bundle",
]

#: The bundle format, versioned for the same reason the policy file is: a
#: customer-hosted deployment runs a release for years, so a bundle arriving in
#: a ticket may have been written by a build older than the one reading it.
#: Within a version, keys are only ever added.
BUNDLE_VERSION = 1

#: Reported by name and presence only. A value here can carry a key inside a
#: URL, and no diagnostic needs one.
_ENV_PREFIX = "GUARDLLM_"

#: Optional installs whose absence silently disables a feature, which is why
#: each one is worth a line: a Rego policy that was never evaluated and a YAML
#: file that was never read both look like a policy that did not fire.
_OPTIONAL = {
    "yaml": "PyYAML, needed to read a YAML policy file",
    "wasmtime": "needed to evaluate a Rego policy",
}
_CORE = ("beautifulsoup4", "soupsieve", "confusables")


class UnsafeBundleError(RuntimeError):
    """The bundle held a credential that could not be removed faithfully.

    Raised rather than returning a redacted-looking bundle, because the span
    pass could not locate the value to replace it. Refusing is the same answer
    the model boundary gives to the same question.
    """


def _distribution_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _optional_report() -> dict[str, Any]:
    """Whether each optional dependency can actually be imported.

    Import rather than distribution metadata: a package present in metadata but
    unimportable is precisely the state that produces a confusing ticket.
    """
    out: dict[str, Any] = {}
    for module, why in _OPTIONAL.items():
        try:
            __import__(module)
        except Exception:  # noqa: BLE001  # any import failure is "not usable"
            out[module] = {"importable": False, "version": None, "needed_for": why}
        else:
            dist = {"yaml": "PyYAML"}.get(module, module)
            out[module] = {
                "importable": True,
                "version": _distribution_version(dist),
                "needed_for": why,
            }
    return out


def _jsonable(value: Any) -> Any:
    """Render a policy value as JSON, losing nothing an operator would read."""
    if isinstance(value, dict):
        return {_key(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (frozenset, set)):
        return sorted(_key(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "value") and hasattr(value, "name"):  # an enum
        return value.value
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _key(value: Any) -> str:
    """A dict key as a string. Tuple keys exist here; JSON has none."""
    if isinstance(value, tuple):
        return ".".join(str(_key(v)) for v in value)
    if hasattr(value, "value") and hasattr(value, "name"):
        return str(value.value)
    return str(value)


def _policy_report(policy: PolicyConfig, source: str) -> dict[str, Any]:
    """The resolved policy, and which fields were changed from the default.

    The changed list is the part that closes tickets. A reader scanning 25
    settings for the one that is not stock is doing work the bundle can do.

    ``source`` says where it came from, and the reason it is here is a live
    gateway run: with no policy file this reported ``policy: null``, which
    reads as "no policy in force" when the truth is that the defaults are in
    force and they are what refused the call. A bundle whose whole job is to
    say what is in force must never be silent about it.
    """
    default = PolicyConfig()
    resolved: dict[str, Any] = {}
    changed: list[str] = []
    for field in dataclasses.fields(policy):
        value = getattr(policy, field.name)
        resolved[field.name] = _jsonable(value)
        if value != getattr(default, field.name):
            changed.append(field.name)
    return {"source": source, "resolved": resolved, "changed_from_default": sorted(changed)}


def _environment() -> dict[str, Any]:
    return {
        "python": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        # Names only. See the module docstring: a value can carry a key.
        "guardllm_env_vars_set": sorted(k for k in os.environ if k.startswith(_ENV_PREFIX)),
        "in_container": Path("/.dockerenv").exists(),
    }


def _scrub(text: str) -> str:
    """Remove credentials from the rendered bundle, or refuse.

    The two passes answer different questions and both are consulted here.
    Spans are attribution and can be replaced exactly. Labels are recognition,
    and a label with no span covering it means a credential is present that
    this cannot faithfully remove, which is a refusal rather than a redaction
    that might not have caught it.
    """
    spans, labels = scan_secret_spans(text)
    out = text
    for start, end in sorted(spans, reverse=True):
        out = f"{out[:start]}[redacted: credential]{out[end:]}"
    # ANY label is a refusal. The scanner computes labels against the text with
    # every span already masked out, so a label means a credential that is
    # still recognizable once everything replaceable has been replaced. An
    # earlier version of this compared label and span counts and let the case
    # through that matters most: one document holding one key that could be
    # located and one that could not scored 1 against 1 and wrote the file.
    if labels:
        raise UnsafeBundleError(
            "the bundle holds credential material that cannot be removed "
            f"exactly ({sorted(set(labels))}), so no file was written. Remove "
            "the secret from your configuration, or pass the settings that "
            "carry it out of band."
        )
    return out


def build_bundle(
    *,
    policy: PolicyConfig | None = None,
    policy_path: str | Path | None = None,
    chain: Any | None = None,
    deployment: str = "library",
    notes: str | None = None,
) -> dict[str, Any]:
    """Collect the bundle as a dictionary.

    ``chain`` is any object with an ``as_dict``, which is
    ``guardllm.gateway.forensics.Chain`` in practice. It is the piece no other
    tool can supply: a block at step nine is explained by an ingest at step
    two, and no per-request log shows that relationship.
    """
    source = "explicit"
    if policy is None and policy_path is not None:
        from guardllm.config import load_policy

        policy = load_policy(policy_path)
        source = "file"
    elif policy is None:
        # Never report "no policy". The defaults are a policy, and they are
        # what refused the call the operator is asking about.
        policy = PolicyConfig()
        source = "defaults"

    bundle: dict[str, Any] = {
        "version": BUNDLE_VERSION,
        "guardllm": {
            "version": _distribution_version("guardllm"),
            "deployment": deployment,
            "core_dependencies": {name: _distribution_version(name) for name in _CORE},
        },
        "optional_dependencies": _optional_report(),
        "environment": _environment(),
        "policy": _policy_report(policy, source),
        "policy_file": str(policy_path) if policy_path else None,
        "decision_chain": chain.as_dict() if chain is not None else None,
    }
    if notes:
        bundle["notes"] = notes
    return bundle


def render_bundle(bundle: dict[str, Any]) -> str:
    """Serialize a bundle to JSON, scanned for credentials on the way out."""
    return _scrub(json.dumps(bundle, indent=2, sort_keys=True, default=repr))


def write_bundle(path: str | Path, **kwargs: Any) -> Path:
    """Build, scrub and write a bundle. Returns the path written.

    Nothing is written when the scan refuses: the file is rendered in full
    before it is opened, so a refusal leaves no partial bundle behind.
    """
    text = render_bundle(build_bundle(**kwargs))
    target = Path(path)
    target.write_text(text, encoding="utf-8")
    return target


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="guardllm.support",
        description="Write a diagnostic bundle for a support ticket.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="guardllm-support.json",
        help="file to write, or - for standard output",
    )
    parser.add_argument(
        "--policy",
        default=os.environ.get("GUARDLLM_POLICY"),
        help="path to the YAML policy file this deployment runs",
    )
    parser.add_argument(
        "--deployment",
        default="library",
        choices=("library", "gateway", "container"),
        help="how GuardLLM is deployed here",
    )
    parser.add_argument("--note", default=None, help="one line describing the problem")
    args = parser.parse_args(argv)

    try:
        text = render_bundle(
            build_bundle(
                policy_path=args.policy,
                deployment=args.deployment,
                notes=args.note,
            )
        )
    except UnsafeBundleError as exc:
        print(f"guardllm.support: refused to write a bundle: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001  # a diagnostic must not need debugging
        print(f"guardllm.support: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.output == "-":
        print(text)
        return 0
    written = Path(args.output)
    written.write_text(text, encoding="utf-8")
    print(f"wrote {written} ({len(text)} bytes). Nothing in it holds message content.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
