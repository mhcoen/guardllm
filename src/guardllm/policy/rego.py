"""Evaluate a Rego policy locally, in process, with no network.

OPA compiles Rego to WebAssembly (``opa build -t wasm``), and that module runs
here through wasmtime in microseconds. Local is the whole point: the library's
claim is that it makes no external API calls, and an HTTP hop to a policy
server would end that. A deployment that already runs central OPA attaches it
at the gateway, which is where network-dependent backends belong.

The seam matters more than the wiring. GuardLLM computes facts nothing else in
a normal stack knows, above all whether this session has already ingested
untrusted content or already had an exfiltration blocked; OPA expresses who may
do what. So GuardLLM produces the facts and Rego decides on them, and the input
document below is the interface. Get that right and OPA, Casbin, or a
customer's own service plug into the same place.

Ordering is not negotiable, and ``PolicyDecision`` exists to make it hard to
get wrong: a GuardLLM deny is final and Rego is never consulted, while on a
GuardLLM allow Rego may still deny. A Rego allow never overrides a GuardLLM
deny. That is the same strictest-wins rule the library already applies when
contamination and escalation both fire.
"""

from __future__ import annotations

import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["POLICY_INPUT_VERSION", "RegoPolicy", "PolicyDecision", "build_input"]

#: The version of the input document a policy is written against.
#:
#: This is the interface with the longest life in the product. A customer's
#: Rego rules live in their repository, not ours, and a customer-hosted
#: deployment runs a release for years, so a field cannot be renamed once
#: anyone has read it. The version travels inside the document rather than
#: alongside it, so a policy can branch on ``input.version`` and keep working
#: across an increment instead of failing at the first changed field.
#:
#: The contract within a version: fields may be ADDED, and a policy that does
#: not read them is unaffected. No field is removed, renamed, or given a new
#: meaning. Anything else increments this.
POLICY_INPUT_VERSION = 1


@dataclass(frozen=True)
class PolicyDecision:
    """What a Rego policy said, and why.

    ``allowed`` is False when the policy produced any deny reason. An empty
    policy result is an allow: Rego rules here are written as ``deny``
    messages, so silence means nothing objected.
    """

    allowed: bool
    reasons: tuple[str, ...] = ()

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "no policy objection"


def build_input(
    *,
    tool: str,
    args: dict[str, Any] | None = None,
    user: dict[str, Any] | None = None,
    contaminated: bool = False,
    escalated: bool = False,
    untrusted_sources: list[str] | None = None,
    injection_detected: bool = False,
    canary_detected: bool = False,
    binding_valid: bool = True,
) -> dict[str, Any]:
    """The input document a policy sees.

    Everything under ``guardllm`` is a fact the library computed and that a
    policy engine has no other way to know. Everything outside it is the
    host's: identity in particular, which the library never invents.

    Kept as an explicit function rather than assembled inline at each call site
    so the schema has one definition. A policy is written against this shape,
    so changing it silently would break rules a customer has already deployed.

    ``version`` is ``POLICY_INPUT_VERSION`` and lets a policy branch rather than
    break across an increment. Within a version, fields are only ever added.

    ``user.roles`` is always present, as a list, even when the host supplied no
    user at all. That is not tidiness. In Rego an undefined reference makes the
    whole rule body undefined, so ``not "admin" in input.user.roles`` against a
    user with no ``roles`` key does not deny, it simply fails to fire, and an
    access-control rule that fails to fire is one that fails OPEN. Measured on
    the fixture policy: absent ``roles`` allowed ``delete_account`` through,
    while ``roles: []`` denied it correctly. A total schema removes the trap for
    every policy author instead of asking each of them to write around it.
    """
    identity = dict(user or {})
    identity.setdefault("roles", [])
    return {
        "version": POLICY_INPUT_VERSION,
        "user": identity,
        "tool": tool,
        "args": args or {},
        "guardllm": {
            "session_contaminated": contaminated,
            "session_escalated": escalated,
            "untrusted_sources": sorted(untrusted_sources or []),
            "injection_detected": injection_detected,
            "canary_detected": canary_detected,
            "binding_valid": binding_valid,
        },
    }


def _wasmtime():
    """wasmtime, imported lazily so the core install does not require it."""
    try:
        import wasmtime
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on install
        raise ModuleNotFoundError(
            "Rego policy evaluation needs wasmtime, which is not part of the "
            "core install. Add it with: pip install 'guardllm[rego]'"
        ) from exc
    return wasmtime


def _bundle_member(bundle: tarfile.TarFile, *names: str) -> bytes | None:
    """The first member present under any of ``names``, or None."""
    for name in names:
        try:
            member = bundle.extractfile(name)
        except KeyError:
            continue
        if member is not None:
            return member.read()
    return None


def _policy_parts(path: Path) -> tuple[bytes, str]:
    """Read policy.wasm AND data.json from an OPA bundle.

    ``opa build -t wasm`` emits a gzipped tar holding ``/policy.wasm`` and,
    when the bundle carries any, ``/data.json``. A bare ``.wasm`` file is also
    accepted, because both are things a person ends up with; it has no data.

    The data document has to come from the bundle. An earlier version parsed
    an empty one here and said in a comment that a bundle's own ``data.json``
    still applied. It does not: the WASM ABI takes the data document as a
    caller-supplied argument, and nothing is compiled into the module. A rule
    reading ``data.config.blocked_tools`` therefore found nothing, and in Rego
    an undefined reference makes the whole rule body undefined, so the rule did
    not deny -- it failed to fire. Measured against ``opa eval`` on the same
    bundle and input: OPA returned two deny messages, this returned "no policy
    objection".
    """
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b" or path.suffixes[-2:] == [".tar", ".gz"]:
        with tarfile.open(path) as bundle:
            wasm = _bundle_member(bundle, "/policy.wasm", "policy.wasm", "./policy.wasm")
            if wasm is None:
                raise ValueError(f"{path} is a bundle with no policy.wasm in it")
            data = _bundle_member(bundle, "/data.json", "data.json", "./data.json")
        if data is None:
            return wasm, "{}"
        text = data.decode("utf-8")
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path} holds a data.json that is not valid JSON: {exc}") from exc
        return wasm, text
    return raw, "{}"


class RegoPolicy:
    """A compiled Rego policy, evaluated in process.

    Build one with::

        opa build -t wasm -e guardllm/deny policy.rego -o bundle.tar.gz

    The entrypoint must produce a set or array of deny messages. Strings are
    taken as reasons; anything else is stringified, because a policy author who
    returns an object still means "this is why".
    """

    def __init__(self, path: str | Path) -> None:
        wasmtime = _wasmtime()
        self._path = Path(path)
        wasm, data_document = _policy_parts(self._path)

        self._engine = wasmtime.Engine()
        self._store = wasmtime.Store(self._engine)
        module = wasmtime.Module(self._engine, wasm)
        linker = wasmtime.Linker(self._engine)

        def _stub(arity: int, returns: bool):
            params = [wasmtime.ValType.i32()] * arity
            results = [wasmtime.ValType.i32()] if returns else []
            kind = wasmtime.FuncType(params, results)
            # Reaching one of these is a bug rather than a policy outcome:
            # every builtin the policy actually requires is rejected at load
            # time by _refuse_unsupported_builtins below, so nothing should
            # ever call one. Returning 0 was what made an unimplemented builtin
            # read as undefined, which in Rego means the rule does not fire,
            # which for a deny rule means the call is allowed.
            body = (lambda *_a: 0) if returns else (lambda *_a: None)
            return wasmtime.Func(self._store, kind, body)

        linker.define(self._store, "env", "opa_abort", _stub(1, False))
        linker.define(self._store, "env", "opa_println", _stub(1, False))
        for i in range(5):
            linker.define(self._store, "env", f"opa_builtin{i}", _stub(i + 2, True))
        memory = wasmtime.Memory(self._store, wasmtime.MemoryType(wasmtime.Limits(2, None)))
        linker.define(self._store, "env", "memory", memory)

        instance = linker.instantiate(self._store, module)
        self._exports = instance.exports(self._store)
        self._memory = self._exports["memory"]
        self._refuse_unsupported_builtins()
        # Parsed once, from the bundle. Most facts a policy needs arrive as
        # input; a bundle that ships reference data expects that data to be
        # here, and passing an empty document instead silently disabled every
        # rule that read it.
        self._data = self._exports["opa_json_parse"](self._store, *self._write(data_document))
        # Everything allocated from here on belongs to one evaluation. The heap
        # is wound back to this mark before each one, so the data document and
        # the module's own allocations survive and the per-call allocations do
        # not accumulate. Without it the WASM heap grew by about 2.2 KB per
        # evaluation and was never reclaimed: 55 MB after 26,000 calls, in a
        # component that sits on the path of every tool call in a gateway that
        # runs for weeks.
        self._heap_base = self._exports["opa_heap_ptr_get"](self._store)

    def _dump(self, addr: int) -> str:
        """Serialize an OPA value address to JSON text."""
        return self._read(self._exports["opa_json_dump"](self._store, addr))

    def _refuse_unsupported_builtins(self) -> None:
        """Refuse a policy that needs a builtin this host does not implement.

        ``builtins()`` names exactly the builtins OPA could not compile into
        the module and expects the host to supply. GuardLLM supplies none: it
        evaluates access-control rules in process with no network, and the
        builtins in that set are the ones whose implementations would be host
        behaviour rather than policy.

        Refusing at load is the whole point. The alternative, which is what
        this did before, is to answer every such call with 0. In Rego that
        reads as undefined, an undefined reference makes the enclosing rule
        body undefined, and a ``deny`` rule that does not fire is an allow. So
        a policy the author tested with ``opa eval`` and watched deny would
        load here, evaluate, and permit the call, with nothing anywhere saying
        why. A refusal at load is loud, happens once, and happens before the
        policy is trusted with a decision.

        ``sprintf`` is the common one, because it is how a deny message
        interpolates the thing it objected to. A literal message needs no
        builtin, and the fixture policy in this repository requires none at
        all.
        """
        required = json.loads(self._dump(self._exports["builtins"](self._store)) or "{}")
        if not required:
            return
        names = ", ".join(sorted(required))
        raise ValueError(
            f"{self._path} needs Rego builtins this build does not implement: {names}. "
            "They are refused at load rather than stubbed, because a stubbed builtin "
            "reads as undefined in Rego, an undefined reference makes the rule body "
            "undefined, and a deny rule that does not fire allows the call. Rewrite "
            "the rules without them (a literal deny message needs no sprintf)."
        )

    def _write(self, text: str) -> tuple[int, int]:
        raw = text.encode("utf-8")
        addr = self._exports["opa_malloc"](self._store, len(raw))
        self._memory.write(self._store, raw, addr)
        return addr, len(raw)

    def _read(self, addr: int) -> str:
        data = self._memory.read(self._store, addr, self._memory.data_len(self._store))
        return data[: data.index(b"\x00")].decode("utf-8")

    def evaluate(self, document: dict[str, Any]) -> PolicyDecision:
        """Run the policy over one input document.

        Not safe to call concurrently on one instance: the wasmtime store and
        the heap mark below are per-instance mutable state. One policy object
        per session, or a lock, the same contract the pipeline states.
        """
        # Wind the heap back before allocating, not after reading, so the
        # previous result stays readable until the next call and the reset
        # happens exactly once per evaluation even if reading raises.
        self._exports["opa_heap_ptr_set"](self._store, self._heap_base)
        addr, length = self._write(json.dumps(document))
        heap = self._exports["opa_heap_ptr_get"](self._store)
        result_addr = self._exports["opa_eval"](
            self._store, 0, 0, self._data, addr, length, heap, 0
        )
        raw = json.loads(self._read(result_addr))

        reasons: list[str] = []
        for entry in raw:
            value = entry.get("result") if isinstance(entry, dict) else None
            if value is None:
                continue
            if isinstance(value, (list, tuple, set)):
                reasons.extend(str(v) for v in value)
            elif isinstance(value, bool):
                # An entrypoint that returns a bare boolean reads as "denied".
                if value:
                    reasons.append("policy denied")
            else:
                reasons.append(str(value))
        return PolicyDecision(allowed=not reasons, reasons=tuple(reasons))


def decide(
    *,
    guard_allowed: bool,
    guard_reason: str,
    policy: RegoPolicy | None,
    document: dict[str, Any],
) -> PolicyDecision:
    """Combine GuardLLM's verdict with a Rego policy. Strictest wins.

    A GuardLLM deny is final and the policy is NOT consulted, because a policy
    able to overturn it would be a way to configure the enforcement off. Rego
    only ever narrows: it is asked whether an already-permitted call should
    additionally be refused.
    """
    if not guard_allowed:
        return PolicyDecision(allowed=False, reasons=(guard_reason,))
    if policy is None:
        return PolicyDecision(allowed=True, reasons=(guard_reason,))
    verdict = policy.evaluate(document)
    if verdict.allowed:
        return PolicyDecision(allowed=True, reasons=(guard_reason,))
    return verdict
