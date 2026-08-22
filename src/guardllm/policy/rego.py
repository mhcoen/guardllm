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

__all__ = ["RegoPolicy", "PolicyDecision", "build_input"]


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


def _policy_wasm(path: Path) -> bytes:
    """Read policy.wasm from an OPA bundle, or from a bare .wasm file.

    ``opa build -t wasm`` emits a gzipped tar holding ``/policy.wasm``. Both
    are accepted because both are things a person ends up with.
    """
    data = path.read_bytes()
    if data[:2] == b"\x1f\x8b" or path.suffixes[-2:] == [".tar", ".gz"]:
        with tarfile.open(path) as bundle:
            for name in ("/policy.wasm", "policy.wasm", "./policy.wasm"):
                try:
                    member = bundle.extractfile(name)
                except KeyError:
                    continue
                if member is not None:
                    return member.read()
        raise ValueError(f"{path} is a bundle with no policy.wasm in it")
    return data


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
        wasm = _policy_wasm(self._path)

        self._engine = wasmtime.Engine()
        self._store = wasmtime.Store(self._engine)
        module = wasmtime.Module(self._engine, wasm)
        linker = wasmtime.Linker(self._engine)

        def _stub(arity: int, returns: bool):
            params = [wasmtime.ValType.i32()] * arity
            results = [wasmtime.ValType.i32()] if returns else []
            kind = wasmtime.FuncType(params, results)
            # A policy that reaches a builtin we did not provide gets 0 rather
            # than a crash. The WASM target already lacks the builtins that
            # would matter here, http.send above all, and access-control rules
            # do not use them.
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
        # Parsed once: the data document is empty here because every fact a
        # policy needs arrives as input. A bundle's own data.json still applies.
        self._data = self._exports["opa_json_parse"](self._store, *self._write("{}"))

    def _write(self, text: str) -> tuple[int, int]:
        raw = text.encode("utf-8")
        addr = self._exports["opa_malloc"](self._store, len(raw))
        self._memory.write(self._store, raw, addr)
        return addr, len(raw)

    def _read(self, addr: int) -> str:
        data = self._memory.read(self._store, addr, self._memory.data_len(self._store))
        return data[: data.index(b"\x00")].decode("utf-8")

    def evaluate(self, document: dict[str, Any]) -> PolicyDecision:
        """Run the policy over one input document."""
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
