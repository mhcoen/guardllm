# Rego policy

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

GuardLLM's own checks decide whether a call is safe. A Rego policy decides
whether it is *permitted*, using facts nothing else in a normal stack knows.

Needs the WASM runtime, which is not in the core install:
`pip install 'guardllm[rego]'`.

## The seam

OPA expresses who may do what. It has no way to learn that this session already
ingested untrusted web content, or that an exfiltration was blocked two turns
ago, because nothing in an ordinary stack computes those facts. GuardLLM
computes exactly those. So GuardLLM produces the facts and Rego decides on
them.

That makes the input document the real interface, more than the OPA wiring:

```json
{
  "version": 1,
  "user":  {"id": "alice", "roles": ["support"]},
  "tool":  "wire_funds",
  "args":  {"amount": 100},
  "guardllm": {
    "session_contaminated": true,
    "session_escalated":    false,
    "untrusted_sources":    ["web_search"],
    "injection_detected":   false,
    "canary_detected":      false,
    "binding_valid":        true
  }
}
```

Which lets a rule be written that cannot be written without it:

```rego
package guardllm

deny contains msg if {
    input.guardllm.session_contaminated
    input.tool == "wire_funds"
    msg := "contaminated session may not move money"
}
```

## Using it

```bash
opa build -t wasm -e guardllm/deny policy.rego -o bundle.tar.gz
```

```python
from guardllm.policy import RegoPolicy, build_input, decide

policy = RegoPolicy("bundle.tar.gz")
gate = guard.check_tool_call(tool, args, ctx)

verdict = decide(
    guard_allowed=gate.allowed,
    guard_reason=gate.reason,
    policy=policy,
    document=build_input(tool=tool, args=args, user={"roles": roles}, contaminated=...),
)
if not verdict.allowed:
    refuse(verdict.reason)
```

The entrypoint returns deny messages, so an empty result is an allow. A bundle
or a bare `policy.wasm` both load.

### What the bundle brings with it

A bundle's `data.json` is loaded and is what `data.` references resolve
against, so a rule can read reference data the bundle ships:

```rego
deny contains msg if {
    some blocked in data.config.blocked_tools
    input.tool == blocked
    msg := "tool is blocked by bundle data"
}
```

Build with `-b` so the directory layout becomes the data path
(`config/data.json` → `data.config`), the same as `opa eval -b`. A bare
`policy.wasm` has no data document, so `data.` references in one are undefined.

### Builtins are refused, not stubbed

OPA compiles most builtins into the WASM module. A few it does not, and expects
the host to supply them; `builtins()` names exactly those. **GuardLLM supplies
none, and refuses at load any policy that needs one**, naming it.

That refusal is the feature. The alternative is to answer such a call with
"undefined", and in Rego an undefined reference makes the enclosing rule body
undefined, so a `deny` rule that reaches one does not deny — it fails to fire,
and the call is allowed. A policy you tested with `opa eval` and watched deny
would load, evaluate, and permit, with nothing anywhere saying why.

`sprintf` is the one you are most likely to meet, because it is how a deny
message interpolates what it objected to. A literal message needs no builtin:

```rego
# refused at load: sprintf is not compiled into the module
msg := sprintf("tool %v is refused", [input.tool])

# fine
msg := "wire_funds is refused from a contaminated session"
```

The fixture policy in this repository requires no host builtin at all, and
neither does any rule written against `input.guardllm`.

## The stability contract

Your rules live in your repository and your deployment runs a release for
years, so this document is the longest-lived interface in the product. Within a
version, **fields are only ever added**. None is removed, renamed, or given a
new meaning; that requires an increment.

`input.version` travels inside the document so a rule can branch on it and keep
working across an increment rather than failing at the first changed field:

```rego
deny contains msg if {
    input.version >= 1
    input.tool == "export_all"
    input.guardllm.session_contaminated
    msg := "no bulk export from a contaminated session"
}
```

`guardllm.policy.POLICY_INPUT_VERSION` is the current value.

## Ordering

1. GuardLLM's own checks run first: binding, replay, validation, contamination,
   escalation.
2. **A GuardLLM deny is final and the policy is not consulted.** Not merely
   overruled: never asked. A policy able to overturn it would be a way to
   configure the enforcement off.
3. On a GuardLLM allow, Rego is consulted and may still deny.

Rego only ever narrows. This is the same strictest-wins rule the library
already applies when contamination and escalation both fire.

## One Rego footgun worth knowing

An undefined reference makes a whole rule body undefined, so a rule that reads
a field the input does not have does not deny, it simply fails to fire. An
access-control rule that fails to fire fails **open**.

`build_input` therefore emits a total document: `user.roles` is always present
as a list even when the host supplied no user. Measured against the fixture
policy, an absent `roles` let `delete_account` through, while `roles: []`
denied it correctly. Write your own input document by hand and that trap is
yours to avoid.

## Why in process

The library claims it runs entirely locally with no external API calls. An
HTTP hop to a policy server inside the policy engine would end that, so the
WASM module is evaluated in process, in microseconds. A deployment that already
runs central OPA attaches it at the gateway, which is where network-dependent
backends belong.

## Related

- [configuration.md](configuration.md): the policy file and `PolicyConfig`.
- [gateway.md](gateway.md): where a network policy backend would attach.
