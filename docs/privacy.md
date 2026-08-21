# Privacy Vault

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

Personal data that reaches a model provider has left your control, whatever the
provider's retention policy says. The privacy vault replaces it with an opaque
token before the prompt is sent, and puts the real value back only where your
policy says it may go.

The vault is entirely opt-in. Without `privacy=PrivacyConfig(...)` nothing in
this document runs and no other GuardLLM verdict changes.

## Enabling it

```python
from guardllm import Guard
from guardllm.security.types import (
    PrivacyConfig,
    PIIClass,
    Destination,
    REDACT,
)

guard = Guard(
    privacy=PrivacyConfig(
        restore_policy={
            "send_email": {
                "/to/*/address": frozenset({PIIClass.EMAIL}),
                "/body": REDACT,
            }
        },
        destination_policy={Destination.USER: frozenset({PIIClass.EMAIL})},
    )
)
```

Both policies are consulted per occurrence, and both deny by default. A field
path with no rule restores nothing; a destination with no rule receives
nothing. `Destination.USER` is not exempt: a channel does not establish
entitlement.

## What gets detected

Three tiers, and the first two infer nothing.

**Declared values.** The host seeds values it already holds from an
authenticated session, so precision is exact and there is no guessing:

```python
guard.seed_private_values({"Jane Ellsworth": PIIClass.PERSON})
```

**Pattern detection.** Deterministic rules for structured identifiers: email,
phone, SSN, credit card validated by Luhn, IBAN, routing number, passport,
driver's licence, national identity number, medical record number, and date of
birth.

**Your own detector.** Anything else, through the `Detector` protocol on
`PrivacyConfig.detectors`. Findings from every registered detector are unioned,
so registration order cannot remove a finding another detector produced. A
detector that reports inferred findings sets `inference_used` on the result,
which is how a reader tells a guess from a match.

`PrivacyConfig.classes` defaults to thirteen classes. Two of them, `PERSON` and
`ADDRESS`, no pattern can find. They are in the default set so that a host
which seeds them gets them tokenized without extra configuration, and they stay
undetected otherwise rather than being guessed at.

`CREDENTIAL` is not on that list and is not configurable. It is always denied
at the model boundary, `class_policy` cannot weaken it, and a config that tries
raises `ValueError` rather than being quietly ignored, so a host never keeps a
line it believes is in force.

## Tokens

`deidentify` returns the rewritten content and a finding per occurrence:

```python
result = guard.deidentify("Email jane@example.invalid about the Q3 review for Jane Ellsworth.")
# result.content:
#   Email [[GL:EMAIL:CSMRT5X32NSFT09]] about the Q3 review
#   for [[GL:PERSON:W5TW61AVNDJ7DYR]].
```

The payloads above are illustrative: they are issued per session, so your own
run prints different ones. The same value tokenizes to the same token within a
session, so a model can reason about "the same person" without ever seeing who.
The payload carries a Reed-Solomon check: a model that transcribes one symbol
wrong has its token corrected, and two wrong symbols are refused rather than
resolved to somebody else's value.

Send `result.content` to the model. Never send the original.

## Restoring into tool arguments

`prepare_tool_call` resolves tokens against `restore_policy`, per field:

```python
prepared = guard.prepare_tool_call(
    "send_email",
    {"to": [{"address": token}], "body": "see attached " + token},
    context,
)
# prepared.args:
#   {"to": [{"address": "jane@example.invalid"}],
#    "body": "see attached [redacted:email]"}
```

The same token restored in one field and redacted in another, because the
recipient field is where an address belongs and the body is not.

**Ordering matters, and it is not a style preference.** `prepare_tool_call`
must run before the host builds its `AuthorizationEvent` and `Binding`. Both
bind exact bytes: a scope authorized over a token fails against the restored
value, and the binding hash will not match. Dispatch `prepared.args`, and build
the authorization over those same arguments.

## Restoring into free text

`reidentify` resolves tokens against `destination_policy`, by where the text is
going:

```python
shown = guard.reidentify(result.content, destination=Destination.USER)
# shown.content:
#   Email jane@example.invalid about the Q3 review for [redacted:person].
```

The email came back because `Destination.USER` is entitled to `EMAIL`. The
person did not, because nothing entitled that destination to `PERSON`.
Destinations are `USER`, `TOOL`, `EXTERNAL`, and `LOG`.

`allowed_classes` narrows a single call further and can never widen past the
policy: the two sets are intersected, so a class the destination does not
permit stays withheld however the argument is written.

## Failing closed

Every one of these refuses the call rather than dispatching a partly resolved
one:

- a token that resolves to nothing, past `max_unresolvable` (default 3) in one
  call;
- a token whose framing the model damaged, unconditionally, because one
  surviving opener is a corrupted dispatch;
- two or more corrupted symbols in a payload, which the codec reports as
  uncorrectable rather than guessing;
- a vault at `vault_max_entries` (default 10,000), which fails rather than
  evicting, since eviction would break resolution for tokens still live in the
  transcript and turn a capacity problem into a correctness problem;
- an argument tree deeper than `max_arg_depth` (64) or larger than
  `max_arg_nodes` (100,000). A subtree the walk did not reach is a subtree
  whose tokens were never resolved, so truncating would dispatch a live
  placeholder.

Check `prepared.allowed` and `shown.allowed` before acting on either result.

## What this does not do

- **It does not find what no tier detects.** A name or a street address with no
  seeded value and no registered detector passes through in the clear. The
  vault reports `detection_incomplete` when it knows its own coverage was
  partial; it cannot report what nothing looked for.
- **It does not survive the process.** The vault is in memory and scoped to the
  session. A restart loses the mapping, and tokens issued before it will no
  longer resolve. They fail closed rather than resolving to the wrong value.
- **It does not protect a path that does not go through it.** Content the host
  sends to a provider without calling `deidentify` is not covered, in the same
  way the rest of GuardLLM governs the paths routed through it.

## Related

- [security.md](security.md): the surrounding defense layers.
- [configuration.md](configuration.md): policy controls and deployment guidance.
- [api.md](api.md): the stable `Guard` facade.
