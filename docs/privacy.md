# Privacy Vault

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

<!-- toc:start -->
<details markdown="1">
<summary>On this page</summary>

- [Enabling it](#enabling-it)
- [What gets detected](#what-gets-detected)
- [Tokens](#tokens)
- [Restoring into tool arguments](#restoring-into-tool-arguments)
- [Restoring into free text](#restoring-into-free-text)
- [Failing closed](#failing-closed)
- [Alphabet runs, and the one thing you may have to choose](#alphabet-runs-and-the-one-thing-you-may-have-to-choose)
- [Persisting the vault](#persisting-the-vault)
- [What this does not do](#what-this-does-not-do)
- [Related](#related)

</details>
<!-- toc:end -->

> Illustrated: [04 What the Provider Sees Instead](mechanisms/04-privacy-vault.html) shows
> substitution at the model boundary and the two deny-by-default gates that decide
> whether a real value comes back.



Personal data that reaches a model provider has left your control, whatever the
provider's retention policy says. The privacy vault replaces it with an opaque
token before the prompt is sent, and puts the real value back only where your
policy says it may go.

The vault is entirely opt-in. Without `privacy=PrivacyConfig(...)` nothing in
this document runs and no other Vörður verdict changes.

## Enabling it

```python
from vordur import Guard
from vordur.security.types import (
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

## Alphabet runs, and the one thing you may have to choose

`234567ABCDEFGHIJKLMNOPQRSTUVWXYZ` is the RFC 4648 Base32 alphabet. It is also
a perfectly ordinary TOTP shared secret, and people paste it into config files
as one. Nothing that looks at the value can tell those apart, so what happens
to a run that is one stretch of an alphabet is a policy setting:

```python
PrivacyConfig(ambiguous_alphabet_policy="redact")  # the default
```

- **`redact`** replaces the line carrying the run, exactly as this path
  already does for credential material whose extent it could not recover.
  Nothing crosses in plaintext and the document is not withheld.
- **`deny`** refuses the content instead, for a deployment that would rather
  see the refusal than a rewritten line.
- **`allow`** keeps the run, for a corpus full of encoding tables. This is the
  only setting under which an alphabet-shaped secret can reach a provider, so
  it is a decision rather than a default.

Egress is not configurable here: `check_outbound` reports the run whatever this
is set to, so a value of this shape never leaves quietly.

## Persisting the vault

The vault is session state by default and nothing reaches disk on its own.
A deployment that needs a token to keep meaning the same person across a
restart attaches a store:

```python
from vordur import Guard
from vordur.security.types import PrivacyConfig
from vordur.security.vault_store import EncryptedFileVaultStore

# Reads the key from VORDUR_VAULT_KEY, and refuses if it is unset.
store = EncryptedFileVaultStore.from_env("/var/lib/vordur/vault.bin")

guard = Guard(privacy=PrivacyConfig(), vault_store=store)
guard.deidentify("...")
guard.persist_vault()  # end of turn, checkpoint, or shutdown
```

Needs the `vault` extra: `pip install 'vordur[vault]'`.

**What this buys is continuity, not protection.** Nothing crosses to the
provider that would not have crossed before. Without a store a restart loses
co-reference, so the same person is issued a second token and tokens from
before the restart stop resolving; they fail closed rather than resolving to
the wrong person either way.

**A persisted vault is a different security object.** In memory it holds
plaintext the caller already had. On disk it is a re-identification database:
one file mapping every token a provider has seen back to the person behind it,
outliving the request, the process, and usually the incident. So the store that
ships encrypts under AES-256-GCM, and there is no unencrypted alternative
behind it: without the extra it refuses to write rather than falling back to
plaintext.

**The key is yours and the library will not invent one.** `generate_key()`
returns a fresh 256-bit key as base64 for a secret manager; nothing in
Vörður writes a key anywhere. `EncryptedFileVaultStore.from_env(path)` reads
one from `VORDUR_VAULT_KEY` and refuses when it is unset, rather than
generating one and coming up healthy and empty against a file it can no longer
read. Lose the key and you lose the file, which is the intended property.

Three behaviours worth knowing before you rely on it:

- **A file it cannot authenticate raises**, and is never read as an empty
  vault. Starting empty after a wrong key looks like a fresh session and is
  not one: every live token would silently stop resolving.
- **`clear()` destroys the stored snapshot too.** A clear invalidates every
  token in the transcript, and leaving the file behind would let the next
  process resurrect them.
- **The file's absence is not authenticated.** Deleting it is
  indistinguishable from a first run. That is a denial of continuity rather
  than a disclosure, and the remedy is filesystem permissions.

`VaultStore` is a three-method protocol (`load`, `save`, `purge`), so a
deployment that wants a database, a KMS-fronted blob, or replication
implements it without touching the vault. Key rotation, escrow, and deletion
evidence sit above the interface rather than inside it.

## What this does not do

- **It does not find what no tier detects.** A name or a street address with no
  seeded value and no registered detector passes through in the clear. Note
  what carries that news, because `detection_incomplete` does not: that flag
  means a detector which ran could not finish, so a class with no detector
  behind it sets nothing and the result still reads `reason='clean'`. What you
  get instead is a warning on the result naming the classes nothing looked for:

  ```text
  No detector for configured class(es): address, person. Nothing scanned for
  them, so a clean result here is not evidence that no value of those classes
  was present.
  ```

  It is emitted whenever a configured class has no structural pattern, no
  seeded value and no registered detector, which at the default configuration
  means `PERSON` and `ADDRESS`. Seeding a value of that class, registering a
  detector for it, or narrowing `PrivacyConfig.classes` all clear it.
- **It does not survive the process unless you ask it to.** The vault is in
  memory and scoped to the session by default. A restart loses the mapping,
  and tokens issued before it will no longer resolve; they fail closed rather
  than resolving to the wrong value. See "Persisting the vault" above for the
  opt-in, and note that it changes continuity rather than what the provider
  sees.
- **It does not protect a path that does not go through it.** Content the host
  sends to a provider without calling `deidentify` is not covered, in the same
  way the rest of Vörður governs the paths routed through it.
- **It may replace a whole line.** When credential material survives
  substitution, the vault replaces the line carrying it rather than the
  document, and says so in `warnings`.

## Related

- [security.md](security.md): the surrounding defense layers.
- [configuration.md](configuration.md): policy controls and deployment guidance.
- [api.md](api.md): the stable `Guard` facade.
