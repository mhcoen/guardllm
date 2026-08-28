# Support bundle

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

A single command that writes one file you can attach to a support ticket:

```bash
python -m vordur.support -o vordur-support.json
```

Or, against a running gateway, one request:

```bash
curl http://localhost:8080/support > vordur-support.json
curl http://localhost:8080/support/<session-id> > vordur-support.json
```

The second form includes that session's decision chain, which is the part that
explains a refusal several turns after the ingest that caused it.

## Why it exists

Vörður is deployed on your infrastructure, which means nobody outside it can
look at a failing system. When a call is refused and should not have been, the
whole evidence base is what you can be talked through producing. Without a
bundle that is a long exchange of "run this, paste the output". With one it is
an attachment.

## What it collects

| | |
| --- | --- |
| **Resolved policy** | Every setting as it is actually in force, plus `changed_from_default` naming the ones that are not stock, and `source` saying whether they came from a file, an explicit object, or the defaults |
| **Versions** | Vörður, Python, the platform, and the three core dependencies |
| **Optional extras** | Whether `yaml`, `wasmtime` and `cryptography` can actually be imported. A Rego policy that never ran and a YAML file that was never read both look like a policy that did not fire |
| **Decision chain** | The session's stages, tools and verdicts with the contamination and escalation flags as they stood at each step |
| **Environment** | Platform, Python build, whether this is a container, and which `VORDUR_*` variables are set |

The commonest ticket resolves to a setting somebody believes is in force and is
not, which is why the resolved policy comes first and why the bundle never
reports "no policy": defaults are a policy, and they are what refused the call.

## What it will not collect

A diagnostic that scoops up prompts, tool arguments or restored values turns a
support ticket into an unplanned data transfer, in the one product whose
subject is exactly that. Three rules hold, and all three are tested:

- **No message content, ever.** The chain names stages, tools and verdicts and
  holds no text. The reason strings come from the library and are written to
  exclude the values they describe.
- **Environment variables by name, never by value.** Whether
  `VORDUR_UPSTREAM` was set answers a real question. What it was set to can
  carry a key inside a query string.
- **The bundle is scanned before it is written**, by the same two passes that
  guard egress.

## When it refuses

If a credential reached a configuration value, the scan replaces it and the
bundle is written with `[redacted: credential]` in its place.

If a credential is recognized that no span can locate exactly, **nothing is
written at all**: `build_bundle` raises `UnsafeBundleError`, the command exits
2, and the gateway endpoint answers `409`. That is the designed answer rather
than a failure. Attribution says which characters can be replaced; recognition
says a credential is present. When recognition fires and attribution has
nothing to replace, redacting would produce a file that looks cleaned and is
not, so the bundle is declined. The remedy is to take the secret out of the
setting that carries it, not to work around the refusal.

## Format

```python
from vordur.support import build_bundle, render_bundle, write_bundle
```

`build_bundle` returns a dictionary, `render_bundle` serializes and scans it,
and `write_bundle` does both and writes the file. The format carries a
`version`, currently `BUNDLE_VERSION == 1`, for the same reason the policy file
does: a bundle arriving in a ticket may have been written by an older build
than the one reading it. Within a version, keys are only ever added.
