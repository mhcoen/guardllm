# Security Policy

GuardLLM is a security library. We take vulnerability reports seriously and aim to respond quickly.

## Supported Versions

Only the most recent minor release line of GuardLLM receives security fixes.

| Version | Supported |
|--------:|:---------:|
| 1.2.x   | Yes       |
| < 1.2   | No        |

The version is declared in `pyproject.toml`. Older versions on PyPI will not be patched; users on older releases should upgrade.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security problems.

Send a private report to **mhcoen@gmail.com** with:

- A description of the vulnerability and the affected component (sanitizer, policy engine, request binding, outbound DLP, etc.)
- A minimal reproduction (input that triggers the issue, version of GuardLLM, Python version)
- Your assessment of impact (information disclosure, authorization bypass, prompt-injection bypass, panic/DoS, etc.)
- Whether you intend to disclose publicly, and on what timeline

You should receive an acknowledgement within **3 business days**. We aim to triage within **7 days** and produce a patch release for confirmed high-severity issues within **30 days**, sooner for actively exploited problems.

If you do not get an acknowledgement within a week, please follow up: mail can get lost.

## Coordinated Disclosure

We follow a 90-day coordinated disclosure window by default. We are happy to negotiate a different timeline for complex fixes or downstream coordination. We will credit reporters in the CHANGELOG unless you ask to remain anonymous.

## In Scope

The following are in scope for vulnerability reports against GuardLLM itself:

- **Sanitizer bypass**: input that escapes `<untrusted_content>` isolation, smuggles instructions past HTML/CSS/whitespace normalization, or evades the prompt-injection detector with no obfuscation cost
- **Authorization bypass**: tool calls that pass `Guard.authorize` / `Guard.check_tool_call` despite policy denying them
- **Request-binding bypass**: tampered parameters that verify against an unrelated binding, or replays that succeed past the anti-replay window
- **Outbound DLP bypass**: untrusted-provenance content copied into outbound payloads without detection
- **Error-channel disclosure**: `Guard.sanitize_exception` leaking internal paths, secrets, or stack frames
- **Canary handling**: canary tokens accepted as untainted, or canary-bearing content silently passing outbound checks
- **Crashes or DoS** in any pipeline path on small, malformed inputs (memory exhaustion, regex catastrophic backtracking, infinite loops)
- **Supply-chain issues** in this repository's dependencies or build pipeline

## Out of Scope

GuardLLM is one layer of defense; it does not replace other controls. The following are not GuardLLM vulnerabilities:

- LLM behavior outside of GuardLLM's pipeline (e.g. the model ignoring `<untrusted_content>` framing when the application strips it before sending to the model)
- Application-layer policy choices: e.g. an empty allowlist is intentionally deny-by-default, and a misconfigured allowlist that admits a destructive tool is the operator's responsibility
- Attacks requiring a privileged local attacker (e.g. someone who can write the application's policy config)
- Performance reports that are not crash-class (general latency regressions belong in regular issues)
- Reports limited to benchmark numbers in `benchmarks/results.md` (those are reproducibility/methodology discussions, not vulnerabilities)

## Test Datasets

The benchmark datasets under `benchmarks/` are part of GuardLLM's evaluation methodology. Changes to those datasets are governed by `benchmarks/methodology.md` and reviewed separately from security fixes. A flaw in a *dataset case* is not a GuardLLM vulnerability; a flaw in *how the pipeline handles a class of input* is.

## Hardening Posture

GuardLLM ships with safe-by-default settings:

- Empty allowlist denies (does not allow-all)
- Untrusted-source destructive tool calls require an explicit `AuthorizationEvent`
- Inbound content is wrapped with source and trust metadata even when no warnings fire
- Outbound checks fail closed when provenance is unknown

If you find a default that does not match this posture, that itself is a reportable issue.
