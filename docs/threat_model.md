# GuardLLM Threat Model

This document states the threats GuardLLM is designed to mitigate, the assumptions it makes about its environment, and the threats it explicitly does not mitigate. It complements `docs/security.md` (architecture) and `SECURITY.md` (reporting policy).

The aim is to be precise about *what GuardLLM is responsible for* so application authors can make informed decisions about what additional controls they still need.

## System Model

A GuardLLM-using application is, abstractly:

```
   external sources                    LLM                 tools / sinks
   (web, email, MCP,        +------------------------+
    documents, calendar,    |                        |
    KG extraction)  ───────►|       application      |───────► (model output,
                            |                        |          tool calls,
                            |   +----------------+   |          outbound payloads)
                            |   |   GuardLLM     |   |
                            |   +----------------+   |
                            +------------------------+
```

GuardLLM sits on the data path between untrusted external sources and trusted decision points (the model, tool invocation, outbound destinations). It carries a single security context (`SecurityContext`) end-to-end so that decisions downstream of ingress can refer back to source trust, provenance, and detection results.

## Trust Boundaries

GuardLLM enforces a label discipline across four boundaries:

1. **Ingress** – content enters from a typed source (`Guard.context_web`, `Guard.context_mcp_server`, etc.). The source determines initial `source_trust`. Content is sanitized, normalized, and wrapped in `<untrusted_content>` framing.
2. **Authorization** – a tool call is admitted only when a structured `AuthorizationEvent` matches policy. Untrusted-content-derived prompts cannot synthesize their own `AuthorizationEvent`.
3. **Integrity** – tool-call parameters are bound via `Guard.bind_request`. Modifications between binding and invocation invalidate the binding.
4. **Egress** – outbound payloads are checked against provenance and DLP policy. Content tagged untrusted at ingress is detected when it tries to reappear in an outbound message.

## Adversaries

GuardLLM considers three adversary classes:

### A1. Untrusted Content Author

Can write arbitrary bytes in any field of an external resource the application reads: a web page, an email body, a calendar invite, a document, an MCP-server tool response.

**Goals**: smuggle instructions to the LLM, exfiltrate prior conversation context, induce destructive tool calls, escape `<untrusted_content>` framing, evade detector heuristics.

**Capabilities**: full control over the byte stream they author; no privileged position in the application or network.

### A2. Compromised Tool / MCP Server

Can return arbitrary tool output, including outputs crafted to look like authorization grants, system messages, or trusted instructions.

**Goals**: as A1, plus replay attacks on previously-authorized actions, parameter tampering after binding, abuse of one tool's output as input to a more destructive tool.

**Capabilities**: full control over response bodies; cannot forge an `AuthorizationEvent` from the application's own authorization adapter.

### A3. Network-Position Attacker

Intercepts traffic between the application and external services.

**Goals**: replay stale tool-call payloads, swap parameters on in-flight calls.

**Capabilities**: read and rewrite traffic in flight, but cannot break TLS or extract the binding secret.

The application itself, the policy configuration, and the principal identity are **trusted**. GuardLLM does not defend against an attacker who can edit `PolicyConfig`, mint principal sessions, or run code in the application process.

## Threats In Scope (T-IN)

| ID    | Threat                                                                                   | Mitigation                                                |
|-------|------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| T-IN1 | Direct prompt injection in untrusted content                                             | Sanitizer + isolation + heuristic detector                |
| T-IN2 | Indirect injection via hidden HTML/CSS / zero-width chars / homoglyphs                   | Normalization, hidden-element removal, TR39 confusables   |
| T-IN3 | Smuggling instructions via encoding (hex / base64 fragments)                             | Hex decode-then-scan in sanitizer                         |
| T-IN4 | Untrusted content synthesizing an `AuthorizationEvent`                                   | Authorization events come only from app adapters, never from content; policy engine rejects events with no matching adapter source |
| T-IN5 | Destructive tool call from untrusted-trust principal                                     | Policy engine + `DESTRUCTIVE_TOOLS` allowlist requires explicit authorization |
| T-IN6 | Parameter tampering between authorization and execution                                  | `Guard.bind_request` + verification at call site          |
| T-IN7 | Replay of stale authorization or binding                                                 | Anti-replay window in binding verification; policy-engine message binding (`PolicyConfig.require_message_binding`) denies an authorization whose message hash does not match the current message |
| T-IN8 | Untrusted-provenance content copied into outbound payload                                | `Guard.check_outbound` provenance + DLP                   |
| T-IN9 | Exfiltration via canary token                                                            | Canary detection at ingress and outbound                  |
| T-IN10| Internal detail leakage via exception messages                                           | `Guard.sanitize_exception`                                |
| T-IN11| Detector evasion via low-cost obfuscation                                                | Multi-signal detector (composition penalty), normalization-before-detection |
| T-IN12| Empty allowlist treated as allow-all                                                     | Empty allowlist denies by default                         |

## Threats Out of Scope (T-OUT)

| ID     | Threat                                                                              | Why out of scope                                                                 |
|--------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| T-OUT1 | Model not honoring `<untrusted_content>` framing                                     | Application layer choice; GuardLLM provides the framing, the application chooses to use it. Use stronger models or system-prompt discipline. |
| T-OUT2 | Compromise of the application process                                                | A1/A2/A3 do not include local code execution. If the attacker can edit policy, the game is over. |
| T-OUT3 | Misconfigured policy admitting a destructive tool to untrusted principals            | Operator responsibility; production checklist covers this.                       |
| T-OUT4 | Attacks requiring the network attacker to break TLS                                  | TLS is a layer below GuardLLM.                                                   |
| T-OUT5 | Side-channel timing attacks on the detector                                          | Heuristics are intentionally fast; we do not claim timing-side-channel resistance. |
| T-OUT6 | Adversarial perturbation of LLM weights (model supply-chain)                         | Layer above GuardLLM; use trusted model sources.                                 |
| T-OUT7 | Vulnerabilities in `beautifulsoup4`, `confusables`, or other runtime deps           | Tracked via Dependabot and pip-audit; CVEs fixed by upgrading, not patched in GuardLLM. |
| T-OUT8 | Detection of human-targeted social engineering not aimed at the model                | Not a content-injection threat.                                                  |

## Assumptions

GuardLLM relies on these assumptions. If any of them is violated, the corresponding mitigations may not hold.

| ID     | Assumption                                                                          | Failure mode if violated                                       |
|--------|--------------------------------------------------------------------------------------|----------------------------------------------------------------|
| A-AS1  | The application calls `process_inbound` before sending content to the model         | Sanitizer / detector never run; no protection                  |
| A-AS2  | The application calls `authorize` / `check_tool_call` before tool invocation        | Policy gate is bypassed                                        |
| A-AS3  | Source identifiers passed to `context_*` are honest about the actual source         | Trust labels are wrong; downstream decisions misroute          |
| A-AS4  | Policy config is authored and stored in a trusted location                          | Attacker who controls policy controls authorization            |
| A-AS5  | The binding secret in `bind_request` is not exposed                                 | Attacker can forge bindings                                    |
| A-AS6  | Time clocks are roughly synchronized for anti-replay windows                        | Anti-replay rejects legitimate calls or admits stale ones      |
| A-AS7  | `<untrusted_content>` framing is preserved through to the model                     | Without framing the model sees untrusted text as system-level  |

## Defense-in-Depth Reminder

GuardLLM materially reduces risk in T-IN1 through T-IN12. It does not eliminate it. Applications should also have:

- Strong authentication and authorization for principals
- Network and runtime isolation between tools
- Secret management with rotation
- Monitoring and incident response that consumes GuardLLM's audit events
- Rate limiting at the request layer (not only inside GuardLLM)

The benchmark numbers in `benchmarks/results.md` are GuardLLM's measured effectiveness on the documented suites; they are not a guarantee against novel attack classes that emerge after release.

## Updating This Document

When you add a new mitigation, add a row to T-IN. When you remove or change an assumption, update A-AS. When you adopt a new external dependency that introduces a new trust boundary, update the system model diagram.
