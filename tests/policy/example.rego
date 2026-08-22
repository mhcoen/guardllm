# Fixture policy for the Rego tests, and the shape the docs describe.
#
# Committed as source rather than as a compiled .wasm: a binary blob in a
# security repository is something no reviewer can read, and the tests compile
# this with `opa build -t wasm` at run time instead.
#
# Every rule below reads a fact from `input.guardllm` that no other policy
# engine in a normal stack can know. That is the whole argument for the seam:
# OPA expresses who may do what, and GuardLLM supplies what happened earlier in
# this session.
package guardllm

# A session that has ingested untrusted content may not move money. This is the
# rule a customer cannot write today without GuardLLM: OPA has no way to learn
# that three turns ago a web page came back with an instruction in it.
deny contains msg if {
    input.guardllm.session_contaminated
    input.tool == "wire_funds"
    msg := "contaminated session may not move money"
}

# Once egress has blocked an exfiltration, stop sending anything outward.
deny contains msg if {
    input.guardllm.session_escalated
    startswith(input.tool, "send_")
    msg := "session escalated after an egress block"
}

# Ordinary access control, expressed against host identity rather than any
# GuardLLM fact. Included so the tests cover the case where the two kinds of
# rule sit side by side.
deny contains msg if {
    input.tool == "delete_account"
    not "admin" in input.user.roles
    msg := "delete_account requires the admin role"
}
