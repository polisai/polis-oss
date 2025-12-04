package policy

# policy_decision returns allow/redact/block outcomes based on identity and findings.
block_request if {
    lower(input.identity.subject) == "blocked-user"
}

redact_request if {
    not block_request
    dlp := object.get(input.findings, "dlp", {})
    object.get(dlp, "redactions_applied", false) == true
}

# Decision action with priority: block > redact > allow
default decision_action := "allow"

decision_action := "block" if {
    block_request
}

decision_action := "redact" if {
    redact_request
}

decision_reason := reason_map[decision_action]

reason_map := {
    "allow": "allow",
    "block": "subject_denied",
    "redact": "dlp_redaction",
}

policy_decision := {
    "action": decision_action,
    "reason": decision_reason,
    "metadata": {
        "policy.reason": decision_reason
    }
}

# decision entrypoint used by policy engine default evaluation.
decision := policy_decision

# request entrypoint used by policy enforcer for outbound traffic.
request := policy_decision

# response entrypoint used by policy enforcer for inbound traffic.
response := policy_decision
