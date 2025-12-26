# MCP Elicitation Policy
# This policy governs server-initiated requests (elicitation) from MCP tools
# to prevent prompt injection attacks and unauthorized sampling requests.

package mcp.elicitation

import rego.v1

default allow = false

# Trusted tools that are allowed to make sampling requests
trusted_tools := {"code-assistant", "documentation-helper", "filesystem-server"}

# Blocked prompt patterns that indicate potential injection attacks
blocked_patterns := [
    "ignore previous",
    "disregard instructions",
    "forget your instructions",
    "new instructions",
    "override",
    "system prompt"
]

# Allow sampling from trusted tools
allow if {
    input.method == "sampling/createMessage"
    input.tool_id in trusted_tools
    not contains_blocked_pattern
}

# Allow resource listing requests (generally safe)
allow if {
    input.method == "resources/list"
}

# Allow prompt listing requests (generally safe)
allow if {
    input.method == "prompts/list"
}

# Block prompts containing injection patterns
contains_blocked_pattern if {
    some msg in input.params.messages
    some pattern in blocked_patterns
    contains(lower(msg.content), pattern)
}

# Block requests with excessive token counts (potential resource abuse)
deny if {
    input.method == "sampling/createMessage"
    input.params.maxTokens > 10000
}

# Block requests from unknown tools
deny if {
    input.method == "sampling/createMessage"
    not input.tool_id in trusted_tools
}

# Main policy decision
decision := {
    "action": "block",
    "reason": "Elicitation blocked: potential prompt injection detected"
} if {
    contains_blocked_pattern
} else := {
    "action": "block",
    "reason": "Elicitation blocked: excessive token request"
} if {
    input.method == "sampling/createMessage"
    input.params.maxTokens > 10000
} else := {
    "action": "block",
    "reason": "Elicitation blocked: untrusted tool"
} if {
    deny
} else := {
    "action": "allow",
    "reason": "Elicitation allowed"
} if {
    allow
} else := {
    "action": "block",
    "reason": "Default deny for elicitation (fail-closed)"
}
