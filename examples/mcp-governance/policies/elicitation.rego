# MCP Elicitation Policy for Bidirectional Inspection
# This policy governs server-initiated requests (elicitation) from MCP tools
# to prevent prompt injection attacks and unauthorized sampling requests.

package mcp.elicitation

import rego.v1

default allow = false

# Trusted tools that are allowed to make sampling requests
trusted_tools := {"code-assistant", "documentation-helper", "filesystem-server", "demo-tool"}

# Blocked prompt patterns that indicate potential injection attacks
blocked_patterns := [
    "ignore previous",
    "disregard instructions",
    "forget your instructions",
    "new instructions",
    "override system",
    "system prompt",
    "jailbreak"
]

# Allow sampling from trusted tools without blocked patterns
allow if {
    input.method == "sampling/createMessage"
    input.tool_id in trusted_tools
    not contains_blocked_pattern
    not excessive_tokens
}

# Allow resource listing requests (generally safe)
allow if {
    input.method == "resources/list"
}

# Allow prompt listing requests (generally safe)
allow if {
    input.method == "prompts/list"
}

# Allow tool listing requests
allow if {
    input.method == "tools/list"
}

# Check for blocked patterns in message content
contains_blocked_pattern if {
    some msg in input.params.messages
    some pattern in blocked_patterns
    contains(lower(msg.content), pattern)
}

# Check for excessive token requests (potential resource abuse)
excessive_tokens if {
    input.params.maxTokens > 10000
}

# Explicit deny rules
deny if {
    input.method == "sampling/createMessage"
    contains_blocked_pattern
}

deny if {
    input.method == "sampling/createMessage"
    excessive_tokens
}

deny if {
    input.method == "sampling/createMessage"
    not input.tool_id in trusted_tools
}

# Main policy decision with detailed reasons
decision := {
    "action": "block",
    "reason": sprintf("Elicitation blocked: potential prompt injection detected in message content", [])
} if {
    contains_blocked_pattern
} else := {
    "action": "block",
    "reason": sprintf("Elicitation blocked: excessive token request (%d > 10000)", [input.params.maxTokens])
} if {
    excessive_tokens
} else := {
    "action": "block",
    "reason": sprintf("Elicitation blocked: untrusted tool '%s'", [input.tool_id])
} if {
    input.method == "sampling/createMessage"
    not input.tool_id in trusted_tools
} else := {
    "action": "allow",
    "reason": "Elicitation allowed"
} if {
    allow
} else := {
    "action": "block",
    "reason": "Default deny for elicitation (fail-closed)"
}
