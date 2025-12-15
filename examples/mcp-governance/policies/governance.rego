package mcp.authz

import rego.v1

default allow = false

# Allow all requests by default if no specific block rule matches
# (Fail-open logic for demo, or we can use allowlist)
# Let's use an allowlist approach for strict governance demo.

# Public entrypoint
allow if {
    # Is it a read operation?
    is_read_operation
    # Is it on an allowed path? (mock check)
    is_safe_path
}

# Allow specific useful read-only tools
allow if {
    input.attributes.method == "tools/list"
}
allow if {
    input.attributes.method == "tools/call"
    input.attributes.params.name == "git_status"
}
allow if {
    input.attributes.method == "tools/call"
    input.attributes.params.name == "git_log"
}

# Allow MCP Initialization
allow if {
    input.attributes.method == "initialize"
}
allow if {
    input.attributes.method == "notifications/initialized"
}

# Block Write Operations explicitly to generate "Deny" outcomes
deny if {
    input.attributes.method == "tools/call"
    is_write_tool(input.attributes.params.name)
}

# Helper: Identify Write Tools
is_write_tool("filesystem_write_file")
is_write_tool("git_commit")
is_write_tool("git_push")

# Helper: Identify Read Operations
is_read_operation if {
    input.attributes.method == "tools/call"
    input.attributes.params.name == "filesystem_read_file"
}
is_read_operation if {
    input.attributes.method == "tools/call"
    input.attributes.params.name == "filesystem_list_directory"
}

# Helper: Path Safety (Mock)
is_safe_path if {
    # If parameters have a path, check it.
    # Note: real tools might have different argument structures.
    # We assume 'path' or 'repo_path' argument.
    path := object.get(input.attributes.params.arguments, "path", "")
    startswith(path, "/tmp/sandbox")
}
is_safe_path if {
    # If no path arg, maybe safe?
    not input.attributes.params.arguments.path
}

# Main Policy Decision
decision := {
    "action": "block",
    "reason": "Write operation blocked by policy"
} if {
    deny
} else := {
    "action": "allow",
    "reason": "Allowed by policy"
} if {
    allow
} else := {
    "action": "block",
    "reason": "Default deny"
}
