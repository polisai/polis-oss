package authz

default allow = {
    "action": "block",
    "reason": "Default deny"
}

# Allow if the secret header matches
allow := {
    "action": "allow",
    "reason": "Request authorized"
} if {
    # Check if the header exists and matches the secret
    # Note: Header keys are canonicalized in Go (e.g., "X-Corp-Auth")
    # Rego input structure depends on Polis implementation, usually input.request.headers
    input.attributes["http.headers"]["X-Corp-Auth"][0] == "secret-token-123"
}
