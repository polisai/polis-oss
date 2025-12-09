package authz

default allow = false

# Allow if the secret header matches
allow {
    # Check if the header exists and matches the secret
    # Note: Header keys are canonicalized in Go (e.g., "X-Corp-Auth")
    # Rego input structure depends on Polis implementation, usually input.request.headers
    input.request.headers["X-Corp-Auth"][0] == "secret-token-123"
}
