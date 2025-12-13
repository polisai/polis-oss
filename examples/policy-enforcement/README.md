# Policy Enforcement Example

This example demonstrates how to use the Open Policy Agent (OPA) integration in Polis to enforce access control policies.

## Prerequisites

- Built `polis.exe` binary.

## Configuration

The configuration defines a `policy` node that references a local `policy.rego` file.

### `policy.rego`
A simple policy that blocks requests containing the `X-Forbidden: true` header.

```rego
action := "block" if {
    input.attributes["http.headers"]["x-forbidden"][0] == "true"
}
```

## Running the Example

### Option 1: Run from Project Root
1.  Open a terminal in the project root.
2.  **Edit** `examples/policy-enforcement/config.yaml`:
    Change the policy bundle path to point to the correct subdirectory:
    ```yaml
    policyBundles:
      - id: "local-policy"
        # ...
        path: "examples/policy-enforcement" # UPDATED PATH
    ```
3.  Run Polis:
    ```powershell
    ./polis.exe --config examples/policy-enforcement/config.yaml
    ```

### Option 2: Use as Main Config
1.  Copy `config.yaml` and `policy.rego` to the root directory.
2.  Ensure `path: "."` in `config.yaml` is correct (it defaults to `.` which works if `policy.rego` is next to the binary).
3.  Run `./polis.exe`.

## Verification

1.  **Allowed Request:**
    ```powershell
    curl http://localhost:8091/allowed
    ```
    Should return 200 OK from upstream.
2.  **Blocked Request:**
    ```powershell
    curl -H "X-Forbidden: true" http://localhost:8091/blocked
    ```
    Should return 403 Forbidden.

## Next Steps
Try modifying `policy.rego` to block based on path or other headers!
