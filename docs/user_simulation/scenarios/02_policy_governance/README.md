# Scenario 2: Policy Enforcement (OPA)

**Goal:** Demonstrate governance capability by blocking requests based on business rules using Open Policy Agent (OPA).

In this scenario, we implement a "Internal Only" policy. Requests must include a specific header `X-Corp-Auth` to be allowed. If missing, the proxy rejects the request immediately.

## Configuration

We define a policy bundle and reference it in the `policy` node of the pipeline.

### `config.yaml`

```yaml
server:
  listenParams:
    - address: ":8090"
      protocol: "http"

policyBundles:
  - id: authz_policy
    version: 1
    artifacts:
      - type: rego
        path: "config/policy.rego"

pipelines:
  - id: policy-governance
    agentId: "*"
    protocol: http
    nodes:
      - id: start
        type: policy
        config:
          entrypoint: "authz/allow"
          bundleRef: "authz_policy"
        on:
          success: egress
          failure: deny

      - id: egress
        type: egress
        config:
          upstream_url: "http://localhost:8081"
          upstream_mode: static
        on:
          success: ""

      - id: deny
        type: terminal.deny
```

### `config/policy.rego`

```rego
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
    # Headers are injected into input.attributes["http.headers"]
    input.attributes["http.headers"]["X-Corp-Auth"][0] == "secret-token-123"
}
```

## Step-by-Step Walkthrough

### 1. Setup Files
Save `config.yaml` in the active directory and `policy.rego` to the `config/` subdirectory.

### 2. Run Polis
```powershell
./polis.exe
```

### 3. Test: Blocked Request
Send a request without the header:
```powershell
curl -v http://localhost:8090/v1/chat/completions
```
**Result:** `403 Forbidden`

### 4. Test: Allowed Request
Send a request with the correct header:
```powershell
curl -v -Headers @{ "X-Corp-Auth" = "secret-token-123" } http://localhost:8090/v1/chat/completions
```
**Result:** `200 OK` (Forwarded to upstream, may return 404 from mock server)
