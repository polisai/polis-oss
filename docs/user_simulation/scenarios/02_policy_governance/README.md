# Scenario 2: Policy Enforcement (OPA)

**Goal:** Demonstrate governance capability by blocking requests based on business rules using Open Policy Agent (OPA).

In this scenario, we implement a "Internal Only" policy. Requests must include a specific header `X-Corp-Auth` to be allowed. If missing, the proxy rejects the request immediately.

## Configuration

We introduce a `policy` node before the egress.

### `pipeline.yaml`

```yaml
id: policy-governance
agentId: "*"
protocol: http
nodes:
  - id: start
    type: policy
    config:
      entrypoint: "authz/allow"
      policy_file: "config/policy.rego"
    on:
      success: egress
      failure: deny

  - id: egress
    type: egress
    config:
      upstream_url: "http://localhost:8081"
    on:
      success: ""

  - id: deny
    type: terminal.deny
```

### `policy.rego`

```rego
package authz

default allow = false

# Allow if the secret header matches
allow {
    input.request.headers["X-Corp-Auth"][0] == "secret-token-123"
}
```

## Step-by-Step Walkthrough

### 1. Setup Files
Save `pipeline.yaml` and `policy.rego` to your config directory.

### 2. Run Polis
```powershell
./proxy.exe --pipeline-file config/pipeline.yaml --data-listen :8090
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
curl -v -H "X-Corp-Auth: secret-token-123" http://localhost:8090/v1/chat/completions
```
**Result:** `200 OK` (Forwarded to upstream)
