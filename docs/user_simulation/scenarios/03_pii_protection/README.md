# Scenario 3: PII Protection (DLP)

**Goal:** Verify proper redaction of sensitive information (PII) such as email addresses and phone numbers.

In this scenario, we use the Data Loss Prevention (DLP) node. The proxy inspects the request body (or response) and redacts patterns matching configured regular expressions.

## Configuration

We use a standard config with a `dlp` node.

### `config.yaml`

```yaml
server:
  listenParams:
    - address: ":8090"
      protocol: "http"

pipelines:
  - id: pii-protection
    agentId: "*"
    protocol: http
    nodes:
      - id: start
        type: dlp
        config:
          rules_file: "./docs/user_simulation/scenarios/03_pii_protection/dlp_rules.yaml" # Ensure this path is correct relative to execution dir
        on:
          success: egress
          failure: deny # If inspection fails critically, usually success is followed even if redacted

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

### `dlp_rules.yaml`

```yaml
rules:
  - id: email-redaction
    name: "Redact Emails"
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    action: redact
    replacement: "[EMAIL_REDACTED]"

  - id: phone-redaction
    name: "Redact US Phone Numbers"
    pattern: '\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
    action: redact
    replacement: "[PHONE_REDACTED]"
```

## Step-by-Step Walkthrough

### 1. Setup Files
Save `config.yaml` to the root `polis-oss` directory. Ensure `dlp_rules.yaml` exists at the path specified in the config.

### 2. Start Upstream
Ensure your mock upstream is running (e.g., `python -m http.server 8081`).

### 3. Run Polis
```powershell
./polis.exe
```

### 4. Send PII Request
```powershell
curl -Method POST http://localhost:8090/v1/chat/completions `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body '{"messages": [{"role": "user", "content": "My email is john.doe@example.com and phone is 555-123-4567"}]}'
```

### 5. Verification
- **Expected Behavior:** The upstream server should receive the request with the PII replaced.
- **Check Upstream Logs:** Look for `My email is [EMAIL_REDACTED] and phone is [PHONE_REDACTED]`.
