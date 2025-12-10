# Scenario 1: Basic Proxy & Pass-through

**Goal:** Verify basic system connectivity, transparency, and header preservation.

In this foundational scenario, we will configure Polis to act as a simple transparent proxy. This proves that the network plumbing is working, the binary is executable, and traffic can flow from Client -> Proxy -> Upstream.

## Pre-requisites
- Polis OSS binary built (`polis.exe`).
- A running upstream service (e.g., `local-llm-demo` or a simple `httpbin`).
- `curl` or PowerShell for sending requests.

## Configuration

We use a minimal configuration that defines a pipeline to forward requests.

### `config.yaml`

```yaml
server:
  listenParams:
    - address: ":8090"
      protocol: "http"

pipelines:
  - id: basic-passthrough
    agentId: "*"
    protocol: http
    nodes:
      - id: start
        type: egress
        config:
          upstream_url: "http://localhost:8081" # Change to your upstream
          upstream_mode: static
        on:
          success: ""
```

## Step-by-Step Walkthrough

### 1. Start the Upstream (Mock)
If you don't have a real LLM running, start a simple listener:
```powershell
# In a separate terminal
python -m http.server 8081
```

### 2. Configure Polis
Save the configuration above to `config.yaml`.

### 3. Run Polis
```powershell
./polis.exe
```

### 4. Send a Request
```powershell
curl -v http://localhost:8090/v1/chat/completions
```

### 5. Verification
- **Success:** You receive a response from the upstream (or 404/200 from python server).
- **Check:** `Proxy-Agent` or custom headers are preserved (if configured).
- **Logs:** Polis console shows "Request processed" with status 200/404.
