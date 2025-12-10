# Scenario 5: Observability & Telemetry

**Goal:** Demonstrate how Polis provides visibility into AI traffic through logging and metrics.

In this scenario, we configure high-verbosity logging and OTLP export (if available) to see the inner workings of the proxy.

## Configuration

We rely on `config.yaml` for system-level settings and pipeline definitions.

### `config.yaml`

```yaml
server:
  listenParams:
    - address: ":8090"
      protocol: "http"

logging:
  level: debug # Maximum verbosity
  pretty: true # Readable logs for local testing

telemetry:
  otlp_endpoint: "localhost:4317" # If running a collector, or leave empty
  insecure: true

pipelines:
  # Basic passthrough pipeline for demonstration
  - id: observability-demo
    agentId: "*"
    protocol: http
    nodes:
      - id: start
        type: egress
        config:
          upstream_url: "http://localhost:8081"
          upstream_mode: static
        on:
          success: ""
```

## Step-by-Step Walkthrough

### 1. Configure
Save the configuration above to `config.yaml`.

### 2. Run Polis with Debug Logs
```powershell
./polis.exe --log-level debug
```

### 3. Generate Traffic
Send various requests (success, failure, malformed).
### 3. Generate Traffic
Send various requests (success, failure, malformed).
```powershell
curl -Method POST http://localhost:8090/v1/chat/completions
```

### 4. Inspect Logs
Look for:
- **Request ID:** Tracing ID for the request.
- **Pipeline Execution:** Step-by-step node execution logs (`Execute Node: policy`).
- **Decisions:** Why a request was allowed or denied.
- **Performance:** Latency of each node.

**Example Log:**
```json
{"level":"debug","node_id":"start","message":"Executing node: egress"}
{"level":"info","method":"POST","path":"/v1/chat/completions","status":200,"duration":150,"message":"Request processed"}
```
