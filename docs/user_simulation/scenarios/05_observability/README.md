# Scenario 5: Observability & Telemetry

**Goal:** Demonstrate how Polis provides visibility into AI traffic through logging and metrics.

In this scenario, we configure high-verbosity logging and OTLP export (if available) to see the inner workings of the proxy.

## Configuration

We rely on `config.yaml` for system-level settings.

### `config.yaml`

```yaml
logging:
  level: debug # Maximum verbosity
  pretty: true # Readable logs for local testing

telemetry:
  otlp_endpoint: "localhost:4317" # If running a collector, or leave empty
  insecure: true
```

### `pipeline.yaml` (Any basic flow)
Reuse Scenario 1's pipeline.

## Step-by-Step Walkthrough

### 1. Configure
Save the logging config to `config/config.yaml`.

### 2. Run Polis with Debug Logs
```powershell
./proxy.exe --log-level debug --data-listen :8090
```

### 3. Generate Traffic
Send various requests (success, failure, malformed).
```powershell
curl http://localhost:8090/v1/chat/completions
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
