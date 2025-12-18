# MCP Governance Examples

This directory contains examples for verifying Polis OSS governance features (Access Control, Operation Gating, DLP, Bidirectional Inspection) with Model Context Protocol (MCP).

## Prerequisites
- Python 3.10+
- Go 1.21+ (to build Polis)
- Node.js 18+ (for MCP Bridge examples)

## Setup

1. **Install Python Dependencies:**
   ```bash
   pip install -r examples/mcp-governance/client/requirements.txt
   ```

2. **Build Polis:**
   ```bash
   go build -o polis.exe ./cmd/polis-core
   go build -o polis-bridge.exe ./cmd/polis-bridge
   ```

## Example 1: Basic MCP Governance

### 1. Start the Mock MCP Server
This server simulates a filesystem, git repo, and search engine. It runs on port `8000`.
```bash
python examples/mcp-governance/client/server.py
```

### 2. Start Polis Gateway
Run Polis using the provided configuration. It listens on `:8085` and proxies to `:8000`.
```bash
./polis.exe --config examples/mcp-governance/config.yaml
```

### 3. Run Verification Script
This script sends JSON-RPC requests to Polis (`:8085`), which proxies them to the Mock Server (`:8000`) while enforcing policies.

```bash
python examples/mcp-governance/client/verify_governance.py
```

### Expected Results
1. **Filesystem Read**: `Success` (Allowed by policy).
2. **Filesystem Write**: `Blocked` (Policy Violation: Write operation blocked).
3. **Search**: `Success` but content should contain `[REDACTED_EMAIL]` instead of real email.

---

## Example 2: Bidirectional Inspection

This example demonstrates how Polis inspects both client→server requests AND server→client responses (SSE streams) to prevent malicious tools from attacking agents.

### Architecture

```
Agent → Polis Gateway → MCP Bridge → MCP Tool
         ↓                            ↓
    [authz policy]              [elicitation policy]
    (client→server)              (server→client)
```

### 1. Start the MCP Bridge with a Tool

```bash
./polis-bridge.exe --port 8090 -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox
```

### 2. Start Polis Gateway with Bidirectional Config

```bash
./polis.exe --config examples/mcp-governance/config-bidirectional.yaml
```

### 3. Test Bidirectional Inspection

**Client → Server (Request Governance):**
```bash
# This request will be evaluated against mcp/authz policy
curl -X POST http://localhost:8085/message \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: demo-agent-001" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"filesystem_read_file","arguments":{"path":"/tmp/sandbox/test.txt"}},"id":1}'
```

**Server → Client (Elicitation Governance):**
When the MCP tool sends a `sampling/createMessage` request back to the agent, Polis will:
- Parse the SSE event
- Detect it's a server-initiated request
- Evaluate against `mcp/elicitation` policy
- Block if it contains prompt injection patterns

### Elicitation Policy

The `policies/elicitation.rego` policy:
- Allows sampling only from trusted tools
- Blocks prompts containing injection patterns like "ignore previous instructions"
- Limits maximum token requests to prevent resource abuse
- Uses fail-closed behavior by default

---

## Example 3: Session Reconnection

This example demonstrates session persistence and reconnection support for MCP connections.

### How It Works

1. **Session Creation**: When a client connects to the SSE endpoint, Polis assigns a unique session ID
2. **Event Buffering**: Events are buffered for a configurable duration (default 60s)
3. **Reconnection**: If disconnected, clients can reconnect using `Last-Event-ID` header
4. **Event Replay**: Polis replays buffered events from the last acknowledged position

### Testing Reconnection

**1. Initial Connection:**
```bash
# Connect and note the session ID from the response
curl -N http://localhost:8085/sse \
  -H "X-Agent-ID: session-agent-001"
```

**2. Simulate Disconnection:**
Press Ctrl+C to disconnect.

**3. Reconnect with Last-Event-ID:**
```bash
# Replace evt-123 with the last event ID you received
curl -N http://localhost:8085/sse \
  -H "X-Agent-ID: session-agent-001" \
  -H "Last-Event-ID: evt-123"
```

**4. Verify Event Replay:**
You should receive all events that were buffered since your last acknowledged event.

### Session Configuration

In `config-bidirectional.yaml`:
```yaml
session.manager:
  buffer_size: 1000        # Events to buffer per session
  buffer_duration: "60s"   # How long to keep buffered events
  session_timeout: "300s"  # Inactive session cleanup timeout
```

---

## Policy Files

| File | Purpose |
|------|---------|
| `policies/governance.rego` | Client→Server request authorization |
| `policies/elicitation.rego` | Server→Client elicitation control |

## Configuration Files

| File | Purpose |
|------|---------|
| `config.yaml` | Basic MCP governance (client→server only) |
| `config-bidirectional.yaml` | Full bidirectional inspection with session support |

## Troubleshooting

### Elicitation requests being blocked unexpectedly

1. Check the tool ID is in the trusted_tools list in `elicitation.rego`
2. Review logs for the specific block reason
3. Test the policy with OPA: `opa eval -d policies/elicitation.rego -i input.json "data.mcp.elicitation.decision"`

### Session reconnection not working

1. Ensure `X-Agent-ID` header is consistent between connections
2. Verify `Last-Event-ID` matches an event in the buffer
3. Check that reconnection is within `buffer_duration` window
