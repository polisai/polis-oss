# MCP Bridge Example

This example demonstrates how to use the Polis MCP Bridge to govern standard CLI-based MCP tools without modifying them.

## Overview

The MCP Bridge acts as a translator between HTTP/SSE and Stdio transports, enabling:
- Governance of any MCP tool that uses stdio transport (npx, docker, etc.)
- Bidirectional security inspection of messages
- Session management with reconnection support
- Policy enforcement for both client→server and server→client messages

## Prerequisites

- Go 1.21+ (to build Polis)
- Node.js 18+ (for npx-based MCP tools)
- npm or npx available in PATH

## Quick Start

### 1. Build Polis Bridge

```bash
go build -o polis-bridge.exe ./cmd/polis-bridge
```

### 2. Start the Bridge with a Filesystem Tool

```bash
# Basic usage - start bridge with filesystem MCP server
./polis-bridge --port 8090 -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox

# Or use the configuration file
./polis-bridge --config examples/mcp-bridge/config.yaml
```

### 3. Connect Your Agent

Configure your AI agent (IDE, Claude Desktop, etc.) to connect to:
- SSE endpoint: `http://localhost:8090/sse`
- Message endpoint: `http://localhost:8090/message`

## Configuration

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--port, -p` | Port to listen on | 8090 |
| `--config, -c` | Path to configuration file | - |
| `--log-level, -l` | Log level (debug, info, warn, error) | info |

### Configuration File

See `config.yaml` for a complete example. Key settings:

```yaml
# Bridge server settings
listen_addr: ":8090"

# Command to execute
command:
  - npx
  - -y
  - "@modelcontextprotocol/server-filesystem"
  - "/tmp/sandbox"

# Session management
session:
  buffer_size: 1000      # Events to buffer for reconnection
  buffer_duration: 60s   # How long to keep buffered events
  session_timeout: 300s  # Inactive session timeout

# Gateway integration (optional)
gateway:
  enabled: true
  url: "http://localhost:8085"
  agent_id: "bridge-001"
```

## Policy Enforcement

### Elicitation Policy

The bridge can enforce policies on server-initiated requests (elicitation) to prevent prompt injection attacks. See `policies/elicitation.rego` for an example policy that:

- Allows sampling requests only from trusted tools
- Blocks prompts containing injection patterns
- Limits maximum token requests
- Uses fail-closed behavior by default

### Integrating with Polis Gateway

To enable full policy enforcement:

1. Start Polis Gateway with MCP governance config:
   ```bash
   ./polis --config examples/mcp-governance/config.yaml
   ```

2. Configure the bridge to connect through the gateway:
   ```yaml
   gateway:
     enabled: true
     url: "http://localhost:8085"
     agent_id: "bridge-001"
   ```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sse` | GET | SSE stream for server→client messages |
| `/message` | POST | JSON-RPC messages from client→server |
| `/health` | GET | Health check endpoint |
| `/metrics` | GET | Prometheus metrics (if enabled) |

## Session Management

The bridge supports session persistence for reconnection:

1. **Session Creation**: Each SSE connection receives a unique session ID
2. **Event Buffering**: Events are buffered for reconnection support
3. **Reconnection**: Use `Last-Event-ID` header to resume from last event
4. **Cleanup**: Inactive sessions are automatically cleaned up

### Reconnection Example

```bash
# Initial connection
curl -N http://localhost:8090/sse -H "X-Agent-ID: my-agent"

# Reconnect with last event ID
curl -N http://localhost:8090/sse \
  -H "X-Agent-ID: my-agent" \
  -H "Last-Event-ID: evt-123"
```

## Multi-Tenant Isolation

The bridge enforces tenant isolation using the `X-Agent-ID` header:

- Requests without `X-Agent-ID` receive 401 Unauthorized
- Sessions are bound to the creating agent
- Cross-agent session access returns 403 Forbidden

## Observability

### Health Check

```bash
curl http://localhost:8090/health
```

Returns:
```json
{
  "status": "healthy",
  "process": "running",
  "uptime": "1h23m45s"
}
```

### Metrics

When metrics are enabled, Prometheus metrics are available at `/metrics`:

- `polis_bridge_messages_total` - Total messages processed
- `polis_bridge_message_duration_seconds` - Message processing latency
- `polis_bridge_active_sessions` - Current active session count
- `polis_bridge_buffer_events` - Events in reconnection buffer

## Troubleshooting

### Bridge won't start

1. Check that the command is valid: `npx -y @modelcontextprotocol/server-filesystem --help`
2. Verify Node.js is installed: `node --version`
3. Check port availability: `netstat -an | grep 8090`

### Connection issues

1. Verify the bridge is running: `curl http://localhost:8090/health`
2. Check logs for errors: `./polis-bridge --log-level debug ...`
3. Ensure `X-Agent-ID` header is set for SSE connections

### Policy blocking requests

1. Check the policy file syntax: `opa check policies/elicitation.rego`
2. Review logs for policy decisions
3. Test policy with OPA playground
