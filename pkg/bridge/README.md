# Bridge Package

The `bridge` package provides the core components for the Polis MCP Transport Bridge. This bridge enables governance of standard CLI-based MCP tools by translating between HTTP/SSE and Stdio transports.

## Core Interfaces

### ProcessManager
Manages the lifecycle of child processes, handling stdin/stdout communication and graceful shutdown.

### StreamInspector  
Parses and evaluates Server-Sent Events (SSE) for policy enforcement, including detection of server-initiated JSON-RPC requests.

### SessionManager
Manages persistent sessions with reconnection support and multi-tenant isolation.

## Key Components

- **Bridge**: Main server that coordinates all components
- **BridgeConfig**: Configuration structure with sensible defaults
- **Session**: Represents an active MCP session with event buffering
- **RingBuffer**: Fixed-size circular buffer for event storage and reconnection
- **SSEEvent**: Parsed Server-Sent Event structure
- **InspectionResult**: Result of policy evaluation on SSE events

## Usage

```go
// Create a new bridge with default configuration
config := DefaultBridgeConfig()
logger := slog.Default()
bridge := NewBridge(config, logger)

// Set implementations for the core interfaces
bridge.SetProcessManager(processManager)
bridge.SetSessionManager(sessionManager) 
bridge.SetStreamInspector(streamInspector)

// Start the bridge
ctx := context.Background()
err := bridge.Start(ctx)
```

This package follows the interface-driven design specified in the MCP expansion requirements, enabling clean separation of concerns and testability.