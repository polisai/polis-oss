# Model Context Protocol (MCP) Implementation Research: Deep-Dive v2

This document provides an exhaustive technical analysis of the MCP bridge implementation within `polis-oss`. It is intended as the master reference for developers and architects.

## Table of Contents
1. [Part 1: Architecture & Strategic Context](#part-1-architecture--strategic-context)
2. [Part 2: Technical Implementation Deep-Dive](#part-2-technical-implementation-deep-dive)
3. [Part 3: State, Reliability & Multi-Tenancy](#part-3-state-reliability--multi-tenancy)
4. [Part 4: The Governance Model (Bidirectional Security)](#part-4-the-governance-model-bidirectional-security)
5. [Part 5: Code Map & Directory Index](#part-5-code-map--directory-index)
6. [Part 6: Critical Analysis (Pros vs. Cons)](#part-6-critical-analysis-pros-vs-cons)

---

## Part 1: Architecture & Strategic Context

### 1.1 The Connectivity Gap
Standard MCP implementations rely heavily on the **Stdio transport**, which is ideal for local CLI tools but creates a major barrier for networked AI agents (e.g., cloud-hosted orchestrators). The `polis-bridge` serves as the essential "Adaptor Pattern" that bridges this gap.

> [!IMPORTANT]
> The primary mission of the bridge is to transform a **local, unmanaged process** into a **governed, networked API**.

### 1.2 The Proxy Philosophy
Polis adopts a "Proxy-First" approach to governance. Instead of running MCP tools directly within the agent's environment (which is hard to monitor and secure), the bridge creates a **Governance Choke Point**. 

- **Centralized Inspection**: Every JSON-RPC packet is intercepted.
- **Protocol Translation**: Stdio is mapped to HTTP/SSE, allowing standard web clients (browsers, remote servers) to interact with local tools.
- **Isolation**: The tool runs in a child process, decoupled from the main gateway logic.

### 1.3 Protocol Translation Flow
The bridge manages a complex dance of three distinct protocols:
1. **Stdio**: Raw bytes sent to/from the child process's `stdin` and `stdout`.
2. **JSON-RPC**: The high-level protocol used by MCP for commands and notifications.
3. **HTTP/SSE**: The transport layer used to deliver events to the remote agent.

---

## Part 2: Technical Implementation Deep-Dive

### 2.1 Process Orchestration (`process_manager.go`)
The `DefaultProcessManager` is the brain of the execution layer. It doesn't just "run" a command; it manages its entire lifecycle.

- **Lifecycle Hooks**: Spawns processes with `os/exec`, tracks their PIDs, and manages graceful `SIGTERM` followed by hard `SIGKILL` if the process hangs.
- **Pipe Management**:
    - **Stdin**: Synchronized writes to prevent message corruption.
    - **Stdout/Stderr**: Buffered scanners that feed into the `ReadLoop`.
- **Resource Capping**: (Planned/Initial) The bridge can enforce timeouts on process startup to prevent zombie processes or resource exhaustion attacks.

### 2.2 The IO Event Loop
A critical part of the implementation is the `readProcessOutput` loop in `bridge.go`.

```go
func (b *Bridge) readProcessOutput() {
    b.process.ReadLoop(func(data []byte) {
        // 1. Classification
        msgType, msg, _ := ClassifyJSONRPC(data)
        
        // 2. Inspection
        ctx := context.Background()
        result, _ := b.inspector.Inspect(ctx, event, "")
        
        // 3. Dispatch
        if result.Action == ActionAllow {
            b.sessions.Broadcast(event)
        }
    })
}
```

- **Non-blocking Reads**: The `ReadLoop` ensures that the bridge remains responsive even if the MCP server is generating massive amounts of data.
- **Backpressure**: While basic in the current version, the use of channels in `Broadcast` provides the foundation for handling slow SSE clients.

### 2.3 SSE Provider (`sse.go`)
The `SSE` layer is responsible for framing JSON-RPC messages into valid Server-Sent Events.

- **CRLF Normalization**: MCP messages must be correctly escaped to prevent breaking the SSE wire format (`data: ... \n\n`).
- **Endpoint Injection**: The first event sent to a client is the `endpoint` event. This tells the client where to send `POST` requests for its `message` commands, effectively completing the bidirectional link.

---

## Part 3: State, Reliability & Multi-Tenancy

### 3.1 Session Continuity (`session_manager.go`)
MCP sessions in Polis are designed for high availability in unstable network conditions.

- **The RingBuffer Mechanism**: The bridge maintains a per-session `RingBuffer` in memory. This buffer stores the most recent `N` SSE events.
- **Reconnection Logic**: When a client reconnects and provides a `Last-Event-ID` header, the bridge automatically replays missed events from the buffer.
- **Session Lifecycle**: 
    - **Creation**: Triggered by a GET request to `/sse`.
    - **Expiration**: Sessions are purged after a configurable `TTL` if no activity is detected, releasing the associated child process.

### 3.2 Multi-Tenant Isolation
The bridge is built to be "Agent-Aware."

- **Agent-ID Enforcement**: The `AgentIDMiddleware` (in `middleware.go`) ensures that requests are tagged with a unique identifier. This prevents "Session Cross-Talk" where one agent might inadvertently receive events intended for another.
- **Context Separation**: While multiple tools can run on a single bridge, each tool identified by a `system_id` maintains its own process and IO streams.

### 3.3 Observability (`metrics.go` & `tracing.go`)
A silent gateway is a dangerous one. Polis integrates deeply with OpenTelemetry.

- **Metrics**: Tracks `mcp_messages_total`, `mcp_process_restarts`, and `mcp_session_active_count`.
- **Tracing**: Every JSON-RPC request is wrapped in a Span. The bridge propagates trace context to the child process via environment variables (e.g., `TRACEPARENT`), allowing for end-to-end observability if the MCP server is also instrumented.

---

## Part 4: The Governance Model (Bidirectional Security)

### 4.1 The "Elicitation" Problem
In standard tool-calling, the agent is the master and the tool is the servant. However, MCP allows for **Server-Initiated Requests** (e.g., `sampling/createMessage`). A compromised or malicious tool can attempt to "elicit" PII or secrets from the agent's context.

> [!WARNING]
> Without bidirectional inspection, a tool could trick an agent into revealing its entire history or performing unauthorized actions.

### 4.2 Stream Inspection Mechanics (`stream_inspector.go`)
The `StreamInspector` is the heart of Polis's security model. It operates on a "Classify-Evaluate-Act" loop.

1. **Classification**: Uses `ClassifyJSONRPC` to determine if a message is a `Request`, `Notification`, or `Response`.
2. **Bipolar Inspection**:
    - **Northbound (Tool -> Agent)**: Inspects elicitation requests.
    - **Southbound (Agent -> Tool)**: Inspects data being sent to the tool (e.g., checking for PII in tool parameters).
3. **Policy Engine**: Decouples the "What to block" logic into OPA (Open Policy Agent) Rego files.

### 4.3 Redaction & Blocking
The inspector can return three distinct results:
- **Allow**: No changes made.
- **Block**: The event is dropped entirely; the client never sees it.
- **Redact**: The JSON payload is mutated in-place (e.g., replacing a credit card number with `[REDACTED]`) before being serialized to the SSE wire.

---

## Part 5: Code Map & Directory Index

The `pkg/bridge` directory is organized into functionally decoupled modules.

| File | Primary Struct/Role | Description |
| :--- | :--- | :--- |
| `bridge.go` | `Bridge` | The Entry point. Orchestrates HTTP/SSE handlers and the IO state machine. |
| `process_manager.go` | `ProcessManager` | Handles `os/exec` logic, stdin/stdout synchronization, and process health. |
| `stream_inspector.go`| `StreamInspector` | The security brain. Performs JSON-RPC classification and OPA evaluation. |
| `session_manager.go` | `SessionManager` | Manages tenant isolation, session TTLs, and `RingBuffer` replays. |
| `sse.go` | `SSEEvent` / Utils | Serializes/Deserializes SSE frames and manages client stream headers. |
| `config.go` | `BridgeConfig` | Defines the schema for bridge-specific settings (command, env, policy paths). |
| `metrics.go` | `Metrics` | Prometheus instrumentation for process exits and message volume. |
| `middleware.go` | `AgentIDMiddleware` | Enforces authentication and traces context propagation. |

---

## Part 6: Critical Analysis (Pros vs. Cons)

### 6.1 The Strengths (SWOT: Strengths)
- **Universal Stdio Adaptor**: Directly supports 90% of current MCP ecosystem tools out-of-the-box.
- **Bipolar Governance**: Unique ability to block elicitation requests before they reach the agent.
- **Enterprise Ready**: Full support for mTLS, Agent-ID isolation, and OpenTelemetry.

### 6.2 The Limitations (SWOT: Weaknesses)
- **Process Isolation**: The bridge currently runs child processes in the same kernel namespace. A malicious binary could potentially escape the Stdio sandbox and access the host file system.
- **Cold Boot Latency**: Spawning a new child process per session can introduce measurable delays for serverless or edge deployments.
- **State Continuity**: While SSE reconnections are supported, terminal process failure results in total session loss.

### 6.3 The Vision: "The Secure Triad"
To address the current limitations, the project is moving towards a tiered isolation model:
1. **Docker Gateway**: Running the bridge itself within a hardened container.
2. **E2B Integration**: Offloading untrusted tool execution to ephemeral, fire-walled sandboxes.
3. **NixOS / Supply Chain**: Ensuring that the bridge and its tools are built from verifiable, deterministic snapshots to prevent package-level poisoning.

---

## Conclusion
The Polis MCP Bridge is more than a transport translator; it is a **Security Policy Enforcement Point (PEP)**. By decoupling the tool execution from the agent logic and providing real-time stream inspection, it allows enterprises to adopt the MCP ecosystem without sacrificing zero-trust principles.
