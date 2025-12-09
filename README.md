# Polis - Secure AI Proxy (Open Source Core)

> **Note**: This is the Open Source Core of the Polis project. For the Enterprise version, please refer to the [Polis Enterprise Documentation](../polis-enterprise/docs).

Polis is a high-performance, protocol-aware proxy designed to enforce zero-trust governance, policy enforcement, and observability for AI agent traffic. It acts as a centralized control plane for your AI infrastructure, intercepting requests, executing user-defined pipelines, and ensuring that all interactions with LLMs and other services are secure, compliant, and monitored.

The OSS version provides the foundational engine for building secure AI gateways, featuring a flexible Directed Acyclic Graph (DAG) pipeline architecture and Policy-as-Code enforcement.

## 🚀 Key Features

*   **Protocol-Aware Proxying**: Native support for HTTP 1.1 and HTTP/2 traffic routing.
*   **Pipeline Architecture**: Define request processing flows as Directed Acyclic Graphs (DAGs), allowing for complex logic like "Auth -> WAF -> Policy -> Egress".
*   **Policy as Code**: Integrated **Open Policy Agent (OPA)** engine allows you to write fine-grained authorization and governance logic in Rego.
*   **WAF Node**: Built-in Web Application Firewall (WAF) node for pattern-based request inspection.
    *   Protect against prompt injection and other attacks using regex rules.
    *   Supports file-backed buffering for large request bodies.
    *   Configurable "fail-open" or "fail-closed" posture.
*   **DLP Node**: Data Loss Prevention (DLP) engine for protecting sensitive information.
    *   Real-time streaming redaction of PII (Personally Identifiable Information).
    *   Configurable scope (request/response) and actions (Redact, Block).
*   **Observability**: First-class support for **OpenTelemetry** (OTLP) to trace every request and policy decision.

## 🏗️ Architecture

```mermaid
graph TD
    User[User/Client] -->|Request| Core[Polis Core :8080]
    
    subgraph Polis Core
        Core -->|Load| Config[File Config Provider]
        Config -->|Watch| File[config.yaml]
        Core -->|Route| Registry[Pipeline Registry]
        Registry --> Executor[DAG Executor]
        Executor -->|Node 1| Policy[OPA Policy Handler]
        Executor -->|Node 2| DLP[DLP Handler]
        Executor -->|Node 3| Egress[Egress Handler]
        Executor -->|Telemetry| Logger[Async JSON Logger]
    end
    
    Egress --> Upstream[LLM / Service]
```

## 🛠️ Getting Started

### Prerequisites

*   **Go**: Version 1.25 or higher.
*   **Docker** (Optional): For containerized deployment or running dependent services like Redis (if enabled).

### Installation

Clone the repository and build the binary:

```bash
# Clone the repo
git clone https://github.com/polisai/polis-oss.git
cd polis-oss

# Build using the provided PowerShell script (Windows)
pwsh -File build.ps1 build

# OR Build using Go directly
go build -o secure-ai-proxy.exe ./cmd/polis-core
```

### Running the Proxy

Run the binary with your configuration file:

```bash
./secure-ai-proxy.exe --config config.yaml --log-level debug --pretty
```

**Command Line Flags:**
*   `--config`: Path to the configuration file (default: `config.yaml`).
*   `--listen`: Address to listen on (default: `:8080`).
*   `--log-level`: Log level (`debug`, `info`, `warn`, `error`).
*   `--pretty`: Enable pretty console logging (default: `false`).

## ⚙️ Configuration Guide

The proxy is configured via a YAML file.

### `config.yaml` Schema

```yaml
server:
  admin_address: ":19090" # Port for admin/health endpoints
  data_address: ":8080"   # Main proxy traffic port

pipeline:
  file: "pipeline.yaml"   # Path to the pipeline definition file
  # mod: "dir"            # Alternatively, load from a directory
  # dir: "./pipelines"

telemetry:
  otlp_endpoint: "localhost:4317" # OpenTelemetry collector endpoint
  insecure: true

logging:
  level: "info"

# Optional: Redis for rate limiting or caching
redis:
  address: "localhost:6379"
  password: ""
  db: 0
```

### Pipeline Configuration

Pipelines are defined in a separate YAML file (referenced in `config.yaml`). A pipeline consists of a sequence of **nodes** that process the request.

**Global Pipeline Attributes:**
*   `id`: Unique identifier for the pipeline.
*   `agentId`: The Agent ID this pipeline matches (or `*` for wildcard).
*   `protocol`: Protocol to match (e.g., `http`).

**Node Attributes:**
*   `id`: Unique ID for the node within the pipeline.
*   `type`: Node type (e.g., `auth`, `waf`, `policy`, `dlp`, `egress`, `terminal.deny`).
*   `config`: Configuration specific to the node type.
*   `on`: Transitions based on outcome (`success`, `failure`).

### Example Pipeline

Here is a full example of a pipeline that authenticates a user, checks for WAF attacks, enforces OPA policy, and then forwards the request.

```yaml
id: secure-llm-pipeline
agentId: "my-agent"
protocol: "http"
nodes:
  # 1. Authentication
  - id: auth_start
    type: auth
    on:
      success: waf_check
      failure: loop_deny

  # 2. Web Application Firewall (WAF)
  - id: waf_check
    type: waf
    config:
      action: block
      rules:
        - name: "Prompt Injection"
          pattern: "(?i)(ignore\\s+(all\\s+)?previous\\s+instructions)"
          severity: "high"
          action: "block"
    on:
      success: policy_authz
      failure: loop_deny

  # 3. Policy Enforcement (OPA)
  - id: policy_authz
    type: policy.opa
    config:
      bundleRef: "authz_policy" # References a loaded policy bundle
    on:
      success: upstream_egress
      failure: loop_deny

  # 4. Egress (Forward to Upstream)
  - id: upstream_egress
    type: egress
    config:
      upstream_url: "https://api.openai.com/v1"
    on:
      success: "" # End of pipeline

  # Terminal Node for Failures
  - id: loop_deny
    type: terminal.deny
    config:
      code: 403
      message: "Access Denied"
```

## 🤝 Relation to Polis Enterprise

This repository (`polis-oss`) contains the open-source **Data Plane** and **Core Engine**.

**Polis Enterprise** extends this core with:
*   A centralized Control Plane for managing thousands of agents.
*   Advanced Governance features (SSO, RBAC, Audit Logs).
*   Dynamic pipeline reconfiguration.
*   Enterprise-grade integrations.

For more information, see the [Polis Enterprise Documentation](../polis-enterprise/docs).
