# Polis OSS - Configuration Guide

This guide explains how to configure the Polis OSS Proxy. There are two main parts to configuration:
1.  **System Config (`config.yaml`)**: Global settings like logging and server ports.
2.  **Pipeline Config (`pipeline.yaml`)**: Defines the flow of traffic (DAG) and specific behaviors for each Agent.

## 1. System Configuration (`config.yaml`)

The `config.yaml` file controls the behavior of the proxy instance itself.

```yaml
logging:
  level: debug   # Options: debug, info, warn, error
  pretty: true   # true for human-readable console logs, false for JSON (production)

server:
  port: 8090     # (Optional) Port to listen on, defaults to 8090 if not set
```

## 2. Pipeline Configuration

Polis uses a Directed Acyclic Graph (DAG) to process requests. This allows you to chain together modular "nodes" like Authorization, Policy Checks, and Egress.

Pipelines are defined in YAML. You can have multiple pipelines for different agents or protocols.

### Structure of a Pipeline

```yaml
id: my-pipeline-id          # Unique ID for this pipeline
agentId: my-agent           # The Agent ID this pipeline matches (or "*" for wildcard)
protocol: http              # Protocol (http is the primary supported protocol in OSS)
nodes:
  - id: start               # ID of the node
    type: auth              # Node type (see Node Types below)
    on:                     # Edge definitions (next steps)
      success: policy_check # Go here if this node succeeds
      failure: deny         # Go here if this node fails

  - id: policy_check
    type: policy
    config:
      entrypoint: "policy/main" # OPA policy entrypoint
    on:
      success: egress
      failure: deny

  - id: egress
    type: egress
    config:
      upstream_url: https://api.openai.com
    on:
      success: ""           # Empty string ends the pipeline successfully

  - id: deny
    type: terminal.deny     # Returns a 403/End of stream
```

### Common Node Types

| Node Type | Description | Config Parameters |
| :--- | :--- | :--- |
| `auth` | Validates authentication tokens (OIDC). | N/A (Uses global auth config) |
| `policy` | Executes OPA/Rego policies. | `entrypoint`: The policy rule to query.<br>`posture`: `fail-closed` or `fail-open`. |
| `dlp` | Scans content for sensitive data. | `rules`: List of regex patterns to Redact/Block. |
| `egress` | Forwards the request upstream. | `upstream_url`: Destination URL.<br>`upstream_mode`: `static` or dynamic routing. |
| `terminal.deny` | Stops execution and returns error. | N/A |

## 3. Policy Integration (OPA/Rego)

Polis uses Open Policy Agent (OPA) for logic. You write policies in Rego.

### Example Policy (`policy.rego`)

```rego
package policy

default allow = false

# Allow if the logic passes
allow {
    input.request.method == "POST"
    # Add your complex logic here
}
```

The proxy loads these policies (typically from a `policies/` directory or configured path) and evaluates them in `policy` nodes.

## 4. Customizing Your Setup

To create a custom setup:

1.  Create a new `pipeline.yaml` (or modify the default).
2.  Define your nodes and flow.
3.  If using policies, write your `.rego` files.
4.  Ensure your `config.yaml` points to or loads these resources.

In the next section (User Stories), we will walk through specific examples of how to configure these files for real-world scenarios.
