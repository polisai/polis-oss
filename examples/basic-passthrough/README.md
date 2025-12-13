# Basic Proxy & Pass-through Example

This example demonstrates the simplest configuration for Polis: acting as a transparent proxy. It forwards all incoming HTTP traffic to a configured upstream service.

## Prerequisites

- Built `polis.exe` binary.
- Basic understanding of running command-line tools.

## Configuration

The `config.yaml` defines a single pipeline:

```yaml
pipelines:
  - id: basic-passthrough
    nodes:
      - id: start
        type: egress
        config:
          upstream_url: "https://httpbin.org/anything"
```

## Running the Example

### Option 1: Run from Project Root
1.  Open a terminal in the project root.
2.  Run Polis pointing to the example config:
    ```powershell
    ./polis.exe --config examples/basic-passthrough/config.yaml
    ```

### Option 2: Use as Main Config
1.  Copy `config.yaml` to the root directory.
2.  Run `./polis.exe` (defaults to `config.yaml`).

You should see the response from `httpbin.org` (or your configured upstream) mirroring your request details. The logs will verify the request flowed through the pipeline.
