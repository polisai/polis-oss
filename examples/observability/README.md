# Observability Example

This example demonstrates how to configure logging and observability features in Polis.

## Prerequisites

- Built `polis.exe` binary.

## Configuration

The `config.yaml` highlights the global `logging` section:

```yaml
logging:
  level: "debug"
  format: "json"
```

This enables detailed debug logs in structured JSON format, suitable for ingestion by log collectors (e.g., Fluentd, Splunk).

## Running the Example

### Option 1: Run from Project Root
1.  Open a terminal in the project root.
2.  Run Polis:
    ```powershell
    ./polis.exe --config examples/observability/config.yaml
    ```

### Option 2: Use as Main Config
1.  Copy `config.yaml` to the root directory.
2.  Run `./polis.exe`.
