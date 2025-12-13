# PII Redaction Example

This example demonstrates how to use the Data Loss Prevention (DLP) capabilities of Polis to redact sensitive information from requests.

## Prerequisites

- Built `polis.exe` binary.

## Configuration

### `dlp_rules.yaml`
Defines regex rules to detect emails and phone numbers.

```yaml
rules:
  - id: "email-redaction"
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    action: "redact"
```

### `config.yaml`
Configures a `dlp` node that uses the above rules file.

## Running the Example

### Option 1: Run from Project Root
1.  Open a terminal in the project root.
2.  **Edit** `examples/pii-redaction/config.yaml`:
    Update the `rules_file` path:
    ```yaml
    nodes:
      - id: redact-pii
        type: dlp
        config:
          rules_file: "examples/pii-redaction/dlp_rules.yaml" # UPDATED PATH
    ```
3.  Run Polis:
    ```powershell
    ./polis.exe --config examples/pii-redaction/config.yaml
    ```

### Option 2: Use as Main Config
1.  Copy `config.yaml` and `dlp_rules.yaml` to the root directory.
2.  Ensure `rules_file: "dlp_rules.yaml"` is set in config.
3.  Run `./polis.exe`.

## Notes
- The DLP filter currently operates on the request body.
- Supported rule types include `regex`.
