# MCP Governance Examples

This directory contains examples for verifying Polis OSS governance features (Access Control, Operation Gating, DLP) with Model Context Protocol (MCP).

## Prerequisites
- Python 3.10+
- Go 1.21+ (to build Polis)

## Setup

1. **Install Python Dependencies:**
   ```bash
   pip install -r examples/mcp-governance/client/requirements.txt
   ```

2. **Build Polis:**
   ```bash
   cd ../..
   go build -o polis.exe ./cmd/polis
   ```

## Running the Examples

### 1. Start the Mock MCP Server
This server simulates a filesystem, git repo, and search engine. It runs on port `8000`.
```bash
python examples/mcp-governance/client/server.py
```

### 2. Start Polis Gateway
Run Polis using the provided configuration. It listens on `:8085` and proxies to `:8000`.
```bash
go run cmd/polis-core/main.go --config examples/mcp-governance/config.yaml
```

### 3. Run Verification Script
This script sends JSON-RPC requests to Polis (`:8085`), which proxies them to the Mock Server (`:8000`) while enforcing policies.

```bash
python examples/mcp-governance/client/verify_governance.py
```

## Expected Results
1. **Filesystem Read**: `Success` (Allowed by policy).
2. **Filesystem Write**: `Blocked` (Policy Violation: Write operation blocked).
3. **Search**: `Success` but content should contain `[REDACTED_EMAIL]` instead of real email.
