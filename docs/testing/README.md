# Polis Unified Sidecar Testing Documentation

This directory contains comprehensive testing guides for validating the Polis Unified Sidecar with real-world MCP tools and IDE integrations.

## Documentation Structure

| Document | Purpose |
|----------|---------|
| [Quick Start](./01-quick-start.md) | 5-minute setup to verify basic functionality |
| [VS Code Integration](./02-vscode-integration.md) | Complete VS Code setup with MCP tools |
| [Windsurf Integration](./03-windsurf-integration.md) | Windsurf/Cascade setup and testing |
| [Git MCP Testing](./04-git-mcp-testing.md) | Git operations through governed proxy |
| [Brave Search Testing](./05-brave-search-testing.md) | Web search with API key management |
| [Policy Enforcement](./06-policy-enforcement.md) | Testing governance and blocking rules |
| [Troubleshooting](./07-troubleshooting.md) | Common issues and solutions |

## Prerequisites

Before starting any test scenario, ensure you have:

- **Polis Binary**: Built `polis.exe`
- **Node.js 18+**: For MCP tool servers (`npx`)
- **Python 3.10+**: For IDE adapter script
- **VS Code** or **Windsurf**: Target IDE for integration testing

## Quick Verification

```powershell
# Build the sidecar
cd polis-oss
go build -o polis.exe ./cmd/polis

# Verify binary
./polis.exe --help
```

## Test Scenarios Overview

### Scenario 1: Basic Bridge (No Governance)
- Start bridge with filesystem MCP server
- Connect via MCP Inspector
- Verify tool listing and execution

### Scenario 2: IDE Integration
- Configure VS Code/Windsurf with Python adapter
- Execute Git operations through governed proxy
- Verify logs show traffic flow

### Scenario 3: Policy Enforcement
- Configure blocking policies
- Attempt blocked operations
- Verify policy decisions in logs

### Scenario 4: Multi-Tool Setup
- Run multiple MCP servers (Git + Brave Search)
- Configure IDE with multiple tool endpoints
- Test cross-tool workflows
