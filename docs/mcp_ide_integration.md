# MCP IDE Integration & Testing Guide

This guide outlines how to use **Polis Bridge** with real-world IDEs like **Visual Studio Code** and **Windsurf**, verifying interactions with MCP servers like **Git** and **Perplexity**.

## Overview

Most IDEs expect MCP servers to be **local executables** communicating via Stdio (Standard Input/Output). 
Polis Bridge, however, operates as an **HTTP/SSE Server** to provide governance and policy enforcement.

To bridge this gap, we use a lightweight **Python Adapter**.

**Flow:**
`IDE (Stdio) <-> Python Adapter <-> [HTTP/SSE] <-> Polis Bridge <-> MCP Server (e.g., Git)`

## Prerequisites

1.  **Polis Bridge Binary**: Built and available.
2.  **Python 3.x**: With `requests` installed (`pip install requests`).
3.  **Adapter Script**: Located at `examples/mcp-bridge/ide-adapter/mcp_sse_client.py`.
4.  **Target MCP Servers**:
    -   **Git**: `npx -y @modelcontextprotocol/server-git`
    -   **Perplexity**: Requires API Key.

---

## 1. Setup the Python Adapter

Ensure dependencies are installed:
```bash
pip install requests
```

The adapter script (`mcp_sse_client.py`) will be used as the "command" in your IDE configuration. It connects to the running bridge via SSE.

---

## 2. Test Scenario A: Git Integration

**Goal**: Verify the IDE can perform Git operations through the governed bridge.

### 2.1 Start Polis Bridge (Hosting Git)

Run the bridge in a terminal. It will host the Git MCP server.
```bash
# Windows
./polis-bridge.exe --port 8090 -- npx -y @modelcontextprotocol/server-git .
```

### 2.2 Configure VS Code

1.  Install the **"Model Context Protocol"** extension (e.g., from Robocorp or similar, depending on availability).
2.  Open your MCP configuration file (usually `mcp_config.json` or via Extension Settings).
3.  Add the bridge configuration:

```json
{
  "mcpServers": {
    "git-polis": {
      "command": "python",
      "args": [
        "C:/Users/adam/Desktop/startup/polis-oss/examples/mcp-bridge/ide-adapter/mcp_sse_client.py",
        "--url",
        "http://localhost:8090",
        "--agent-id",
        "vscode-user"
      ]
    }
  }
}
```
4.  **Reload VS Code**.
5.  **Verify**: Open the MCP Tool panel (if available) or use the Chat interface to ask: *"What is the status of the current git repo?"*
6.  **Polis Logs**: You should see traffic in the Polis Bridge terminal (`method=tools/call`), verifying governance.

### 2.3 Configure Windsurf

1.  Locate Windsurf's MCP config: `~/.codeium/windsurf/mcp_config.json` (or `%USERPROFILE%\.codeium\windsurf\mcp_config.json` on Windows).
2.  Add the same entry as above.
3.  **Restart Windsurf Cascade**.
4.  **Verify**: Ask Cascade: *"Check the git log for the last 3 commits."*

---

## 3. Test Scenario B: Perplexity Integration (Search)

**Goal**: Verify the IDE can search the web using Perplexity through the bridge.

### 3.1 Start Polis Bridge (Hosting Perplexity)

**Note**: You need a Perplexity API Key.

```bash
set PERPLEXITY_API_KEY=pplx-xxxxxxxx
./polis-bridge.exe --port 8091 -- npx -y @modelcontextprotocol/server-perplexity
```
*(Note: We use port 8091 to avoid conflict if the Git bridge is still running, or stop the previous one.)*

### 3.2 Update IDE Configuration

Update the JSON config to point to the new bridge instance (or a different entry).

```json
{
  "mcpServers": {
    "perplexity-polis": {
      "command": "python",
      "args": [
        "C:/Users/adam/Desktop/startup/polis-oss/examples/mcp-bridge/ide-adapter/mcp_sse_client.py",
        "--url",
        "http://localhost:8091",
        "--agent-id",
        "research-agent"
      ]
    }
  }
}
```

### 3.3 Verify
1.  **Restart IDE**.
2.  **Ask**: *"Search for the latest news on 'Agentic AI Standards' using Perplexity."*
3.  **Observe**: The IDE should stream results. The Bridge logs will show the traffic.

---

## 4. Troubleshooting

-   **"Connection Refused"**: Ensure `polis-bridge.exe` is running and the port matches the `--url` arg.
-   **"Python not found"**: Ensure `python` is in your PATH or use the full path to `python.exe`.
-   **"No Output"**: Check the Bridge logs. If the policy blocks a request, the adapter might receive nothing.
-   **Path Issues**: Always use absolute paths in IDE JSON configurations to prevent CWD confusion.
