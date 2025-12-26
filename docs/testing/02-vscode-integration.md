# VS Code Integration Guide

This guide covers setting up VS Code to use MCP tools through the Polis governed proxy.

## Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌─────────────┐
│   VS Code       │────▶│  Python Adapter  │────▶│  Polis Bridge   │────▶│  MCP Server │
│   (Stdio)       │◀────│  (HTTP/SSE)      │◀────│  (Governance)   │◀────│  (Git/FS)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘     └─────────────┘
```

VS Code expects MCP servers to communicate via Stdio. The Python adapter bridges this gap by:
1. Reading Stdio from VS Code
2. Forwarding to Polis Bridge via HTTP
3. Streaming responses back via SSE

## Prerequisites

- VS Code with MCP extension (e.g., Continue, Cline, or similar)
- Python 3.10+ with `requests` library
- Polis binary (`polis.exe`) built

## Step 1: Install Python Dependencies

```powershell
pip install requests
```

## Step 2: Verify Adapter Script

The adapter is located at:
```
polis-oss/examples/mcp-bridge/ide-adapter/mcp_sse_client.py
```

Test it manually:
```powershell
python C:\Users\adam\Desktop\startup\polis-oss\examples\mcp-bridge\ide-adapter\mcp_sse_client.py --help
```

## Step 3: Start Polis Bridge

### Create Configuration (polis.yaml)

#### Option A: Git MCP Server
```yaml
server:
  port: 8090
tools:
  git:
    command: ["npx", "-y", "@modelcontextprotocol/server-git", "."]
```

#### Option B: Filesystem MCP Server
```yaml
server:
  port: 8090
tools:
  filesystem:
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\adam\\Desktop\\startup"]
```

### Start Polis
```powershell
.\polis.exe --config polis.yaml
```

## Step 4: Configure VS Code MCP Settings

### Location of MCP Config

VS Code MCP configuration is typically at:
- **Windows**: `%APPDATA%\Code\User\globalStorage\<extension-id>\mcp_config.json`
- **Or**: In the extension's settings UI

### For Continue Extension

1. Open VS Code Settings (`Ctrl+,`)
2. Search for "Continue MCP"
3. Click "Edit in settings.json"
4. Add:

```json
{
  "continue.mcpServers": {
    "polis-git": {
      "command": "python",
      "args": [
        "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
        "--url", "http://localhost:8090",
        "--agent-id", "vscode-continue"
      ]
    }
  }
}
```

### For Cline Extension

1. Open Command Palette (`Ctrl+Shift+P`)
2. Search "Cline: Open MCP Settings"
3. Add server configuration:

```json
{
  "mcpServers": {
    "polis-git": {
      "command": "python",
      "args": [
        "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
        "--url", "http://localhost:8090",
        "--agent-id", "vscode-cline"
      ]
    }
  }
}
```

### Generic MCP Config Format

```json
{
  "mcpServers": {
    "polis-git": {
      "command": "python",
      "args": [
        "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
        "--url", "http://localhost:8090",
        "--agent-id", "vscode-user"
      ],
      "env": {}
    },
    "polis-filesystem": {
      "command": "python",
      "args": [
        "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
        "--url", "http://localhost:8091",
        "--agent-id", "vscode-user"
      ]
    }
  }
}
```

## Step 5: Reload VS Code

1. Press `Ctrl+Shift+P`
2. Run "Developer: Reload Window"
3. Wait for extensions to reconnect

## Step 6: Verify Connection

### Check Bridge Logs

In the Polis terminal, you should see:
```
INFO New session created session_id=abc123 agent_id=vscode-user
INFO Sent endpoint event session_id=abc123
```

### Check VS Code

1. Open the MCP tool panel (varies by extension)
2. You should see tools like:
   - `git_status`
   - `git_log`
   - `git_diff`
   - `git_commit`

## Step 7: Test Tool Execution

### Via Chat Interface

Ask your AI assistant:
> "What is the current git status of this repository?"

### Expected Flow

1. VS Code sends request to Python adapter
2. Adapter forwards to Polis Bridge
3. Bridge evaluates policy (if configured)
4. Bridge forwards to Git MCP server
5. Response streams back through the chain

### Verify in Logs

```
INFO Received message request method=POST
INFO processed message direction=ingress method=tools/call
INFO processed message direction=egress method=tools/call
```

## Multi-Server Setup

Run multiple bridges on different ports:

Create three config files and run three instances (or one instance with multiple tools if supported, but simpler to use separate ports for now):

```powershell
# Terminal 1: Git server (polis-git.yaml -> port 8090)
.\polis.exe --config polis-git.yaml

# Terminal 2: Filesystem server (polis-fs.yaml -> port 8091)
.\polis.exe --config polis-fs.yaml

# Terminal 3: Brave Search (polis-search.yaml -> port 8092)
.\polis.exe --config polis-search.yaml
```

Configure all in VS Code:
```json
{
  "mcpServers": {
    "polis-git": {
      "command": "python",
      "args": ["...mcp_sse_client.py", "--url", "http://localhost:8090", "--agent-id", "vscode"]
    },
    "polis-fs": {
      "command": "python",
      "args": ["...mcp_sse_client.py", "--url", "http://localhost:8091", "--agent-id", "vscode"]
    },
    "polis-search": {
      "command": "python",
      "args": ["...mcp_sse_client.py", "--url", "http://localhost:8092", "--agent-id", "vscode"]
    }
  }
}
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Tools not appearing | Check bridge logs for connection errors |
| "Python not found" | Use full path: `C:\Python311\python.exe` |
| Connection timeout | Verify bridge is running on correct port |
| 401 Unauthorized | Ensure `--agent-id` is passed to adapter |
| No response | Check if MCP server started successfully |

## Success Criteria

✅ VS Code connects to Polis Bridge  
✅ Tools appear in MCP panel  
✅ Tool calls execute successfully  
✅ Bridge logs show traffic flow  
✅ Governance policies are evaluated (if configured)  

## Next Steps

- [Windsurf Integration](./03-windsurf-integration.md)
- [Git MCP Testing](./04-git-mcp-testing.md)
- [Policy Enforcement](./06-policy-enforcement.md)
