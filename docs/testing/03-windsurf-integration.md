# Windsurf Integration Guide

This guide covers setting up Windsurf (Codeium's AI IDE) to use MCP tools through the Polis governed proxy.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌─────────────┐
│   Windsurf      │────▶│  Python Adapter  │────▶│  Polis Bridge   │────▶│  MCP Server │
│   Cascade       │◀────│  (HTTP/SSE)      │◀────│  (Governance)   │◀────│  (Git/FS)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘     └─────────────┘
```

Windsurf's Cascade AI uses MCP for tool access. Like VS Code, it expects Stdio-based servers.

## Prerequisites

- Windsurf IDE installed
- Python 3.10+ with `requests` library
- Polis binary (`polis.exe`) built

## Step 1: Locate Windsurf MCP Config

Windsurf stores MCP configuration at:

**Windows:**
```
%USERPROFILE%\.codeium\windsurf\mcp_config.json
```

**Full Path Example:**
```
C:\Users\adam\.codeium\windsurf\mcp_config.json
```

If the file doesn't exist, create it:
```powershell
# Create directory if needed
mkdir -Force "$env:USERPROFILE\.codeium\windsurf"

# Create empty config
echo '{"mcpServers":{}}' > "$env:USERPROFILE\.codeium\windsurf\mcp_config.json"
```

## Step 2: Start Polis Bridge

### Git MCP Server (Recommended for Testing)

Create `polis-git.yaml`:
```yaml
server:
  port: 8090
tools:
  git:
    command: ["npx", "-y", "@modelcontextprotocol/server-git", "."]
```

Run Polis:
```powershell
cd C:\Users\adam\Desktop\startup\polis-oss
.\polis.exe --config polis-git.yaml
```

### Verify Bridge is Running

```powershell
Invoke-RestMethod -Uri "http://localhost:8090/health"
# Expected: {"status":"healthy"}
```

## Step 3: Configure Windsurf MCP

Edit `%USERPROFILE%\.codeium\windsurf\mcp_config.json`:

```json
{
  "mcpServers": {
    "polis-git": {
      "command": "python",
      "args": [
        "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
        "--url",
        "http://localhost:8090",
        "--agent-id",
        "windsurf-cascade"
      ]
    }
  }
}
```

### Multi-Tool Configuration

```json
{
  "mcpServers": {
    "polis-git": {
      "command": "python",
      "args": [
        "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
        "--url", "http://localhost:8090",
        "--agent-id", "windsurf"
      ]
    },
    "polis-filesystem": {
      "command": "python",
      "args": [
        "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
        "--url", "http://localhost:8091",
        "--agent-id", "windsurf"
      ]
    },
    "polis-brave-search": {
      "command": "python",
      "args": [
        "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
        "--url", "http://localhost:8092",
        "--agent-id", "windsurf"
      ]
    }
  }
}
```

## Step 4: Restart Windsurf

1. Close Windsurf completely
2. Reopen Windsurf
3. Open a project folder (e.g., `polis-oss`)

## Step 5: Verify Connection

### Check Bridge Logs

In the Polis Bridge terminal:
```
INFO New session created session_id=xyz789 agent_id=windsurf-cascade
INFO Sent endpoint event session_id=xyz789
```

### Check Windsurf Cascade

1. Open Cascade panel (usually on the right side)
2. The MCP tools should be available to Cascade

## Step 6: Test with Cascade

### Test Prompt 1: Git Status

Type in Cascade:
> "What is the current git status of this repository?"

**Expected Behavior:**
1. Cascade recognizes it needs the `git_status` tool
2. Calls the tool through Polis Bridge
3. Returns formatted git status

**Bridge Logs:**
```
INFO processed message direction=ingress method=tools/call
INFO processed message direction=egress method=tools/call
```

### Test Prompt 2: Git Log

> "Show me the last 5 commits in this repository"

**Expected:** Cascade uses `git_log` tool and displays commit history.

### Test Prompt 3: Git Diff

> "What files have been modified since the last commit?"

**Expected:** Cascade uses `git_diff` tool and shows changes.

## Step 7: Test Brave Search (Optional)

### Start Brave Search Bridge

Create `polis-search.yaml`:
```yaml
server:
  port: 8092
tools:
  brave-search:
    command: ["npx", "-y", "@anthropics/brave-search-mcp"]
    env:
      BRAVE_API_KEY: "BSA-xxxxxxxxxxxxxxxx"
```

Start bridge:
```powershell
.\polis.exe --config polis-search.yaml
```

### Test Search

In Cascade:
> "Search the web for 'MCP Model Context Protocol latest news'"

**Expected:** Cascade uses Brave Search tool and returns web results.

## Troubleshooting

### Config Not Loading

```powershell
# Verify config file exists and is valid JSON
Get-Content "$env:USERPROFILE\.codeium\windsurf\mcp_config.json" | ConvertFrom-Json
```

### Python Path Issues

Use absolute path to Python:
```json
{
  "mcpServers": {
    "polis-git": {
      "command": "C:\\Python311\\python.exe",
      "args": [...]
    }
  }
}
```

### Connection Refused

1. Verify bridge is running: `curl http://localhost:8090/health`
2. Check port matches config
3. Ensure no firewall blocking

### Tools Not Appearing

1. Check Windsurf logs (Help > Toggle Developer Tools > Console)
2. Look for MCP connection errors
3. Verify adapter script path is correct

### Session Timeout

If Cascade disconnects frequently:
1. Check bridge logs for errors
2. Verify network stability
3. Consider increasing session timeout in bridge config

## Advanced: Multiple Workspaces

For different projects with different tools:

```json
{
  "mcpServers": {
    "polis-git-project-a": {
      "command": "python",
      "args": ["...mcp_sse_client.py", "--url", "http://localhost:8090", "--agent-id", "windsurf-project-a"]
    },
    "polis-git-project-b": {
      "command": "python",
      "args": ["...mcp_sse_client.py", "--url", "http://localhost:8093", "--agent-id", "windsurf-project-b"]
    }
  }
}
```

Run separate bridges for each project:
```powershell
# Project A
cd C:\Projects\ProjectA
# (Ensure polis-project-a.yaml exists with port 8090)
polis.exe --config polis-project-a.yaml

# Project B
cd C:\Projects\ProjectB
# (Ensure polis-project-b.yaml exists with port 8093)
polis.exe --config polis-project-b.yaml
```

## Success Criteria

✅ Windsurf connects to Polis Bridge  
✅ Cascade can list available tools  
✅ Git operations work through Cascade  
✅ Bridge logs show governed traffic  
✅ Multiple tools work simultaneously  

## Next Steps

- [Git MCP Testing](./04-git-mcp-testing.md) - Detailed Git scenarios
- [Brave Search Testing](./05-brave-search-testing.md) - Web search integration
- [Policy Enforcement](./06-policy-enforcement.md) - Add governance rules
