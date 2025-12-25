# Troubleshooting Guide

This guide covers common issues and solutions when testing the Polis MCP proxy.

## Quick Diagnostics

### Health Check

```powershell
# Check if bridge is running
Invoke-RestMethod -Uri "http://localhost:8090/health"

# Expected: {"status":"healthy"}
# If unhealthy: {"status":"unhealthy","reason":"..."}
```

### Process Check

```powershell
# Check if bridge process is running
Get-Process | Where-Object {$_.ProcessName -like "*polis*"}

# Check if child process (npx/node) is running
Get-Process | Where-Object {$_.ProcessName -like "*node*"}
```

### Port Check

```powershell
# Check if port is in use
netstat -ano | findstr :8090

# Check what's using the port
Get-Process -Id (Get-NetTCPConnection -LocalPort 8090).OwningProcess
```

---

## Connection Issues

### Issue: "Connection Refused"

**Symptoms:**
- `curl: (7) Failed to connect to localhost port 8090`
- IDE shows "Cannot connect to MCP server"

**Solutions:**

1. **Verify bridge is running:**
   ```powershell
   # Check process
   Get-Process polis-bridge -ErrorAction SilentlyContinue
   
   # If not running, start it
   .\polis.exe --config polis.yaml
   ```

2. **Check port conflict:**
   ```powershell
   # See what's using port 8090
   netstat -ano | findstr :8090
   
   # Use different port
   # Use different port (override in command or config)
   .\polis.exe --port 8091 --config polis.yaml
   ```

3. **Check firewall:**
   ```powershell
   # Allow port through firewall (admin required)
   New-NetFirewallRule -DisplayName "Polis Bridge" -Direction Inbound -LocalPort 8090 -Protocol TCP -Action Allow
   ```

### Issue: "401 Unauthorized"

**Symptoms:**
- SSE connection fails with 401
- "missing X-Agent-ID header" in logs

**Solutions:**

1. **Add Agent ID header:**
   ```powershell
   curl.exe -H "X-Agent-ID: my-agent" http://localhost:8090/sse
   ```

2. **Check IDE adapter config:**
   ```json
   {
     "args": ["...mcp_sse_client.py", "--url", "http://localhost:8090", "--agent-id", "my-agent"]
   }
   ```

3. **Use relaxed mode (development):**
   ```powershell
   # Note: polis.exe enforces agent-id by default. Ensure client sends X-Agent-ID.
   ```

### Issue: "403 Forbidden"

**Symptoms:**
- Session access denied
- "agent ID mismatch" in logs

**Solutions:**

1. **Use consistent agent ID:**
   - Ensure same `--agent-id` across all requests
   - Don't mix agent IDs in same session

2. **Check session ownership:**
   - Each session is bound to creating agent
   - Create new session if agent ID changed

---

## MCP Tool Issues

### Issue: "No Tools Listed"

**Symptoms:**
- MCP Inspector shows empty tools list
- IDE doesn't see any tools

**Solutions:**

1. **Wait for handshake:**
   ```
   # Check bridge logs for:
   INFO MCP handshake completed successfully
   ```

2. **Check child process:**
   ```powershell
   # Verify npx/node is running
   Get-Process node
   
   # Check stderr in bridge logs
   WARN Process stderr output=...
   ```

3. **Test tool directly:**
   ```powershell
   # Run MCP server directly (without bridge)
   npx -y @modelcontextprotocol/server-filesystem .
   # Type: {"jsonrpc":"2.0","id":1,"method":"tools/list"}
   ```

### Issue: "Tool Call Timeout"

**Symptoms:**
- Tool calls hang
- No response received

**Solutions:**

1. **Check child process health:**
   ```powershell
   # Look for process errors
   Get-Process node -ErrorAction SilentlyContinue
   ```

2. **Increase timeout:**
   ```yaml
   # config.yaml
   shutdown_timeout: 30s
   ```

3. **Check for blocking operations:**
   - Some tools may block on user input
   - Check tool documentation

### Issue: "JSON Parse Error"

**Symptoms:**
- `SyntaxError: Unterminated string in JSON`
- Partial responses

**Solutions:**

1. **Large payload handling:**
   - Bridge should handle messages up to 10MB
   - Check if response is truncated

2. **Check encoding:**
   - Ensure UTF-8 encoding
   - Check for binary data in response

---

## Policy Issues

### Issue: "Policy Not Loading"

**Symptoms:**
- "Failed to load policy modules" in logs
- Policy not being evaluated

**Solutions:**

1. **Check file path:**
   ```powershell
   # Verify policy files exist
   Get-ChildItem examples/mcp-bridge/policies/*.rego
   ```

2. **Validate Rego syntax:**
   ```powershell
   # Install OPA CLI
   # Then validate
   opa check examples/mcp-bridge/policies/authz.rego
   ```

3. **Check entrypoint:**
   ```yaml
   # config.yaml
   policy:
     path: "examples/mcp-bridge/policies"
     entrypoint: "mcp/authz"  # Must match package name
   ```

### Issue: "Policy Not Matching"

**Symptoms:**
- Expected block not happening
- Policy seems ignored

**Solutions:**

1. **Enable debug logging:**
   ```powershell
   .\polis.exe --log-level debug --config ...
   ```

2. **Check policy input:**
   ```rego
   # Add to policy for debugging
   package mcp.authz
   
   import rego.v1
   
   # This will show in logs
   debug := input
   ```

3. **Verify input structure:**
   - `input.method` - JSON-RPC method
   - `input.params` - Method parameters
   - `input.agent_id` - Agent identifier

### Issue: "Policy Blocks Everything"

**Symptoms:**
- All requests blocked
- "default deny" behavior

**Solutions:**

1. **Check default decision:**
   ```rego
   # Ensure default is allow
   default decision := {"action": "allow"}
   ```

2. **Check rule conditions:**
   - Rules may be too broad
   - Add more specific conditions

---

## IDE Integration Issues

### Issue: "Python Adapter Not Found"

**Symptoms:**
- "python not found" error
- IDE can't start MCP server

**Solutions:**

1. **Use full Python path:**
   ```json
   {
     "command": "C:\\Python311\\python.exe",
     "args": ["..."]
   }
   ```

2. **Check Python installation:**
   ```powershell
   python --version
   where.exe python
   ```

3. **Install dependencies:**
   ```powershell
   pip install requests
   ```

### Issue: "Adapter Script Path Wrong"

**Symptoms:**
- "No such file or directory"
- Script not found

**Solutions:**

1. **Use absolute paths:**
   ```json
   {
     "args": [
       "C:\\Users\\adam\\Desktop\\startup\\polis-oss\\examples\\mcp-bridge\\ide-adapter\\mcp_sse_client.py",
       "--url", "http://localhost:8090"
     ]
   }
   ```

2. **Escape backslashes:**
   - JSON requires `\\` for Windows paths
   - Or use forward slashes: `C:/Users/adam/...`

### Issue: "VS Code Extension Not Connecting"

**Symptoms:**
- Extension shows disconnected
- No MCP tools available

**Solutions:**

1. **Reload VS Code:**
   - `Ctrl+Shift+P` → "Developer: Reload Window"

2. **Check extension logs:**
   - `Ctrl+Shift+P` → "Developer: Toggle Developer Tools"
   - Look for MCP-related errors

3. **Verify config location:**
   - Different extensions use different config paths
   - Check extension documentation

### Issue: "Windsurf Not Loading Config"

**Symptoms:**
- Cascade doesn't see tools
- Config seems ignored

**Solutions:**

1. **Verify config path:**
   ```powershell
   # Check file exists
   Get-Content "$env:USERPROFILE\.codeium\windsurf\mcp_config.json"
   ```

2. **Validate JSON:**
   ```powershell
   Get-Content "$env:USERPROFILE\.codeium\windsurf\mcp_config.json" | ConvertFrom-Json
   ```

3. **Restart Windsurf completely:**
   - Close all Windsurf windows
   - End any remaining processes
   - Reopen

---

## Performance Issues

### Issue: "Slow Response Times"

**Symptoms:**
- Tool calls take long time
- Noticeable lag

**Solutions:**

1. **Check network:**
   ```powershell
   # Test latency
   Measure-Command { Invoke-RestMethod http://localhost:8090/health }
   ```

2. **Check child process:**
   - Some MCP servers are slow to start
   - First call may be slower (cold start)

3. **Reduce logging:**
   ```powershell
   .\polis.exe --log-level warn --config ...
   ```

### Issue: "Memory Usage High"

**Symptoms:**
- Bridge using lots of memory
- System slowdown

**Solutions:**

1. **Check session buffer:**
   ```yaml
   # config.yaml
   session:
     buffer_size: 100  # Reduce from default
   ```

2. **Restart bridge periodically:**
   - For long-running sessions
   - Clears accumulated state

---

## Logging and Debugging

### Enable Verbose Logging

```powershell
.\polis.exe --log-level debug --config ...
```

### Log Levels

| Level | Use Case |
|-------|----------|
| `error` | Production, errors only |
| `warn` | Production, warnings and errors |
| `info` | Default, normal operation |
| `debug` | Development, verbose output |

### Key Log Messages

| Message | Meaning |
|---------|---------|
| `MCP handshake completed` | Tool server ready |
| `New session created` | Client connected |
| `processed message` | Request/response handled |
| `Policy decision` | Governance evaluated |
| `Process exited` | Child process stopped |

### Capture Logs to File

```powershell
.\polis.exe --config ... 2>&1 | Tee-Object -FilePath bridge.log
```

---

## Getting Help

### Collect Diagnostic Info

When reporting issues, include:

1. **Bridge version:**
   ```powershell
   # Check help output
   .\polis.exe --help
   ```

2. **Configuration:**
   ```powershell
   Get-Content examples/mcp-bridge/config.yaml
   ```

3. **Logs:**
   ```powershell
   # Run with debug logging
   .\polis.exe --log-level debug --config ...
   ```

4. **Environment:**
   ```powershell
   $PSVersionTable
   go version
   node --version
   python --version
   ```

### Common Commands Summary

```powershell
# Health check
Invoke-RestMethod http://localhost:8090/health

# Test SSE connection
curl.exe -N -H "X-Agent-ID: test" http://localhost:8090/sse

# Check processes
Get-Process | Where-Object {$_.ProcessName -match "polis|node"}

# Check ports
netstat -ano | findstr :8090

# Validate policy
opa check examples/mcp-bridge/policies/authz.rego
```
