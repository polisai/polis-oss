# Quick Start: 5-Minute Verification

This guide gets you from zero to a working Polis MCP proxy in 5 minutes.

## Step 1: Build the Binary (1 min)

```powershell
cd C:\Users\adam\Desktop\startup\polis-oss

# Build the unified sidecar
go build -o polis.exe ./cmd/polis
```

## Step 2: Create Test Directory (30 sec)

```powershell
# Create a test directory for testing
mkdir C:\Users\adam\Desktop\mcp-test
echo "Hello from Polis MCP Proxy!" > C:\Users\adam\Desktop\mcp-test\test.txt
echo "SECRET_API_KEY=sk-12345" > C:\Users\adam\Desktop\mcp-test\secrets.txt
```

## Step 3: Start the Bridge (30 sec)

```powershell
# Create config file
@"
server:
  port: 8090
tools:
  filesystem:
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\adam\\Desktop\\mcp-test"]
"@ | Out-File -Encoding UTF8 polis.yaml

# Start Polis with config
.\polis.exe --config polis.yaml
```

**Expected Output:**
```
INFO Starting polis-bridge port=8090 command=[npx -y @modelcontextprotocol/server-filesystem C:\Users\adam\Desktop\mcp-test]
INFO Process started pid=12345
INFO MCP handshake completed successfully
INFO HTTP server starting addr=:8090
```

## Step 4: Verify Health (30 sec)

Open a new terminal:

```powershell
# Check health endpoint
Invoke-RestMethod -Uri "http://localhost:8090/health"
```

**Expected Output:**
```json
{"status":"healthy"}
```

## Step 5: Test SSE Connection (1 min)

```powershell
# Connect to SSE endpoint (will stream events)
curl.exe -N -H "X-Agent-ID: quick-test" "http://localhost:8090/sse"
```

**Expected Output:**
```
event: endpoint
data: http://localhost:8090/message?session_id=abc123

event: message
data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",...}}
```

Press `Ctrl+C` to stop.

## Step 6: Test with MCP Inspector (1.5 min)

```powershell
# Launch the official MCP Inspector
npx @modelcontextprotocol/inspector
```

1. Open the URL shown (usually `http://localhost:5173`)
2. In the connection field, enter: `http://localhost:8090/sse`
3. Add header: `X-Agent-ID: inspector-test`
4. Click **Connect**
5. Click **Tools** tab
6. You should see: `read_file`, `write_file`, `list_directory`, etc.

### Test a Tool Call

1. Select `read_file`
2. Enter arguments:
   ```json
   {"path": "C:\\Users\\adam\\Desktop\\mcp-test\\test.txt"}
   ```
3. Click **Run**
4. **Expected Result**: `Hello from Polis MCP Proxy!`

## Success Criteria

✅ Health endpoint returns `{"status":"healthy"}`  
✅ SSE connection streams `endpoint` event  
✅ MCP Inspector lists filesystem tools  
✅ `read_file` returns file contents  
✅ Bridge logs show `method=tools/call`  

## Next Steps

- [VS Code Integration](./02-vscode-integration.md) - Connect your IDE
- [Git MCP Testing](./04-git-mcp-testing.md) - Test with real Git operations
- [Policy Enforcement](./06-policy-enforcement.md) - Add governance rules

## Quick Troubleshooting

| Issue | Solution |
|-------|----------|
| `Connection refused` | Ensure bridge is running on port 8090 |
| `401 Unauthorized` | Add `X-Agent-ID` header |
| `npx not found` | Install Node.js and ensure `npx` is in PATH |
| `No tools listed` | Wait for MCP handshake to complete |
