# Brave Search MCP Testing Guide

This guide covers testing the Brave Search MCP server through Polis Bridge, including API key management and search governance.

## Overview

The Brave Search MCP server provides web search capabilities to AI agents. This is useful for:
- Research and fact-checking
- Finding documentation
- Current events and news
- Technical information lookup

## Prerequisites

### Get Brave Search API Key

1. Go to [Brave Search API](https://brave.com/search/api/)
2. Sign up for an account
3. Create an API key (free tier available)
4. Copy the key (format: `BSA-xxxxxxxxxxxxxxxx`)

### Verify API Key

```powershell
# Test API key directly
$headers = @{"X-Subscription-Token" = "BSA-your-api-key"}
Invoke-RestMethod -Uri "https://api.search.brave.com/res/v1/web/search?q=test" -Headers $headers
```

## Setup

### Step 1: Set Environment Variable

```powershell
# Set for current session
$env:BRAVE_API_KEY = "BSA-your-actual-api-key"

# Or set permanently (requires admin)
[Environment]::SetEnvironmentVariable("BRAVE_API_KEY", "BSA-your-actual-api-key", "User")
```

### Step 2: Start Polis Bridge with Brave Search

```powershell
cd C:\Users\adam\Desktop\startup\polis-oss

# Ensure API key is set
echo $env:BRAVE_API_KEY

# Start bridge
.\polis-bridge.exe --port 8092 -- npx -y @anthropics/brave-search-mcp
```

**Expected Output:**
```
INFO Starting polis-bridge port=8092 command=[npx -y @anthropics/brave-search-mcp]
INFO Process started pid=12345
INFO MCP handshake completed successfully
INFO HTTP server starting addr=:8092
```

### Step 3: Verify Health

```powershell
Invoke-RestMethod -Uri "http://localhost:8092/health"
# Expected: {"status":"healthy"}
```

## Test Scenarios

---

### Scenario 1: Basic Web Search

**Goal:** Verify basic search functionality works.

**Test via MCP Inspector:**
1. Connect to `http://localhost:8092/sse`
2. Add header: `X-Agent-ID: search-tester`
3. Go to Tools tab
4. Select `brave_web_search`
5. Enter arguments:
   ```json
   {"query": "Model Context Protocol MCP"}
   ```
6. Click Run

**Expected Output:**
```json
{
  "results": [
    {
      "title": "Model Context Protocol - Anthropic",
      "url": "https://...",
      "description": "..."
    },
    ...
  ]
}
```

**Via IDE Chat:**
> "Search the web for 'Model Context Protocol MCP'"

---

### Scenario 2: News Search

**Goal:** Verify news-specific search works.

**Test Arguments:**
```json
{
  "query": "AI agents latest news",
  "count": 5,
  "freshness": "day"
}
```

**Via IDE Chat:**
> "Search for the latest news about AI agents from today"

**Verification:**
- Results are recent (within last day)
- Results are news-related

---

### Scenario 3: Local Search

**Goal:** Verify location-based search works.

**Test Arguments:**
```json
{
  "query": "coffee shops",
  "country": "US",
  "search_lang": "en"
}
```

**Via IDE Chat:**
> "Search for coffee shops in the US"

---

### Scenario 4: Search with Filters

**Goal:** Verify search filters work correctly.

**Test Arguments:**
```json
{
  "query": "python programming tutorial",
  "count": 10,
  "safesearch": "strict"
}
```

**Verification:**
- Results are safe for work
- Count matches requested

---

### Scenario 5: Error Handling - Invalid API Key

**Goal:** Verify graceful handling of API key issues.

**Setup:**
```powershell
# Start with invalid key
$env:BRAVE_API_KEY = "invalid-key"
.\polis-bridge.exe --port 8092 -- npx -y @anthropics/brave-search-mcp
```

**Test:**
1. Attempt a search
2. Verify error message is returned (not crash)

**Expected:**
- Error message about authentication
- Bridge remains running

---

### Scenario 6: Rate Limiting

**Goal:** Verify handling of API rate limits.

**Test:**
1. Make many rapid search requests
2. Observe behavior when rate limit hit

**Expected:**
- Rate limit error returned
- Bridge doesn't crash
- Subsequent requests work after cooldown

---

## Governance Testing

### Scenario 7: Block Sensitive Searches

**Goal:** Verify policy can block certain search queries.

**Create Policy** (`examples/mcp-bridge/policies/search-policy.rego`):
```rego
package mcp.authz

import rego.v1

default decision := {"action": "allow"}

# Block searches containing sensitive terms
decision := {"action": "block", "reason": "Search query contains blocked terms"} if {
    input.method == "tools/call"
    input.params.name == "brave_web_search"
    query := input.params.arguments.query
    contains(lower(query), "confidential")
}

decision := {"action": "block", "reason": "Search query contains blocked terms"} if {
    input.method == "tools/call"
    input.params.name == "brave_web_search"
    query := input.params.arguments.query
    contains(lower(query), "internal only")
}
```

**Start Bridge with Policy:**
```powershell
.\polis-bridge.exe --port 8092 --config examples/mcp-bridge/search-config.yaml -- npx -y @anthropics/brave-search-mcp
```

**Test:**
1. Search for "confidential company data"
2. Verify search is blocked

**Expected:**
- Search fails with policy message
- Bridge logs show `action=block`

---

### Scenario 8: Redact Search Results

**Goal:** Verify policy can redact sensitive information from results.

**Policy for Redaction:**
```rego
package mcp.authz

import rego.v1

# Redact URLs containing certain domains
decision := {"action": "redact", "reason": "Redacting internal URLs"} if {
    input.method == "tools/call"
    # Check if response contains internal URLs
    # (This would be in the egress/after policy)
}
```

---

### Scenario 9: Audit Search Queries

**Goal:** Verify all searches are logged for compliance.

**Test:**
1. Perform various searches
2. Review bridge logs

**Expected Log Entries:**
```
INFO processed message direction=ingress method=tools/call tool=brave_web_search query="MCP protocol"
INFO processed message direction=egress method=tools/call tool=brave_web_search results_count=10
```

---

## Multi-Tool Integration

### Scenario 10: Combined Git + Search Workflow

**Goal:** Test using both Git and Search tools together.

**Setup:**
```powershell
# Terminal 1: Git bridge
.\polis-bridge.exe --port 8090 -- npx -y @modelcontextprotocol/server-git .

# Terminal 2: Search bridge
$env:BRAVE_API_KEY = "BSA-your-key"
.\polis-bridge.exe --port 8092 -- npx -y @anthropics/brave-search-mcp
```

**IDE Config:**
```json
{
  "mcpServers": {
    "polis-git": {
      "command": "python",
      "args": ["...mcp_sse_client.py", "--url", "http://localhost:8090", "--agent-id", "dev"]
    },
    "polis-search": {
      "command": "python",
      "args": ["...mcp_sse_client.py", "--url", "http://localhost:8092", "--agent-id", "dev"]
    }
  }
}
```

**Test Workflow:**
1. Ask: "What is the current git status?"
2. Ask: "Search for documentation about the error message I'm seeing"
3. Verify both tools work in same session

---

## API Key Security

### Best Practices

1. **Never commit API keys** to version control
2. **Use environment variables** for key storage
3. **Rotate keys** periodically
4. **Monitor usage** in Brave dashboard

### Secure Key Storage

**Windows Credential Manager:**
```powershell
# Store key
cmdkey /generic:BRAVE_API_KEY /user:api /pass:BSA-your-key

# Retrieve in script (example)
# Use Windows Credential Manager API
```

**Environment File (Development Only):**
```powershell
# .env file (add to .gitignore!)
BRAVE_API_KEY=BSA-your-key

# Load in PowerShell
Get-Content .env | ForEach-Object {
    if ($_ -match "^([^=]+)=(.*)$") {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2])
    }
}
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "API key not found" | Verify `BRAVE_API_KEY` env var is set |
| "401 Unauthorized" | Check API key is valid and not expired |
| "429 Too Many Requests" | Wait for rate limit reset |
| "No results" | Try different search terms |
| "Connection refused" | Verify bridge is running on correct port |

---

## Success Criteria

✅ Basic web search returns results  
✅ News search with freshness filter works  
✅ Search count parameter respected  
✅ Invalid API key handled gracefully  
✅ Rate limiting handled without crash  
✅ Policies can block sensitive searches  
✅ All searches logged for audit  
✅ Multi-tool workflow works  

## Next Steps

- [Policy Enforcement](./06-policy-enforcement.md)
- [Troubleshooting](./07-troubleshooting.md)
