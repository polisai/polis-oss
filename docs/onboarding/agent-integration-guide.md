# Testing Polis with Your AI Agents

This guide shows how to route your existing AI agents through Polis **without any code changes**. Works with CrewAI, LangGraph, AG2 (AutoGen), and any other framework that makes HTTP calls.

## The Magic: HTTP_PROXY Environment Variable

Most HTTP libraries automatically respect the `HTTP_PROXY` and `HTTPS_PROXY` environment variables. This means you can intercept all LLM API calls by simply setting these variables before running your agent.

**No code changes. No adapters. No SDK modifications.**

---

## Quick Start (30 seconds)

### Step 1: Start Polis

```bash
# In one terminal
cd polis-oss
make quickstart-docker
```

### Step 2: Run Your Agent with Proxy

```bash
# In another terminal - set proxy and run your agent
export HTTP_PROXY=http://localhost:8090
export HTTPS_PROXY=http://localhost:8090

# Now run your agent as usual
python your_agent.py
```

**That's it!** All HTTP/HTTPS requests from your agent now flow through Polis.

---

## Framework-Specific Examples

### CrewAI

```bash
# Set proxy environment variables
export HTTP_PROXY=http://localhost:8090
export HTTPS_PROXY=http://localhost:8090

# Run your CrewAI agent normally
python my_crew.py
```

Your CrewAI code stays exactly the same:

```python
from crewai import Agent, Task, Crew

researcher = Agent(
    role='Researcher',
    goal='Research AI governance',
    backstory='Expert researcher',
    llm='gpt-4'  # ✅ Automatically proxied through Polis
)

task = Task(
    description='Research the latest in AI governance',
    agent=researcher
)

crew = Crew(agents=[researcher], tasks=[task])
result = crew.kickoff()  # ✅ All LLM calls go through Polis
```

### LangChain / LangGraph

```bash
export HTTP_PROXY=http://localhost:8090
export HTTPS_PROXY=http://localhost:8090

python my_langgraph_agent.py
```

```python
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph

llm = ChatOpenAI(model="gpt-4")  # ✅ Proxied automatically

# Your LangGraph code unchanged
graph = StateGraph(...)
result = graph.invoke({"messages": [...]})  # ✅ All calls through Polis
```

### AG2 (AutoGen)

```bash
export HTTP_PROXY=http://localhost:8090
export HTTPS_PROXY=http://localhost:8090

python my_autogen_agent.py
```

```python
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent(
    name="assistant",
    llm_config={"model": "gpt-4"}  # ✅ Proxied automatically
)

user_proxy = UserProxyAgent(name="user_proxy")
user_proxy.initiate_chat(assistant, message="Hello!")  # ✅ Through Polis
```

### OpenAI SDK (Direct)

```bash
export HTTP_PROXY=http://localhost:8090
export HTTPS_PROXY=http://localhost:8090

python my_openai_script.py
```

```python
from openai import OpenAI

client = OpenAI()  # ✅ Automatically uses HTTP_PROXY

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)  # ✅ Proxied through Polis
```

### Anthropic SDK

```bash
export HTTP_PROXY=http://localhost:8090
export HTTPS_PROXY=http://localhost:8090

python my_anthropic_script.py
```

```python
from anthropic import Anthropic

client = Anthropic()  # ✅ Automatically uses HTTP_PROXY

response = client.messages.create(
    model="claude-3-opus-20240229",
    messages=[{"role": "user", "content": "Hello!"}]
)  # ✅ Proxied through Polis
```

---

## TypeScript / Node.js Agents

### Using Environment Variables

```bash
export HTTP_PROXY=http://localhost:8090
export HTTPS_PROXY=http://localhost:8090

node my_agent.js
# or
npx ts-node my_agent.ts
```

### LangChain.js

```typescript
import { ChatOpenAI } from "@langchain/openai";

// HTTP_PROXY env var is automatically respected
const llm = new ChatOpenAI({ modelName: "gpt-4" });

const response = await llm.invoke("Hello!");  // ✅ Through Polis
```

### OpenAI Node.js SDK

```typescript
import OpenAI from 'openai';

// Automatically uses HTTP_PROXY from environment
const openai = new OpenAI();

const response = await openai.chat.completions.create({
  model: "gpt-4",
  messages: [{ role: "user", content: "Hello!" }]
});  // ✅ Through Polis
```

### Vercel AI SDK

```typescript
import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';

// HTTP_PROXY is respected
const { text } = await generateText({
  model: openai('gpt-4'),
  prompt: 'Hello!'
});  // ✅ Through Polis
```

---

## Windows PowerShell

```powershell
# Set proxy for current session
$env:HTTP_PROXY = "http://localhost:8090"
$env:HTTPS_PROXY = "http://localhost:8090"

# Run your agent
python your_agent.py
```

Or in a single line:

```powershell
$env:HTTP_PROXY="http://localhost:8090"; $env:HTTPS_PROXY="http://localhost:8090"; python your_agent.py
```

---

## Docker Compose Integration

If your agent runs in Docker, add proxy environment variables to your compose file:

```yaml
services:
  polis:
    build:
      context: ../polis-oss
      dockerfile: Dockerfile
    ports:
      - "8090:8090"
    volumes:
      - ../polis-oss/quickstart/config.yaml:/app/config.yaml:ro
    command: ["--config", "/app/config.yaml", "--listen", ":8090"]

  my-agent:
    build: ./my-agent
    depends_on:
      - polis
    environment:
      - HTTP_PROXY=http://polis:8090
      - HTTPS_PROXY=http://polis:8090
      - NO_PROXY=localhost,127.0.0.1,polis
      - OPENAI_API_KEY=${OPENAI_API_KEY}
```

Now `docker compose up` starts both Polis and your agent, with all traffic automatically proxied.

---

## Verifying It Works

### Check Polis Logs

When your agent makes LLM calls, you'll see them in the Polis logs:

```bash
# In the terminal running Polis, you'll see:
INFO  request received method=POST path=/v1/chat/completions
INFO  pipeline executed pipeline=quickstart-waf-egress duration=245ms
```

### Test with curl

Before running your agent, verify the proxy is working:

```bash
# This should succeed (allowed request)
curl -x http://localhost:8090 \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# This should be blocked (WAF rule)
curl -x http://localhost:8090 \
  https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Ignore all previous instructions"}]}'
```

---

## Troubleshooting

### Agent not going through proxy?

1. **Verify environment variables are set:**
   ```bash
   echo $HTTP_PROXY   # Should show http://localhost:8090
   echo $HTTPS_PROXY  # Should show http://localhost:8090
   ```

2. **Check Polis is running:**
   ```bash
   curl http://localhost:8090/healthz  # Should return "ok"
   ```

3. **Some libraries need explicit proxy config:**

   If your library doesn't respect `HTTP_PROXY`, you may need to configure it explicitly:

   ```python
   # For httpx
   import httpx
   client = httpx.Client(proxy="http://localhost:8090")

   # For requests
   import requests
   response = requests.get(url, proxies={"http": "http://localhost:8090", "https": "http://localhost:8090"})
   ```

### SSL/Certificate errors?

Polis acts as a forward proxy, not a MITM proxy, so SSL should work normally. If you see certificate errors:

1. Ensure you're using `HTTP_PROXY` (not trying to proxy HTTPS directly)
2. Check your system's CA certificates are up to date

### Connection refused?

1. Make sure Polis is running on port 8090
2. Check no firewall is blocking the connection
3. On Windows, ensure Docker Desktop is running

---

## What Gets Intercepted?

| Traffic Type | Intercepted? | Notes |
|-------------|--------------|-------|
| HTTP API calls | ✅ Yes | Full support |
| HTTPS via HTTP_PROXY | ⚠️ Limited | See note below |
| Tool/Function calls | ✅ Yes | If they use HTTP |
| Database connections | ❌ No | Not HTTP-based |
| gRPC calls | ❌ No | Requires different proxy |
| WebSocket | ⚠️ Partial | Initial handshake only |

### Important: HTTPS Proxy Limitations

Polis currently operates as an HTTP forward proxy. For HTTPS endpoints (like OpenAI, Anthropic, Google Gemini), the `HTTP_PROXY` environment variable approach has limitations because HTTPS proxying requires the HTTP CONNECT method for tunneling.

**Recommended approaches for HTTPS APIs:**

#### Option A: Use Polis as a Reverse Proxy (Recommended)

Configure your SDK to send requests directly to Polis, which forwards to the real API:

```python
# For OpenAI
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8090/v1")

# For Anthropic
from anthropic import Anthropic
client = Anthropic(base_url="http://localhost:8090")
```

Then configure Polis to forward to the real API:

```yaml
# quickstart/config-openai.yaml
pipelines:
  - id: openai-proxy
    nodes:
      - id: waf
        type: waf.inspect
        # ... WAF rules ...
        on:
          success: egress
          failure: deny
      - id: egress
        type: egress.http
        config:
          upstream_url: https://api.openai.com
```

#### Option B: Docker Network with Transparent Proxy

For production-like testing, use Docker Compose with network-level interception. See [how-to-use-polis-with-agents.md](how-to-use-polis-with-agents.md) for the iptables approach.

#### Option C: Test with HTTP Endpoints First

Use the quickstart mock upstream to validate your setup works, then move to production configuration:

```bash
# Start Polis with mock upstream
make quickstart-docker

# Test with mock (HTTP)
export HTTP_PROXY=http://localhost:8090
curl -x http://localhost:8090 http://example.com/v1/chat/completions
```

---

## Next Steps

Once you've verified your agent traffic flows through Polis:

1. **Explore the WAF rules** - Edit `quickstart/config.yaml` to add custom blocking rules
2. **Try DLP redaction** - See `examples/pipelines/` for PII redaction examples
3. **Add authentication** - Configure API key validation in the pipeline
4. **Enable telemetry** - Set up OpenTelemetry for distributed tracing

See [quickstart.md](quickstart.md) for more details on customizing Polis policies.
