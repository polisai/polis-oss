# is there a way to to that without adapters with just docker or some configuration that does not need to be done in the code

Yes, absolutely. **This is actually the better path for your "zero code changes" goal.** Let me show you three approaches that don't require adapters.

***

## Approach 1: HTTP_PROXY / HTTPS_PROXY Environment Variables (Simplest)

Most Python HTTP libraries (`requests`, `httpx`, `urllib3`) and Node.js libraries (`axios`, `node-fetch`, `undici`) **automatically respect** `HTTP_PROXY` and `HTTPS_PROXY` environment variables.

### In Docker Compose:

```yaml
version: '3.8'
services:
  proxy:
    image: odra/proxy:dev
    ports:
      - "8080:8080"
      - "9090:9090"  # observability UI
    networks:
      - agent-net

  agent-app:
    build: ./quickstart/python-langgraph
    depends_on:
      - proxy
    environment:
      # This is all you need
      - HTTP_PROXY=http://proxy:8080
      - HTTPS_PROXY=http://proxy:8080
      - NO_PROXY=localhost,127.0.0.1,proxy  # avoid proxying internal calls
    networks:
      - agent-net
    # No code changes needed

networks:
  agent-net:
```


### What happens:

1. Agent makes a call: `requests.get("https://api.openai.com/...")`
2. Because `HTTPS_PROXY` is set, the request automatically goes to `http://proxy:8080` first
3. Your proxy receives it, can log/modify/enforce policies
4. Proxy forwards to the real endpoint (or returns modified response)

### Developer experience:

```bash
docker compose up
```

Zero code changes. LangGraph code looks like normal LangGraph:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4", api_key="sk-...")
response = llm.invoke({"messages": [...]})
# ✅ Automatically goes via proxy because HTTP_PROXY env var is set
```


### Limitations:

- **Doesn't work for HTTP/2 or gRPC** (needs TCP-level proxying)
- **Some libraries don't respect env proxies** (e.g., custom Go binaries, some older libraries)
- **HTTPS requires TLS termination** - Polis supports this! See the [TLS Termination Guide](../../examples/tls-termination/)
  - Generate self-signed certs with `polis-cert` utility
  - Configure TLS in your Polis config to inspect HTTPS traffic
  - For mTLS, add client certificate authentication
- **Can't intercept database connections** or non-HTTP protocols

***

## Approach 2: Docker Network with iptables (Transparent Proxy)

This is closer to your production sidecar model. Uses kernel-level packet routing so **literally all TCP traffic** gets intercepted.

### In Docker Compose:

```yaml
version: '3.8'
services:
  proxy:
    image: odra/proxy:dev
    cap_add:
      - NET_ADMIN  # Required for iptables
    networks:
      - agent-net
    environment:
      - PROXY_MODE=transparent
      - PROXY_LISTEN_PORT=8080
    ports:
      - "9090:9090"  # observability

  agent-app:
    build: ./quickstart/python-langgraph
    depends_on:
      - proxy
    networks:
      - agent-net
    # No environment variables needed
    # No code changes needed
    # iptables rules handle the interception

networks:
  agent-net:
    driver: bridge
```


### What your proxy needs to do:

Inside the proxy container, on startup:

```bash
#!/bin/bash
# Inside proxy container startup script

# Configure iptables to redirect all outbound traffic to port 8080
iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.1 -j REDIRECT --to-port 8080

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Start your proxy listening on 0.0.0.0:8080
/path/to/your-proxy-binary --mode=transparent --port=8080
```


### Developer experience:

```bash
docker compose up
```

**Completely identical code** to production. No env vars, no adapters:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4", api_key="sk-...")
response = llm.invoke({"messages": [...]})
# ✅ All TCP traffic is transparently redirected via iptables
```


### How it works:

1. Agent code calls `api.openai.com:443`
2. Kernel routing layer intercepts it (iptables rule)
3. Redirects to `localhost:8080` (your proxy)
4. Your proxy sees the original destination (`api.openai.com:443`) via socket options
5. Proxy connects to real endpoint, forwards traffic, returns response to agent

### Limitations:

- Requires `CAP_NET_ADMIN` in the container (security consideration)
- More complex to debug (transparent proxies are tricky)
- Your proxy must be able to parse/reconstruct the original destination (needs `SO_ORIGINAL_DST` support)
- Won't work on macOS Docker Desktop easily (no native iptables)


### When to use:

- Production sidecar compatibility (same mechanics)
- Zero environment/code changes
- True "all traffic" capture (including TLS, gRPC, custom protocols)

***

## Approach 3: Init Container / Entrypoint Wrapper (Lightweight)

Instead of Docker Compose magic, provide a **tiny wrapper script** that sets up proxying and then launches the user's agent.

### Structure:

```dockerfile
# Dockerfile for agent-app
FROM python:3.11

WORKDIR /app

# Install your wrapper script
COPY --from=odra/proxy-init:latest /usr/local/bin/odra-proxy-entrypoint /entrypoint.sh

# Copy agent code
COPY . .

RUN pip install -r requirements.txt

# Use the wrapper as entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "app.py"]
```

The wrapper script (`odra-proxy-entrypoint`):

```bash
#!/bin/bash

# If ODRA_PROXY_URL is set, configure HTTP proxying
if [ -n "$ODRA_PROXY_URL" ]; then
    export HTTP_PROXY="$ODRA_PROXY_URL"
    export HTTPS_PROXY="$ODRA_PROXY_URL"
    export NO_PROXY="localhost,127.0.0.1"
fi

# Or use iptables if ODRA_PROXY_TRANSPARENT is set
if [ "$ODRA_PROXY_TRANSPARENT" = "true" ]; then
    iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.1 -j REDIRECT --to-port 8080
    sysctl -w net.ipv4.ip_forward=1
fi

# Run whatever command the user specified
exec "$@"
```


### Docker Compose:

```yaml
services:
  proxy:
    image: odra/proxy:dev
    cap_add:
      - NET_ADMIN
    networks:
      - agent-net

  agent-app:
    build: ./quickstart/python-langgraph
    depends_on:
      - proxy
    environment:
      # Either HTTP_PROXY mode:
      - ODRA_PROXY_URL=http://proxy:8080
      # Or transparent mode:
      # - ODRA_PROXY_TRANSPARENT=true
      # (requires CAP_NET_ADMIN)
    networks:
      - agent-net
```


### Advantage:

- Works with or without Compose
- Developers can use same image in K8s, ECS, Lambda, bare servers
- Entrypoint can do other setup (logging, telemetry, config)

***

## Recommendation: Start with Approach 1, Plan for 2

### For your "wow in 5 minutes" GitHub quickstart:

**Use Approach 1 (HTTP_PROXY env vars)**:

- ✅ **Simplest to implement** (just set env vars in Compose)
- ✅ **Works cross-platform** (Windows, Mac, Linux Docker Desktop)
- ✅ **Zero code changes** in agent code
- ✅ **Zero container security concerns**
- ✅ **Covers 95% of use cases** (all HTTP-based LLMs and tools)

```yaml
# docker-compose.dev.yaml
version: '3.8'
services:
  proxy:
    image: odra/proxy:dev
    ports:
      - "8080:8080"
      - "9090:9090"
    networks:
      - agent-net

  agent-app:
    build: ./quickstart/python-langgraph
    depends_on:
      - proxy
    environment:
      - HTTP_PROXY=http://proxy:8080
      - HTTPS_PROXY=http://proxy:8080
      - NO_PROXY=localhost,127.0.0.1,proxy
    networks:
      - agent-net

networks:
  agent-net:
```


### Then offer Approach 2 as a "production-parity" option:

In your docs: *"For true sidecar parity with production, use the transparent proxy mode..."*

```yaml
# docker-compose.transparent.yaml
# (same as above but with CAP_NET_ADMIN + iptables setup)
```


***

## How Your Proxy Handles the Requests

Either way, your proxy needs to **understand** that these are forwarded requests.

### With HTTP_PROXY (Approach 1):

The agent makes an HTTP request like:

```
GET /v1/chat/completions HTTP/1.1
Host: api.openai.com
```

But it connects to `http://proxy:8080`, so your proxy sees:

```
GET https://api.openai.com/v1/chat/completions HTTP/1.1
Host: api.openai.com
```

(The original `Host` header is preserved; your proxy just forwards it.)

Your proxy code:

```python
# Pseudocode for your proxy
async def handle_request(scope, receive, send):
    # scope contains the HTTP request details
    # For forwarded requests, you see the real destination in headers
    host = scope["headers"][b"host"].decode()
    path = scope["path"]

    # Log/modify/enforce policies
    print(f"Agent → {host}{path}")

    # Forward to real endpoint
    real_response = await forward_request(host, path, scope, receive)

    # Send back to agent
    await send(real_response)
```


### With iptables (Approach 2):

Your proxy receives traffic on `localhost:8080` but needs to know the **original destination**. Use `SO_ORIGINAL_DST`:

```python
import socket

# Inside proxy, when accepting a connection:
sock = accept()
# Get original destination before iptables redirect
original_dest = socket.getsockopt(socket.SOL_IP, socket.SO_ORIGINAL_DST)
# original_dest is the real endpoint the agent tried to reach
```


***

## Summary Table

| Approach | Code Changes | Env Vars | Security | Cross-Platform | Complexity |
| :-- | :-- | :-- | :-- | :-- | :-- |
| **1. HTTP_PROXY** | ❌ Zero | ✅ Yes | ✅ Safe | ✅ Yes | 🟢 Low |
| **2. iptables** | ❌ Zero | ❌ No | 🟡 Needs CAP_NET_ADMIN | ❌ Not macOS | 🟠 Medium |
| **3. Wrapper** | ❌ Zero | ✅ Yes/No | ✅ Flexible | ✅ Yes | 🟡 Medium |


***

## Your GitHub README Flow (Approach 1)

```markdown
# Odra Agent Proxy - 5-Minute Quickstart

## Start the proxy and sample agent:

\`\`\`bash
git clone https://github.com/odra-labs/agent-proxy.git
cd agent-proxy
docker compose up
\`\`\`

That's it! The proxy automatically intercepts all outbound requests from the sample agent.

## See it in action:

1. Open http://localhost:9090 (observability UI)
2. In another terminal, hit the agent:
   \`\`\`bash
   curl http://localhost:3000/chat -X POST -d '{"message": "What is AI governance?"}'
   \`\`\`
3. Watch the UI show:
   - Agent → LLM request
   - LLM response
   - Tool calls (if any)
   - Policies applied

## Zero code changes:

Your agent code is **completely unchanged**:
\`\`\`python
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(model="gpt-4")
response = llm.invoke({"messages": [...]})  # ✅ Proxied automatically
\`\`\`

The \`docker-compose.yml\` sets \`HTTP_PROXY\` and \`HTTPS_PROXY\`, so all requests are routed through the proxy.

## Next: Try a policy

Edit \`proxy/policies/basic.yaml\` and add a rule to redact PII. Hit save, send another request through the agent—watch it get redacted in the trace.
```
