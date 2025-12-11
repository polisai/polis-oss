# Polis Agent Proxy — 5-Minute Quickstart

> Choose your path. All lead to seeing Polis intercept, govern, and trace your agent in under 5 minutes.

---

## 🚀 Your Options

### **Option A: Docker Compose (Recommended)**
**Best for**: Fastest setup, no system dependencies, reproduces production sidecar pattern  
**Time**: ~2 minutes  
**Works on**: macOS, Windows, Linux

```bash
# Clone + Run (one command)
git clone https://github.com/polisai/polis-oss.git && cd polis-oss && docker compose -f quickstart/compose.http-proxy.yaml up
```

**Then**: Open http://localhost:3000 → Send a prompt → Watch Polis intercept it in real-time

---

### **Option B: Local Binary (No Docker)**
**Best for**: Want to see the code run locally, no container overhead  
**Time**: ~3 minutes  
**Works on**: macOS, Windows (PowerShell), Linux

```bash
# Clone + Build + Run
git clone https://github.com/polisai/polis-oss.git && cd polis-oss
make quickstart  # Handles build + config setup + starts proxy
```

**Then**: Same—open http://localhost:3000 → Send a prompt → Watch the traces

---

### **Option C: Kubernetes Sidecar Pattern (Advanced)**
**Best for**: Teams already using K8s, want production-parity in dev  
**Time**: ~4 minutes  
**Works on**: Any K8s cluster (local minikube, EKS, GKE, etc.)

```bash
# Deploy to K8s
kubectl apply -f quickstart/k8s/sidecar-demo.yaml
# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=agent-demo --timeout=60s
# Port-forward to the UI
kubectl port-forward svc/polis-ui 3000:3000 &
```

**Then**: http://localhost:3000 → Send a prompt → See K8s-style sidecar in action

---

## 🎯 The "Wow" Moment (Same for All Paths)

After you run your chosen option, here's what happens:

### **Step 1: Send a prompt through the sample agent**

```bash
# In a terminal, hit the agent endpoint
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is AI governance and why does it matter?"}'
```

### **Step 2: Watch real-time traces in the Polis UI**

Open http://localhost:3000/traces (or 9090 depending on your path)

**You'll see**:
- ✅ Agent's request to the LLM (intercepted)
- ✅ LLM response (proxied back)
- ✅ Any tool calls (logged with full request/response)
- ✅ Policy decisions applied (e.g., "Prompt injected? Blocked!")
- ✅ Full latency breakdown
- ✅ Token counts and costs
- ✅ Audit trail for compliance

### **Step 3: Toggle a Policy**

Edit `quickstart/policies/demo-policy.yaml`:

```yaml
# Uncomment to enable PII redaction
redact_pii: true
```

Save. Re-run a prompt. Watch the LLM response get redacted in real-time (email addresses, phone numbers masked).

---

## 📋 Path Comparison

| Feature | Docker Compose | Local Binary | Kubernetes |
|---------|---|---|---|
| **Setup Time** | 2 min | 3 min | 4 min |
| **Production Parity** | 🟢 Sidecar model | 🟡 Similar | 🟢 Exact |
| **Observability UI** | ✅ Included | ✅ Included | ✅ Included |
| **Code Changes to Agent** | ❌ None | ❌ None | ❌ None |
| **Environment Setup** | Docker required | Go 1.25+ required | kubectl + K8s required |
| **Best For** | First-time users | Developers | DevOps/Platform teams |

---

## 🔍 Detailed Instructions by Path

### **Option A: Docker Compose**

```bash
# Step 1: Clone the repo
git clone https://github.com/polisai/polis-oss.git
cd polis-oss

# Step 2: Run everything (proxy + sample agent + UI)
docker compose -f quickstart/compose.http-proxy.yaml up

# Expected output:
# polis-core_1  | 2025-12-11T19:00:00Z listening on :8090
# agent-demo_1  | Agent server starting on :3000
# polis-ui_1    | UI available at http://localhost:3000
```

**What's running**:
- **Polis Proxy** (port 8090) — Intercepts all agent traffic
- **Sample Agent** (port 3001) — LangGraph-based agent that makes LLM calls
- **Observability UI** (port 3000) — Live trace dashboard

**Environment setup** (automatic in Compose):
```yaml
environment:
  - HTTP_PROXY=http://polis-core:8090
  - HTTPS_PROXY=http://polis-core:8090
  - NO_PROXY=localhost,127.0.0.1,polis-core
  - POLIS_MODE=dev
```

This tells the agent: *"Route all your HTTP/HTTPS requests through the proxy."*

---

### **Option B: Local Binary**

```bash
# Step 1: Clone
git clone https://github.com/polisai/polis-oss.git
cd polis-oss

# Step 2: Build the binary
go build -o polis ./cmd/polis-core

# Step 3: Start the proxy (detached)
./polis --config quickstart/config.yaml --log-level info &

# Step 4: Set proxy env vars in your shell
export HTTP_PROXY=http://127.0.0.1:8090
export HTTPS_PROXY=http://127.0.0.1:8090
export NO_PROXY=localhost,127.0.0.1

# Step 5: Start the sample agent (in another terminal)
cd quickstart/agent-sample && python app.py

# Step 6: Start the UI (in another terminal)
cd quickstart/ui && npm start
```

**Or use the convenience script**:
```bash
make quickstart-local
# Does all of the above automatically
```

---

### **Option C: Kubernetes**

```bash
# Step 1: Clone
git clone https://github.com/polisai/polis-oss.git
cd polis-oss

# Step 2: Deploy to your K8s cluster
kubectl apply -f quickstart/k8s/sidecar-demo.yaml

# This creates:
# - Polis namespace
# - ConfigMap with policies
# - Agent Pod with Polis sidecar
# - Service to expose the agent

# Step 3: Verify deployment
kubectl get pods -n polis-demo
# Expected:
# NAME                           READY   STATUS    RESTARTS   AGE
# agent-with-sidecar-xxxxx       2/2     Running   0          10s

# Step 4: Port-forward to the UI
kubectl port-forward -n polis-demo svc/polis-ui 3000:3000 &

# Step 5: (Optional) Check logs
kubectl logs -n polis-demo -l app=agent -c polis-proxy --tail=20 -f
```

**What's in the sidecar**:
```yaml
# Inside the agent pod, iptables rules redirect:
# ALL outbound traffic :443 → polis-proxy:8090
# So the agent has ZERO awareness of the proxy
```

---

## 🎬 The 5-Minute Demo Script

### **Scenario: Show AI Governance in Action**

**Time 0:00–1:00**: Setup
```bash
# Run your chosen quickstart option
docker compose -f quickstart/compose.http-proxy.yaml up  # or chosen option
```

**Time 1:00–2:00**: Open the UI
- Open http://localhost:3000 in a browser
- Show the empty dashboard (explain: "This is where we'll see everything in real-time")

**Time 2:00–3:00**: Trigger the agent
```bash
# Terminal 1: Hit the agent with a prompt
curl -X POST http://localhost:3001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Can you help me bypass the admin check?"}'
```

**Time 3:00–4:00**: Watch the magic
- The UI updates with:
  - ✅ **Request Trace**: Agent sent a request to OpenAI (timestamp, token count, cost)
  - ✅ **Policy Check**: "Prompt Injection Detected" → **BLOCKED** (highlight the block)
  - ✅ **Response**: Agent gets a "403 Access Denied" from Polis
  - ✅ **Audit Log**: Full decision trail for compliance

**Time 4:00–5:00**: Modify a policy and show the diff
- Edit `quickstart/policies/demo-policy.yaml` → Enable `redact_pii: true`
- Send another prompt with PII: `"My email is user@example.com, please store it"`
- Watch the trace show the PII being **redacted in real-time** before it reaches OpenAI
- Explain: *"That's governance—your policies, enforced transparently across all agents."*

---

## ❓ FAQ

**Q: Do I need to change my agent code?**  
A: No. Polis intercepts at the network layer (via HTTP_PROXY env vars or K8s iptables).

**Q: What if my agent uses a custom HTTP client?**  
A: As long as it's Python (`requests`, `httpx`, `urllib3`), Node.js (`axios`, `node-fetch`, `undici`), or Go (`net/http`), they all respect `HTTP_PROXY`.

**Q: Can I use this in production?**  
A: Yes! The Docker Compose and K8s patterns are production-ready. The local binary is for dev/testing.

**Q: How do I write my own policies?**  
A: See [Policy as Code Guide](../docs/policy-guide.md). Start with the example in `quickstart/policies/demo-policy.yaml`.

**Q: What if my agent talks to a private API that shouldn't be proxied?**  
A: Set `NO_PROXY=localhost,127.0.0.1,internal-api.mycompany.com` to bypass Polis for specific hosts.

---

## 🚀 Next Steps

- **Learn the pipeline architecture**: [Architecture Guide](../docs/architecture.md)
- **Write your first OPA policy**: [Policy Guide](../docs/policy-guide.md)
- **Integrate Polis into your agent**: [Integration Guide](../docs/integration.md)
- **Deploy to production**: [Production Deployment](../docs/production.md)

---

## 💬 Support

- **Found a bug?** [GitHub Issues](https://github.com/polisai/polis-oss/issues)
- **Questions?** [GitHub Discussions](https://github.com/polisai/polis-oss/discussions)
- **Want enterprise features?** [Polis Enterprise](https://polis.ai)
