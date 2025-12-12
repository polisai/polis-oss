# Polis Agent Proxy — 5-Minute Quickstart (Archived)

> Archived onboarding draft migrated from `user-onbording/QUICKSTART.md`. This document references assets (UI, sample agent, Prometheus, admin port) that are not included in the OSS core.

---

## 🚀 Your Options

### **Option A: Docker Compose (Recommended)**
**Best for**: Fastest setup, no system dependencies, reproduces production sidecar pattern
**Time**: ~2 minutes
**Works on**: macOS, Windows, Linux

```bash
# Clone + Run (one command)
git clone https://github.com/polisai/polis-oss.git && cd polis-oss && docker compose -f quickstart/compose.polis.yaml up
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
|---|---|---|---|
| **Setup Time** | 2 min | 3 min | 4 min |
| **Production Parity** | 🟢 Sidecar model | 🟡 Similar | 🟢 Exact |
| **Observability UI** | ✅ Included | ✅ Included | ✅ Included |
| **Code Changes to Agent** | ❌ None | ❌ None | ❌ None |
| **Environment Setup** | Docker required | Go 1.25+ required | kubectl + K8s required |
| **Best For** | First-time users | Developers | DevOps/Platform teams |

---

## ❓ FAQ

**Q: Do I need to change my agent code?**
A: No. Polis intercepts at the network layer (via HTTP_PROXY env vars or K8s iptables).

**Q: What if my agent uses a custom HTTP client?**
A: As long as it's Python (`requests`, `httpx`, `urllib3`), Node.js (`axios`, `node-fetch`, `undici`), or Go (`net/http`), they all respect `HTTP_PROXY`.

**Q: Can I use this in production?**
A: Yes! The Docker Compose and K8s patterns are production-ready. The local binary is for dev/testing.

**Q: How do I write my own policies?**
A: See `docs/policy-guide.md`. Start with the example in `quickstart/policies/demo-policy.yaml`.

**Q: What if my agent talks to a private API that shouldn't be proxied?**
A: Set `NO_PROXY=localhost,127.0.0.1,internal-api.mycompany.com` to bypass Polis for specific hosts.

---

## 🚀 Next Steps

- **Learn the pipeline architecture**: `docs/architecture.md`
- **Write your first OPA policy**: `docs/policy-guide.md`
- **Integrate Polis into your agent**: `docs/integration.md`
- **Deploy to production**: `docs/production.md`

---

## 💬 Support

- **Found a bug?** https://github.com/polisai/polis-oss/issues
- **Questions?** https://github.com/polisai/polis-oss/discussions
- **Want enterprise features?** https://polis.ai

