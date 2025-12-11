# Polis - Secure AI Proxy (Open Source Core)

> **Get started in 5 minutes.** Choose your path, run one command, watch Polis govern your agents in real-time.

---

## 🚀 Quick Start (Pick Your Path)

### **A. Docker Compose** ← Start here (2 min)
```bash
git clone https://github.com/polisai/polis-oss.git && cd polis-oss
docker compose -f quickstart/compose.http-proxy.yaml up
# Open http://localhost:3000
```

### **B. Local Binary** (3 min)
```bash
git clone https://github.com/polisai/polis-oss.git && cd polis-oss
make quickstart-local
# Open http://localhost:3000
```

### **C. Kubernetes Sidecar** (4 min)
```bash
git clone https://github.com/polisai/polis-oss.git && cd polis-oss
make quickstart-k8s
# Open http://localhost:3000
```

**👉 [Detailed Quickstart Guide →](./QUICKSTART.md)**

---

## ✨ The 5-Minute "Wow" Moment

After running your chosen quickstart:

1. **Open the UI** → http://localhost:3000
2. **Send a prompt**:
   ```bash
   curl -X POST http://localhost:3001/chat \
     -H "Content-Type: application/json" \
     -d '{"message": "What is AI governance?"}'
   ```
3. **Watch in real-time**:
   - ✅ Agent request intercepted
   - ✅ LLM call captured
   - ✅ Policies applied
   - ✅ PII redacted
   - ✅ Full audit trail

4. **Toggle a policy** → Edit `quickstart/policies/demo-policy.yaml` → See live redaction

---

## 🎯 What You Get

Polis is a high-performance, protocol-aware proxy for AI agents:

- **🔒 Zero-Trust Governance**: Enforce policies on every LLM call
- **📊 Real-Time Observability**: See all agent traffic with full traces
- **🛡️ Built-in Security**: Prompt injection detection, PII redaction, WAF
- **⚙️ Pipeline Architecture**: DAG-based request processing flows
- **📜 Policy-as-Code**: Write fine-grained rules in OPA Rego
- **🔌 Protocol-Aware**: Native HTTP/1.1 and HTTP/2 support
- **📡 OpenTelemetry**: First-class tracing and metrics

---

## 🏗️ Architecture

```
Your Agent
    ↓
    ├─ All outbound traffic (HTTP_PROXY or iptables)
    ↓
Polis Core (:8090)
    ├─ [Pipeline DAG Executor]
    │   ├─ Authentication
    │   ├─ WAF (Prompt Injection Detection)
    │   ├─ DLP (PII Redaction)
    │   ├─ OPA Policy Enforcement
    │   └─ Metrics & Auditing
    ├─ [Observability Engine]
    │   ├─ Request/Response Tracing
    │   ├─ Policy Decision Logs
    │   └─ Cost Tracking
    ↓
LLM API / External Service
    ↓
Response → Polis → Your Agent
```

See [Architecture Guide](./docs/architecture.md) for details.

---

## 📚 Key Features

### **1. Pipeline-as-Code (DAG Architecture)**

Define your governance flows in YAML:

```yaml
nodes:
  - id: check_injection
    type: waf
    config:
      rules:
        - name: "Prompt Injection"
          pattern: "(?i)(ignore.*instructions)"
          action: block
    on:
      success: check_pii
      failure: deny

  - id: check_pii
    type: dlp
    config:
      redact_patterns: [email, ssn, phone]
    on:
      success: forward_llm
      failure: forward_llm

  - id: forward_llm
    type: egress
    config:
      upstream_url: "https://api.openai.com/v1"
```

### **2. Policy-as-Code (OPA Integration)**

Write fine-grained authorization in Rego:

```rego
package polis.authz

# Only allow GPT-4 for authorized agents
allow {
    input.model == "gpt-4"
    input.agent_id in authorized_agents
}

deny[msg] {
    input.model == "gpt-4-turbo"
    msg := "gpt-4-turbo requires approval"
}
```

### **3. Multi-Layer Security**

- **WAF**: Detect prompt injection, jailbreaks, prompt attacks
- **DLP**: Redact PII, API keys, sensitive data in real-time
- **Auth**: API key validation, agent identity verification
- **Audit**: Complete request/response logs for compliance

### **4. Full Observability**

- Real-time request traces (latency, tokens, cost)
- Policy decision logs (what was blocked/redacted and why)
- Metrics: OpenTelemetry OTLP export
- Dashboards: Built-in UI for traces and metrics

---

## 🚢 Deployment Options

| Environment | Setup | Use Case |
|-------------|-------|----------|
| **Docker Compose** | `docker compose up` | Local dev, quick demos |
| **Local Binary** | `go build` + env vars | Single-machine dev |
| **Kubernetes** | Sidecar pattern (iptables) | Production, true sidecar |
| **Cloud Functions** | Wrapper pattern | AWS Lambda, GCP Functions |

---

## 📖 Documentation

- **[Quick Start Guide](./QUICKSTART.md)** – 5-minute setup
- **[Onboarding Flow](./ONBOARDING-FLOW.md)** – Visual decision tree
- **[Configuration Guide](./docs/config-guide.md)** – Full YAML schema
- **[Policy Guide](./docs/policy-guide.md)** – Write OPA policies
- **[Integration Guide](./docs/integration.md)** – Add to your agents
- **[Production Deployment](./docs/production.md)** – K8s, scaling, HA
- **[API Reference](./docs/api-reference.md)** – Endpoints and webhooks

---

## ✅ What's Included (OSS Core)

- Protocol-aware proxy (HTTP/1.1, HTTP/2)
- DAG pipeline executor
- Built-in nodes: auth, waf, dlp, policy, egress, logging
- OPA integration for policy enforcement
- OpenTelemetry tracing
- Observability UI
- Sample agent (LangGraph-based)
- Docker and K8s deployment configs
- Comprehensive policy examples

---

## 🚀 Getting Started

1. **Clone the repo**:
   ```bash
   git clone https://github.com/polisai/polis-oss.git
   cd polis-oss
   ```

2. **Choose your quickstart** (see top of this README):
   - Docker Compose (easiest)
   - Local Binary (if you have Go)
   - Kubernetes (for production patterns)

3. **Open the UI** and send your first request

4. **Explore the examples** in `quickstart/`

5. **Read the [Configuration Guide](./docs/config-guide.md)** to customize

---

## 🔌 Integration with Your Agent

To use Polis with your existing agent:

### **Option 1: HTTP Proxy (Easiest)**
```bash
export HTTP_PROXY=http://polis:8090
export HTTPS_PROXY=http://polis:8090
python your_agent.py  # All requests go through Polis
```

### **Option 2: Kubernetes Sidecar (Production)**
```yaml
spec:
  containers:
    - name: agent
      # No proxy config needed; iptables handles it
    - name: polis-proxy
      # Runs as sidecar, transparently intercepts traffic
```

See [Integration Guide](./docs/integration.md) for language-specific examples (Python, Node.js, Go).

---

## 🎯 Use Cases

- **AI Governance**: Enforce policies on all LLM calls across your organization
- **Compliance**: Audit trails, redaction rules for GDPR/HIPAA
- **Security**: Prompt injection detection, jailbreak prevention
- **Observability**: Full tracing and cost tracking for all agent interactions
- **Cost Control**: Monitor and limit token usage, API spend
- **Multi-Tenancy**: Route different agents through different policies

---

## 🤝 Contributing

Polis OSS is open to contributions!

- **Found a bug?** [GitHub Issues](https://github.com/polisai/polis-oss/issues)
- **Have an idea?** [GitHub Discussions](https://github.com/polisai/polis-oss/discussions)
- **Want to contribute?** See [CONTRIBUTING.md](./CONTRIBUTING.md)

---

## 📜 License

Polis OSS Core is licensed under the [Apache 2.0 License](./LICENSE).

---

## 🏢 Polis Enterprise

Need advanced features?

- **Multi-tenant Control Plane** for managing hundreds of agents
- **RBAC & SSO** for enterprise governance
- **Dynamic policy reconfiguration** without downtime
- **Advanced analytics** and compliance dashboards
- **24/7 support** and SLA guarantees

[Learn more about Polis Enterprise →](https://polis.ai)

---

## 🚀 Next Steps

1. **Run the quickstart** (5 minutes)
2. **Explore the examples** in `quickstart/`
3. **Read the [Policy Guide](./docs/policy-guide.md)** to write your first rule
4. **Integrate with your agent** using the [Integration Guide](./docs/integration.md)
5. **Deploy to production** following the [Production Guide](./docs/production.md)

**Questions?** Check the [FAQ](./docs/faq.md) or open a [GitHub Discussion](https://github.com/polisai/polis-oss/discussions).

---

Made with ❤️ by [Odra Labs](https://odra-labs.com)
