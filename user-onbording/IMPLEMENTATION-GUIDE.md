# Polis Onboarding Strategy — Complete Implementation Guide

## 📋 Overview

This document outlines the **frictionless multi-path onboarding strategy** for Polis, designed to get users to a "wow moment" (seeing Polis intercept and govern their agent traffic) within 5 minutes, regardless of their local setup.

---

## 🎯 The Goal

**Transform a GitHub visitor into a wowed user in < 5 minutes, without any code changes to their agent.**

### Success Metrics
- ✅ Time to first trace: < 2 minutes
- ✅ Time to "wow" moment: < 5 minutes  
- ✅ Bounce rate: < 5%
- ✅ Progression to own agent: 60% within 30 min
- ✅ Shareability: One-liner copy-paste setup

---

## 🚀 The Three Paths

Users land on the Polis GitHub page and are immediately presented with **three clear, mutually exclusive options**, each optimized for their setup:

### **Option A: Docker Compose** (Recommended, 2 minutes)
**For**: Users with Docker installed, want fastest setup  
**How**: `docker compose up`  
**Why**: No dependencies, works cross-platform, reproduces sidecar pattern  

**Flow**:
```
Landing page → Click "Docker Compose" → Copy command → Paste in terminal
→ Docker pulls images (1 min) → Services start (1 min) → UI loads
→ Send request → See traces → DONE!
```

**Key advantage**: Near-zero friction, near-zero failures

### **Option B: Local Binary** (3 minutes)
**For**: Developers who want to understand the code, have Go installed  
**How**: `make quickstart-local`  
**Why**: See Polis running locally, debug easier, no Docker overhead  

**Flow**:
```
Landing page → Click "Local Binary" → Copy command → Go installed?
→ Binary compiles (2 min) → Services start (1 min) → UI loads
→ Send request → See traces → DONE!
```

**Key advantage**: Educational, closer to development workflow

### **Option C: Kubernetes Sidecar** (4 minutes)
**For**: Platform teams, want production-parity in dev, have K8s cluster  
**How**: `kubectl apply`  
**Why**: True sidecar pattern, same architecture as production  

**Flow**:
```
Landing page → Click "Kubernetes" → Copy command → kubectl configured?
→ Pods deploy (2 min) → Become ready (1 min) → Port-forward (1 min)
→ Open UI → Send request → See traces → DONE!
```

**Key advantage**: Zero code differences between dev and prod

---

## 📂 Repo Structure

```
polis-oss/
├── QUICKSTART.md                    ← The main entry point
├── ONBOARDING-FLOW.md               ← Visual decision tree
├── quickstart.sh                    ← Interactive setup wizard
├── Makefile                         ← One-liner commands
│
├── README.md                        ← Updated with 3 quick paths
├── docs/
│   ├── architecture.md
│   ├── policy-guide.md
│   ├── integration.md
│   └── production.md
│
├── quickstart/
│   ├── compose.http-proxy.yaml      ← Option A: Docker (HTTP_PROXY)
│   ├── compose.transparent.yaml     ← Option A': Docker (iptables)
│   ├── config.yaml                  ← Polis configuration
│   ├── pipeline.yaml                ← Default pipeline
│   ├── policies/
│   │   └── demo-policy.yaml         ← Example policies
│   ├── k8s/
│   │   └── sidecar-demo.yaml        ← Option C: K8s manifest
│   ├── agent-sample/                ← Sample LangGraph agent
│   │   └── Dockerfile
│   │   └── app.py
│   └── ui/                          ← Observability dashboard
│       └── Dockerfile
│       └── package.json
│
├── cmd/
│   └── polis-core/
│       └── main.go
│
└── .github/
    └── README.md
```

---

## 🎬 User Journeys (by Choice)

### **Journey A: Docker Compose**

```
User lands on GitHub
│
├─ Sees 3 options (A/B/C)
├─ Clicks "Docker Compose"
├─ Reads 2-line instruction
├─ Copies command and runs:
│  docker compose -f quickstart/compose.http-proxy.yaml up
│
├─ Terminal output:
│  polis-core_1   | listening on :8090
│  agent-demo_1   | Agent ready on :3001
│  polis-ui_1     | UI ready on :3000
│
├─ Waits 1-2 min for images to pull/start
├─ Opens http://localhost:3000
├─ Sees the Observability UI (empty traces)
│
├─ Sends request:
│  curl -X POST http://localhost:3001/chat \
│    -H "Content-Type: application/json" \
│    -d '{"message": "What is AI governance?"}'
│
├─ 🎉 SEES MAGIC:
│  • Trace appears in real-time
│  • Shows LLM request/response
│  • Shows policy decisions
│  • Shows tokens and cost
│
├─ Edits demo-policy.yaml: redact_pii: true
├─ Sends another request with "user@example.com"
├─ Watches email get redacted in real-time
│
└─ ✅ HOOKED! (5 min elapsed)
```

**Success**: 95% of users complete this path
**Time**: 5 min total (1 min setup, 4 min usage)

---

### **Journey B: Local Binary**

```
User lands on GitHub
│
├─ Sees 3 options (A/B/C)
├─ Clicks "Local Binary"
├─ Checks if Go 1.25+ is installed
│  ├─ Not installed? → Helpful link to golang.org
│  └─ Installed? → Continue
│
├─ Runs: make quickstart-local
│  (Makefile orchestrates: build → start proxy → start agent → start UI)
│
├─ Terminal output shows each service starting
├─ Waits 2-3 min for compilation and startup
│
├─ Opens http://localhost:3000
├─ REST IS IDENTICAL TO JOURNEY A
│
└─ ✅ HOOKED! (5 min elapsed)
```

**Success**: 80% of users complete this path (some need to install Go)
**Time**: 5 min total (2 min setup, 3 min usage)

---

### **Journey C: Kubernetes**

```
User lands on GitHub
│
├─ Sees 3 options (A/B/C)
├─ Clicks "Kubernetes"
├─ Checks if kubectl is configured
│  ├─ Not configured? → Link to K8s setup docs
│  └─ Configured? → Continue
│
├─ Runs: kubectl apply -f quickstart/k8s/sidecar-demo.yaml
│
├─ Runs: kubectl wait ... --timeout=60s
│
├─ Runs: kubectl port-forward svc/polis-ui 3000:3000
│
├─ Waits 2-3 min for pods to pull images and be ready
│
├─ Opens http://localhost:3000
├─ REST IS IDENTICAL TO JOURNEYS A/B
│
└─ ✅ HOOKED! (5 min elapsed, production-parity achieved)
```

**Success**: 85% of users complete this path (some need K8s cluster)
**Time**: 4-5 min total (2-3 min setup, 2-3 min usage)

---

## 🎯 The "Wow" Moment (Universal, all Paths)

**What users see when they send their first request:**

### **Before** (nothing in the UI)
- Empty traces dashboard
- Explanation: "Send a request below to see Polis in action"

### **After** (magic happens)
Real-time trace showing:

1. **Request Details**
   - Timestamp, endpoint, method, status code
   - Request body (with any PII masked)
   - Time taken: 1234ms

2. **Policy Execution**
   - ✓ WAF Check: Prompt injection? No.
   - ✓ DLP Check: Sensitive data? Found email, redacted.
   - ✓ Policy Enforcement: Allowed.

3. **LLM Interaction**
   - ▶ Request to OpenAI
   - ◀ Response received
   - Tokens: 156 prompt, 245 completion
   - Estimated cost: $0.00127

4. **Audit Trail**
   - Full request/response (with redactions applied)
   - All policy decisions logged
   - Exportable for compliance

### **Then** (the real magic)
User edits `quickstart/policies/demo-policy.yaml`:
```yaml
patterns:
  - name: Email
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    replace_with: "[EMAIL_REDACTED]"
    enabled: true  # Toggle this to enable PII redaction
```

Sends another request with: `"Contact me at alice@example.com"` 

**Watches in real-time** as the email gets redacted to `[EMAIL_REDACTED]` in both request and response.

**Realization**: "Oh wow, this proxy can see and modify everything in real-time without touching my code!"

---

## 🔧 Implementation Details

### **Entry Point: README.md**

Updated README **immediately** shows three commands:

```markdown
## 🚀 Get Started in 5 Minutes

### Option A: Docker Compose (Recommended)
\`\`\`bash
docker compose -f quickstart/compose.http-proxy.yaml up
\`\`\`

### Option B: Local Binary
\`\`\`bash
make quickstart-local
\`\`\`

### Option C: Kubernetes
\`\`\`bash
kubectl apply -f quickstart/k8s/sidecar-demo.yaml
\`\`\`
```

### **Interactive Option: Shell Script**

For users who want guidance, `./quickstart.sh`:
- Detects system capabilities (Docker, Go, kubectl)
- Shows which options are available
- Walks through chosen path with colored output
- Provides helpful error messages if setup fails

### **Detailed Guide: QUICKSTART.md**

Full instructions for each path with:
- Prerequisites checklist
- Step-by-step instructions
- Example curl commands
- What to expect at each stage
- Next steps (move to own agent)

---

## 📊 Traffic Flow & Architecture

### **Option A/B: HTTP_PROXY Model**

```
Agent Code
    │ "I'm calling api.openai.com"
    ▼
HTTP Client (respects HTTP_PROXY env var)
    │ "Wait, HTTP_PROXY is set to localhost:8090"
    ▼
Polis Core (:8090) [Middleware]
    │ Sees: POST https://api.openai.com/v1/chat/completions
    ├─ Log it
    ├─ Check for injection → No
    ├─ Check for PII → Found, redact
    ├─ Forward to real endpoint
    │
    ▼
OpenAI API
    │ Response
    ▼
Polis Core [Middleware]
    │ Sees response
    ├─ Check for PII → Redact again
    ├─ Track metrics
    ├─ Log it
    │
    ▼
Agent Code (receives response)
```

**Why it works**:
- Python `requests`, `httpx`, `urllib3` respect HTTP_PROXY
- Node `axios`, `node-fetch`, `undici` respect HTTP_PROXY
- Go `net/http` respects HTTP_PROXY
- No code changes needed in agent

### **Option C: iptables Model**

```
Agent Code
    │ "I'm calling api.openai.com:443"
    ▼
TCP Socket
    │ "Where am I going?"
    ▼
Kernel iptables Rules (transparent proxy)
    │ OUTPUT chain: "Redirect to localhost:8090"
    ▼
Polis Core (:8090) [Transparent Proxy]
    │ "I see you wanted api.openai.com:443, I'll handle that"
    │ (Uses SO_ORIGINAL_DST to learn real destination)
    │
    ├─ Log, check, redact, forward
    │
    ▼
OpenAI API
    │ Same as Option A from here
    ▼
Polis Core
    │ Response processing
    ▼
Agent Code
```

**Why it's special**:
- Agent has ZERO awareness of proxy
- No HTTP_PROXY env vars needed
- Same as production sidecar
- True "transparent" proxy

---

## 🎨 UI/UX Considerations

### **The Observability UI**

**Home/Traces Page**:
- Initially shows: "Send a request to see traces appear in real-time"
- After first request: Timeline of all requests, color-coded by outcome
  - Green: Allowed
  - Orange: Modified (PII redacted)
  - Red: Blocked (injection detected)

**Trace Details Page**:
- Timeline view of request → policies → LLM → response
- Side-by-side request/response (redacted values highlighted)
- Policy decisions and why (e.g., "Email redacted: user@example.com → [EMAIL_REDACTED]")
- Metrics: latency, tokens, cost

**Policies Page**:
- Live editor for `demo-policy.yaml`
- Save button → Polis reloads (hot-reload in dev)
- Test area to validate policies before deploying

---

## 📈 Success Metrics & Analytics

Track these to measure onboarding effectiveness:

1. **Time to First Trace**: Median < 2 min
2. **Time to "Wow"**: Median < 5 min
3. **Bounce Rate**: < 5% (% of users who exit after landing)
4. **Path Distribution**: ~60% A, ~20% B, ~20% C
5. **Errors by Path**: Track failures per path, improve those
6. **Progression Rate**: % of users who read integration docs within 5 min of setup
7. **Share Rate**: % of users who copy/share the setup command

---

## 🔄 Continuous Improvement Loop

**Monthly Reviews**:
- Analyze which path has highest success rate
- Identify most common errors
- Update error messages and docs
- Monitor user feedback (GitHub issues, discussions)

**Quarterly Updates**:
- Add new example policies (e.g., cost limits, rate limiting)
- Improve UI based on user behavior
- Expand integration guides for more frameworks

---

## 🚀 Future Enhancements

### **Phase 2: Personalized Paths**
- Detect framework from git clone history
- Offer framework-specific policies (e.g., LangGraph rate limiting)

### **Phase 3: Production Migration**
- "One-click" move from Docker Compose to K8s
- Pre-configured production pipeline templates

### **Phase 4: Community**
- Curated policy library shared by users
- Showcase examples from real deployments

---

## 📝 Checklist for Implementation

- [ ] Update main README.md with 3 quick paths
- [ ] Create QUICKSTART.md with detailed instructions
- [ ] Create ONBOARDING-FLOW.md with visual flowchart
- [ ] Create docker-compose.http-proxy.yaml
- [ ] Create docker-compose.transparent.yaml (optional alt)
- [ ] Create k8s/sidecar-demo.yaml
- [ ] Create quickstart.sh (interactive wizard)
- [ ] Create Makefile with quickstart targets
- [ ] Create sample policies in quickstart/policies/
- [ ] Create sample agent (LangGraph-based)
- [ ] Create observability UI
- [ ] Test all 3 paths on different systems
- [ ] Document error messages and recovery paths
- [ ] Set up analytics to track onboarding flow
- [ ] Create video walkthrough (optional but high-value)
- [ ] Link to integration guides for common frameworks

---

## 📞 Support During Onboarding

**For each path, provide**:
- Clear error messages (not generic stack traces)
- Helpful suggestions ("Docker not found? Install from...")
- Recovery commands ("Stuck? Try: docker compose down -v && docker compose up")
- Quick links to docs and support

**Fallback**: If none of the 3 paths work for a user:
- Link to full documentation
- GitHub discussions (not issues)
- Community Slack channel

---

## 🎓 Learning Path After "Wow"

Once a user is hooked (5 min), guide them through:

1. **Understanding Polis** (5 min read)
   - Architecture overview
   - How pipelines work

2. **Integration to Own Agent** (10 min)
   - Choose their framework
   - Run with Polis proxy
   - See their agent's traces

3. **Writing First Policy** (15 min)
   - Start with template
   - Add a custom rule
   - Test and iterate

4. **Production Deployment** (30 min read)
   - K8s sidecar setup
   - Multi-agent governance
   - Scaling considerations

---

This strategy prioritizes **reducing friction to the "wow moment"** while providing multiple paths for different setups. The goal is to create momentum: onboarded → wowed → hooked → committed.
