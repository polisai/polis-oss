# Polis - Secure AI Proxy (Open Source Core) (Archived)

> Archived onboarding draft migrated from `user-onbording/README-updated.md`. The canonical README is at the repo root.

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

## 🤝 Contributing

Polis OSS is open to contributions!

- **Found a bug?** [GitHub Issues](https://github.com/polisai/polis-oss/issues)
- **Have an idea?** [GitHub Discussions](https://github.com/polisai/polis-oss/discussions)
- **Want to contribute?** See `CONTRIBUTING.md`

