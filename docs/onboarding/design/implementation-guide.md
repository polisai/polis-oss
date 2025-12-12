# Polis Onboarding Strategy — Complete Implementation Guide (Archived)

> Archived onboarding draft migrated from `user-onbording/IMPLEMENTATION-GUIDE.md`. This describes an expanded onboarding bundle (UI + sample agent) which is not included in the OSS core.

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

### **Option B: Local Binary** (3 minutes)
**For**: Developers who want to understand the code, have Go installed
**How**: `make quickstart-local`
**Why**: See Polis running locally, debug easier, no Docker overhead

### **Option C: Kubernetes Sidecar** (4 minutes)
**For**: Platform teams, want production-parity in dev, have K8s cluster
**How**: `kubectl apply`
**Why**: True sidecar pattern, same architecture as production

---

## 📂 Repo Structure

```
polis-oss/
├── QUICKSTART.md
├── ONBOARDING-FLOW.md
├── quickstart.sh
├── Makefile
│
├── README.md
├── docs/
│   ├── architecture.md
│   ├── policy-guide.md
│   ├── integration.md
│   └── production.md
│
├── quickstart/
│   ├── compose.http-proxy.yaml
│   ├── compose.transparent.yaml
│   ├── config.yaml
│   ├── pipeline.yaml
│   ├── policies/
│   │   └── demo-policy.yaml
│   ├── k8s/
│   │   └── sidecar-demo.yaml
│   ├── agent-sample/
│   └── ui/
│
├── cmd/
│   └── polis-core/
│       └── main.go
└── .github/
```

---

## 🎬 User Journeys (by Choice)

### **Journey A: Docker Compose**

```
User lands on GitHub
│
├─ Sees 3 options (A/B/C)
├─ Clicks "Docker Compose"
├─ Copies command and runs:
│  docker compose -f quickstart/compose.http-proxy.yaml up
│
├─ Terminal output:
│  polis-core_1   | listening on :8090
│  agent-demo_1   | Agent ready on :3001
│  polis-ui_1     | UI ready on :3000
│
└─ ✅ HOOKED!
```

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
└─ ✅ HOOKED! (5 min elapsed)
```

### **Journey C: Kubernetes**

```
User lands on GitHub
│
├─ Sees 3 options (A/B/C)
├─ Clicks "Kubernetes"
├─ Checks if kubectl is configured
│
├─ Runs: kubectl apply -f quickstart/k8s/sidecar-demo.yaml
├─ Runs: kubectl wait ... --timeout=60s
├─ Runs: kubectl port-forward svc/polis-ui 3000:3000
│
└─ ✅ HOOKED!
```

---

## 🎯 The "Wow" Moment (Universal, all Paths)

(See original draft for the full expanded narrative.)

