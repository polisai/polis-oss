# Polis OSS - Setup Guide

Welcome to **Polis OSS**, the open-source specific edition of the Secure AI Proxy. This guide will walk you through the process of setting up the proxy from source code to a running "Hello World" instance.

## 1. Prerequisites

Before you begin, ensure you have the following installed on your system:

*   **Go** (Version 1.25 or later): Required to compile the code. [Download Go](https://go.dev/dl/)
*   **Git**: Required to clone the repository. [Download Git](https://git-scm.com/downloads)
*   **PowerShell 7** (Optional but recommended for Windows): Useful for running the build scripts.

## 2. Installation

Since this is the Open Source version, we will build the binary from the source code.

> [!NOTE]
> **Production Note:** In a managed or enterprise environment, you would typically download a pre-compiled binary from the [Releases] page or pull a Docker image. For this OSS version, compiling from source gives you the latest changes and full control.

### Step 2.1: Clone the Repository

Open your terminal or command prompt and run:

```bash
git clone https://github.com/polisai/polis-oss.git
cd polis-oss
```

### Step 2.2: Build the Binary

We provide a `build.ps1` helper script for convenience, but you can also use standard Go commands.

**Option A: Using the Build Script (Recommended)**

```powershell
./build.ps1 build
```

This commands compiles the generic `proxy` binary.

**Option B: Standard Go Build**

```bash
go mod download
go build -o polis-core.exe ./cmd/polis-core/main.go
# OR for the main proxy entry point
go build -o proxy.exe ./cmd/proxy/main.go
```

After building, you should see a `proxy.exe` (or `polis-core.exe`) file in your directory.

## 3. "Hello World" - Running the Proxy

Now that you have the binary, let's start it up to ensure everything is working.

### Step 3.1: Environment Setup

The proxy relies on a configuration file. By default, it looks for `config.yaml` in the current directory or `config/`.

Check that you have a basic `config.yaml` and `pipeline.yaml` available. The repo comes with defaults in the root or `config/` folder.

### Step 3.2: Start the Server

Run the binary:

```bash
./proxy.exe
```

You should see startup logs indicating the server is listening, likely on port `8090` (depending on your config).

```json
{"level":"info","time":"...","message":"Starting server on :8090"}
```

### Step 3.3: Verify Connectivity

Open a new terminal and send a health check request (assuming default admin port configuration) or a simple proxy request.

```bash
curl http://localhost:8090/health
```

If you receive a `200 OK` response, congratulations! Your Polis OSS proxy is up and running.

## Next Steps

Now that your proxy is running, it's time to configure it to do something useful. Proceed to the [Configuration Guide](./02_configuration_guide.md) to learn how to set up pipelines and policies.
