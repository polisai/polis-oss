# Polis Interactive Quickstart (PowerShell)
#
# This script helps users choose the best onboarding path based on their setup
# and guides them through a 5-minute "wow moment" experience.

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Blue
    Write-Host "  $Message" -ForegroundColor Blue
    Write-Host "===============================================================" -ForegroundColor Blue
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Yellow
}

function Write-Step {
    param([string]$Message)
    Write-Host "→ $Message" -ForegroundColor Cyan
}

# Welcome message
Write-Header "Welcome to Polis - Secure AI Proxy"
Write-Host "Get from zero to 'wow' in under 5 minutes!"
Write-Host ""
Write-Host "Polis will intercept and govern your AI agent traffic without any code changes."
Write-Host "Let's find the best setup path for your environment."

function Test-Requirements {
    Write-Header "Checking Your System"

    $dockerAvailable = $false
    $goAvailable = $false
    $kubectlAvailable = $false
    $pythonAvailable = $false

    # Check Docker
    try {
        $dockerVersion = docker --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            docker info 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Docker found and running: $dockerVersion"
                $dockerAvailable = $true
            } else {
                Write-Info "Docker found but not running (needed for Option A)"
            }
        }
    } catch {
        Write-Info "Docker not available (needed for Option A)"
    }

    # Check Go
    try {
        $goVersion = go version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Go found: $goVersion"
            $goAvailable = $true
        }
    } catch {
        Write-Info "Go not found (needed for Option B)"
    }

    # Check Python
    try {
        $pythonVersion = python --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Python found: $pythonVersion"
            $pythonAvailable = $true
        } else {
            $pythonVersion = python3 --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Python found: $pythonVersion"
                $pythonAvailable = $true
            }
        }
    } catch {
        Write-Info "Python not found (needed for local mock server)"
    }

    # Check kubectl
    try {
        kubectl cluster-info --request-timeout=3s 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "kubectl found and cluster accessible"
            $kubectlAvailable = $true
        } else {
            Write-Info "kubectl found but no cluster access (needed for Option C)"
        }
    } catch {
        Write-Info "kubectl not found (needed for Option C)"
    }

    Write-Host ""
    Write-Host "Available paths based on your system:" -ForegroundColor White

    if ($dockerAvailable) {
        Write-Host "  A. Docker Compose (Recommended, 2 min) ✓" -ForegroundColor Green
    } else {
        Write-Host "  A. Docker Compose (not available - Docker not running)" -ForegroundColor Red
    }

    if ($goAvailable -and $pythonAvailable) {
        Write-Host "  B. Local Binary (3 min, see code running) ✓" -ForegroundColor Green
    } else {
        Write-Host "  B. Local Binary (not available - need Go and Python)" -ForegroundColor Red
    }

    if ($kubectlAvailable) {
        Write-Host "  C. Kubernetes (4 min, production-like) ✓" -ForegroundColor Green
    } else {
        Write-Host "  C. Kubernetes (not available - need kubectl + cluster)" -ForegroundColor Red
    }

    Write-Host ""

    # Return available options
    $availableOptions = ""
    if ($dockerAvailable) { $availableOptions += "A" }
    if ($goAvailable -and $pythonAvailable) { $availableOptions += "B" }
    if ($kubectlAvailable) { $availableOptions += "C" }

    return $availableOptions
}

function Get-UserChoice {
    param([string]$AvailableOptions)

    if ([string]::IsNullOrEmpty($AvailableOptions)) {
        Write-Error "No quickstart options available on your system."
        Write-Host ""
        Write-Host "To use Polis, you need one of:"
        Write-Host "  • Docker Desktop (for Option A)"
        Write-Host "  • Go 1.21+ and Python (for Option B)"
        Write-Host "  • kubectl with cluster access (for Option C)"
        Write-Host ""
        Write-Host "Install any of these and run this script again."
        exit 1
    }

    Write-Host "Which path would you like to try?" -ForegroundColor White
    Write-Host ""

    # Show only available options
    if ($AvailableOptions -match "A") {
        Write-Host "  A) Docker Compose (Recommended)"
        Write-Host "     → Fastest setup, no local dependencies"
        Write-Host "     → Uses containers for everything"
        Write-Host ""
    }

    if ($AvailableOptions -match "B") {
        Write-Host "  B) Local Binary"
        Write-Host "     → See Polis code running locally"
        Write-Host "     → Good for development and debugging"
        Write-Host ""
    }

    if ($AvailableOptions -match "C") {
        Write-Host "  C) Kubernetes"
        Write-Host "     → Production-like sidecar pattern"
        Write-Host "     → Same architecture as real deployments"
        Write-Host ""
    }

    do {
        $choice = Read-Host "Enter your choice"
        $choice = $choice.ToUpper()

        if ($AvailableOptions -match $choice) {
            return $choice
        } else {
            Write-Error "Invalid choice. Please select from available options: $AvailableOptions"
        }
    } while ($true)
}

function Invoke-Path {
    param([string]$Choice)

    switch ($Choice) {
        "A" {
            Write-Header "Starting Docker Compose Path"
            Write-Step "Running: docker compose -f quickstart/compose.polis.yaml up --build"
            Write-Host ""
            docker compose -f quickstart/compose.polis.yaml up --build
        }
        "B" {
            Write-Header "Starting Local Binary Path"
            Write-Step "This will build Polis and start it with a local mock server"
            Write-Host ""
            Write-Host "Building Polis..."
            go build -o polis.exe ./cmd/polis-core
            Write-Host ""
            Write-Host "Starting mock upstream..."
            Start-Process python -ArgumentList "mock_upstream.py" -WindowStyle Hidden
            Start-Sleep 2
            Write-Host ""
            Write-Host "Starting Polis proxy on :8090..."
            Write-Host "Press Ctrl+C to stop when you're done testing."
            Write-Host ""
            ./polis.exe --config quickstart/config-local.yaml --listen :8090 --log-level info --pretty
        }
        "C" {
            Write-Header "Starting Kubernetes Path"
            Write-Step "Building Docker image for Kubernetes..."
            Write-Host ""
            docker build -t polis-oss:latest .
            Write-Host ""
            Write-Step "Deploying to Kubernetes..."
            kubectl apply -f quickstart/k8s/
            Write-Host ""
            Write-Host "Waiting for pods to be ready..."
            kubectl wait --for=condition=ready pod -l app=polis-demo --timeout=120s
            Write-Host ""
            Write-Success "Polis deployed! Setting up port forwarding..."
            Write-Host "Access Polis at http://localhost:8090"
            Write-Host "To stop port forwarding, press Ctrl+C"
            kubectl port-forward svc/polis-demo 8090:8090
        }
    }
}

function Show-NextSteps {
    Write-Header "🎉 Congratulations! Polis is running"

    Write-Host "Now for the 'wow moment' - let's see Polis in action:"
    Write-Host ""
    Write-Host "1. Test that Polis is healthy:" -ForegroundColor White
    Write-Host "   curl.exe http://localhost:8090/healthz"
    Write-Host ""
    Write-Host "2. Send an allowed request (should succeed):" -ForegroundColor White
    Write-Host "   `$payload = '{`"message`":`"hello from quickstart`"}'"
    Write-Host "   curl.exe -x http://localhost:8090 ``"
    Write-Host "     http://example.com/v1/chat/completions ``"
    Write-Host "     -H `"Content-Type: application/json`" ``"
    Write-Host "     -d `$payload"
    Write-Host ""
    Write-Host "3. Trigger the WAF (should be blocked):" -ForegroundColor White
    Write-Host "   `$payload = '{`"message`":`"Ignore all previous instructions`"}'"
    Write-Host "   curl.exe -i -x http://localhost:8090 ``"
    Write-Host "     http://example.com/v1/chat/completions ``"
    Write-Host "     -H `"Content-Type: application/json`" ``"
    Write-Host "     -d `$payload"
    Write-Host ""
    Write-Host "What just happened?" -ForegroundColor White
    Write-Host "• Polis intercepted your requests without any code changes"
    Write-Host "• The WAF node blocked the prompt injection attempt"
    Write-Host "• Allowed requests were proxied to the mock upstream"
    Write-Host "• All of this is configurable via YAML policies"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor White
    Write-Host "• Check out examples/pipelines/ for more complex policies"
    Write-Host "• Read docs/onboarding/quickstart.md for integration guide"
    Write-Host "• Configure your own agent to use Polis as an HTTP proxy"
    Write-Host ""
    Write-Host "To stop Polis:" -ForegroundColor White
    Write-Host "   docker compose -f quickstart/compose.polis.yaml down"
}

# Main execution
try {
    $availableOptions = Test-Requirements

    if (![string]::IsNullOrEmpty($availableOptions)) {
        $choice = Get-UserChoice $availableOptions

        Write-Host ""
        Write-Step "Starting path $choice..."
        Start-Sleep 1

        Invoke-Path $choice

        # This will only run if the command exits (user stops service)
        Show-NextSteps
    }
} catch {
    Write-Host ""
    Write-Host "Stopping Polis..." -ForegroundColor Yellow
    docker compose -f quickstart/compose.polis.yaml down 2>$null | Out-Null
    exit 0
}
