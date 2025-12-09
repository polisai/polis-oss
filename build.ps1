# Build script for Secure AI Proxy (PowerShell alternative to Makefile)

param(
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"

$BuildDir = "build"
$CoverageDir = "tests/coverage"
$CoverageOut = "$CoverageDir/coverage.out"
$CoverageHtml = "$CoverageDir/coverage.html"

function Ensure-BuildDir {
    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }
}

function Ensure-CoverageDir {
    if (-not (Test-Path $CoverageDir)) {
        New-Item -ItemType Directory -Path $CoverageDir | Out-Null
    }
}

function Get-VersionMetadata {
    $version = ""
    try {
        $version = (git describe --tags --always --dirty)
    } catch {
        $version = ""
    }

    if ([string]::IsNullOrWhiteSpace($version)) {
        $version = "dev"
    }

    $buildDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

    $gitCommit = ""
    try {
        $gitCommit = (git rev-parse HEAD)
    } catch {
        $gitCommit = ""
    }

    if ([string]::IsNullOrWhiteSpace($gitCommit)) {
        $gitCommit = "unknown"
    }

    return [pscustomobject]@{
        Version   = $version
        BuildDate = $buildDate
        GitCommit = $gitCommit
    }
}

function Get-BinaryName {
    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        return "polis.exe"
    }

    return "polis"
}

function Invoke-GoCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [string]$Description = "go command"
    )

    & go @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Ensure-Packages {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    $null = & go list $Pattern 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Skipping: no packages match pattern '$Pattern'." -ForegroundColor Yellow
        return $false
    }

    return $true
}

function Test-Project {
    Write-Host "Running tests..." -ForegroundColor Green
    Ensure-CoverageDir
    Invoke-GoCommand -Arguments @("test", "./...", "-coverprofile=$CoverageOut", "-covermode=atomic", "-timeout=5m") -Description "go test ./..."
}

function Test-Coverage {
    Write-Host "Generating coverage report..." -ForegroundColor Green
    Test-Project
    Invoke-GoCommand -Arguments @("tool", "cover", "-html=$CoverageOut", "-o", $CoverageHtml) -Description "go tool cover"
    Write-Host "Coverage report saved to $CoverageHtml" -ForegroundColor Cyan
}

function Test-Race {
    Write-Host "Running tests with race detector..." -ForegroundColor Green
    Ensure-CoverageDir
    Invoke-GoCommand -Arguments @("test", "./...", "-race", "-coverprofile=$CoverageOut", "-covermode=atomic", "-timeout=5m") -Description "go test ./... (race)"
}

function Test-Verbose {
    Write-Host "Running verbose tests..." -ForegroundColor Green
    Ensure-CoverageDir
    Invoke-GoCommand -Arguments @("test", "-v", "./...", "-coverprofile=$CoverageOut", "-covermode=atomic", "-timeout=5m") -Description "go test -v ./..."
}

function Test-Integration {
    Write-Host "Running integration tests..." -ForegroundColor Green
    if (Ensure-Packages "./tests/integration/...") {
        Invoke-GoCommand -Arguments @("test", "-v", "./tests/integration/...", "-timeout=10m") -Description "go test ./tests/integration/..."
    }
}

function Test-E2E {
    Write-Host "Running end-to-end tests..." -ForegroundColor Green
    if (Ensure-Packages "./tests/e2e/...") {
        Invoke-GoCommand -Arguments @("test", "-v", "./tests/e2e/...", "-timeout=10m") -Description "go test ./tests/e2e/..."
    }
}

function Test-Contract {
    Write-Host "Running contract tests..." -ForegroundColor Green
    if (Ensure-Packages "./tests/contract/...") {
        Invoke-GoCommand -Arguments @("test", "-v", "./tests/contract/...", "-timeout=5m") -Description "go test ./tests/contract/..."
    }
}

function Run-Benchmarks {
    Write-Host "Running benchmarks..." -ForegroundColor Green
    if (Ensure-Packages "./tests/perf/...") {
        Invoke-GoCommand -Arguments @("test", "-bench=.", "-benchmem", "-run=^$", "./tests/perf/...") -Description "go test benchmarks"
    }
}

function Build-Project {
    Write-Host "Building binary..." -ForegroundColor Green
    Ensure-BuildDir
    $meta = Get-VersionMetadata
    $ldflags = "-s -w -X main.Version=$($meta.Version) -X main.BuildDate=$($meta.BuildDate) -X main.GitCommit=$($meta.GitCommit)"
    $binary = Get-BinaryName
    $outputPath = Join-Path $BuildDir $binary
    Invoke-GoCommand -Arguments @("build", "-ldflags=$ldflags", "-o", $outputPath, "./cmd/proxy") -Description "go build"
    Write-Host "Binary created: $outputPath" -ForegroundColor Cyan
}

function Install-Project {
    Write-Host "Installing binary..." -ForegroundColor Green
    $meta = Get-VersionMetadata
    $ldflags = "-s -w -X main.Version=$($meta.Version) -X main.BuildDate=$($meta.BuildDate) -X main.GitCommit=$($meta.GitCommit)"
    Invoke-GoCommand -Arguments @("install", "-ldflags=$ldflags", "./cmd/proxy") -Description "go install"
}

function Format-Code {
    Write-Host "Formatting code..." -ForegroundColor Green
    Invoke-GoCommand -Arguments @("fmt", "./...") -Description "go fmt"
}

function Format-Check {
    Write-Host "Checking formatting..." -ForegroundColor Green
    $output = & gofmt -l .
    if ($LASTEXITCODE -ne 0) {
        throw "gofmt -l failed with exit code $LASTEXITCODE"
    }

    if ($output) {
        Write-Host "The following files need formatting:" -ForegroundColor Yellow
        $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        throw "Formatting check failed"
    }

    Write-Host "All Go files are properly formatted." -ForegroundColor Green
}

function Lint-Code {
    Write-Host "Running linter..." -ForegroundColor Green
    & golangci-lint run ./...
    if ($LASTEXITCODE -ne 0) {
        throw "golangci-lint failed with exit code $LASTEXITCODE"
    }
}

function Vet-Code {
    Write-Host "Running go vet..." -ForegroundColor Green
    Invoke-GoCommand -Arguments @("vet", "./...") -Description "go vet"
}

function Tidy-Modules {
    Write-Host "Tidying go.mod and go.sum..." -ForegroundColor Green
    Invoke-GoCommand -Arguments @("mod", "tidy") -Description "go mod tidy"
}

function Verify-Modules {
    Write-Host "Verifying module dependencies..." -ForegroundColor Green
    Invoke-GoCommand -Arguments @("mod", "verify") -Description "go mod verify"
}

function Download-Modules {
    Write-Host "Downloading module dependencies..." -ForegroundColor Green
    Invoke-GoCommand -Arguments @("mod", "download") -Description "go mod download"
}

function Run-CI {
    Write-Host "Running CI checks..." -ForegroundColor Green
    Format-Check
    Lint-Code
    Vet-Code
    Test-Project
    Write-Host "All CI checks passed!" -ForegroundColor Green
}

function Run-PreCommit {
    Write-Host "Running pre-commit checks..." -ForegroundColor Green
    Format-Code
    Lint-Code
    Vet-Code
    Test-Project
function Clean-Project {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Green
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
    if (Test-Path $CoverageDir) { Remove-Item -Recurse -Force $CoverageDir }
    Invoke-GoCommand -Arguments @("clean") -Description "go clean"
}   if (Test-Path $CoverageDir) { Remove-Item -Recurse -Force $CoverageDir }
    Invoke-GoCommand -Arguments @("clean") -Description "go clean"
}

function Build-DockerImage {
    Write-Host "Building Docker image..." -ForegroundColor Green
    $meta = Get-VersionMetadata
    & docker build `
        -t "polis:$($meta.Version)" `
        --build-arg "VERSION=$($meta.Version)" `
        --build-arg "BUILD_DATE=$($meta.BuildDate)" `
        --build-arg "VCS_REF=$($meta.GitCommit)" `
        .
    if ($LASTEXITCODE -ne 0) {
        throw "docker build failed with exit code $LASTEXITCODE"
    }
}

function Run-DockerContainer {
    Write-Host "Starting Docker container..." -ForegroundColor Green
    $meta = Get-VersionMetadata
    & docker run --rm -p 8080:8080 -p 9090:9090 "polis:$($meta.Version)"
    if ($LASTEXITCODE -ne 0) {
        throw "docker run failed with exit code $LASTEXITCODE"
    }
}

function Security-Scan {
    Write-Host "Running security scan..." -ForegroundColor Green
    if (-not (Get-Command gosec -ErrorAction SilentlyContinue)) {
        Write-Host "Installing gosec..." -ForegroundColor Yellow
        & go install github.com/securego/gosec/v2/cmd/gosec@latest
        if ($LASTEXITCODE -ne 0) {
            throw "go install gosec failed with exit code $LASTEXITCODE"
        }
    }

    & gosec -no-fail ./...
    if ($LASTEXITCODE -ne 0) {
        throw "gosec scan failed with exit code $LASTEXITCODE"
    }
}

function Show-Help {
    Write-Host "Secure AI Proxy Build Script" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage: pwsh -File build.ps1 <command>" -ForegroundColor Yellow
    Write-Host "   or: powershell -ExecutionPolicy Bypass -File build.ps1 <command>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Available commands:" -ForegroundColor Yellow
    Write-Host "  build            Build the binary"
    Write-Host "  install          Install the binary"
    Write-Host "  test             Run all tests with coverage"
    Write-Host "  test-race        Run all tests with race detector"
    Write-Host "  test-verbose     Run all tests with verbose output"
    Write-Host "  test-integration Run integration tests"
    Write-Host "  test-e2e         Run end-to-end tests"
    Write-Host "  test-contract    Run contract tests"
    Write-Host "  test-coverage    Generate HTML coverage report"
    Write-Host "  bench            Run benchmarks in tests/perf"
    Write-Host "  fmt              Format Go code"
    Write-Host "  fmt-check        Check formatting without modifying files"
    Write-Host "  lint             Run golangci-lint"
    Write-Host "  vet              Run go vet"
    Write-Host "  tidy             Run go mod tidy"
    Write-Host "  verify           Run go mod verify"
    Write-Host "  download         Run go mod download"
    Write-Host "  ci               Run CI checks (fmt-check, lint, vet, test)"
    Write-Host "  pre-commit       Run local pre-commit checks (fmt, lint, vet, test)"
    Write-Host "  clean            Remove build artifacts"
    Write-Host "  docker-build     Build Docker image"
    Write-Host "  docker-run       Run Docker container"
    Write-Host "  security-scan    Run gosec security scan"
    Write-Host "  help             Show this help message"
}

# Execute the requested command
switch ($Command.ToLowerInvariant()) {
    "build" { Build-Project }
    "install" { Install-Project }
    "test" { Test-Project }
    "test-race" { Test-Race }
    "test-verbose" { Test-Verbose }
    "test-integration" { Test-Integration }
    "test-e2e" { Test-E2E }
    "test-contract" { Test-Contract }
    "test-coverage" { Test-Coverage }
    "bench" { Run-Benchmarks }
    "fmt" { Format-Code }
    "fmt-check" { Format-Check }
    "lint" { Lint-Code }
    "vet" { Vet-Code }
    "tidy" { Tidy-Modules }
    "verify" { Verify-Modules }
    "download" { Download-Modules }
    "ci" { Run-CI }
    "pre-commit" { Run-PreCommit }
    "clean" { Clean-Project }
    "docker-build" { Build-DockerImage }
    "docker-run" { Run-DockerContainer }
    "security-scan" { Security-Scan }
    "help" { Show-Help }
    default {
        Write-Host "Unknown command: $Command" -ForegroundColor Red
        Show-Help
        exit 1
    }
}
