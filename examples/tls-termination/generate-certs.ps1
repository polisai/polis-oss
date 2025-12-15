# Certificate Generation Script for Polis TLS Termination
# This script demonstrates how to generate certificates for different scenarios

param(
    [string]$OutputDir = "./certs",
    [switch]$TestSuite,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Certificate Generation Script for Polis TLS Termination

Usage:
  .\generate-certs.ps1 [-OutputDir <path>] [-TestSuite] [-Help]

Parameters:
  -OutputDir <path>  : Output directory for certificates (default: ./certs)
  -TestSuite         : Generate complete test certificate suite
  -Help              : Show this help message

Examples:
  # Generate complete test suite
  .\generate-certs.ps1 -TestSuite

  # Generate test suite in custom directory
  .\generate-certs.ps1 -TestSuite -OutputDir ./my-certs

  # Generate individual certificates (see script for examples)
  .\generate-certs.ps1
"@
    exit 0
}

# Build the certificate utility if it doesn't exist
if (-not (Test-Path "polis-cert.exe")) {
    Write-Host "Building polis-cert utility..."
    go build -o polis-cert.exe ./cmd/polis-cert
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build polis-cert utility"
        exit 1
    }
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if ($TestSuite) {
    Write-Host "Generating complete test certificate suite..."
    & ./polis-cert.exe generate -test-suite -output-dir $OutputDir

    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Test certificate suite generated successfully in $OutputDir"
        Write-Host ""
        Write-Host "Generated files:"
        Get-ChildItem $OutputDir | ForEach-Object { Write-Host "  - $($_.Name)" }

        Write-Host ""
        Write-Host "Example configuration:"
        Write-Host @"
server:
  tls:
    enabled: true
    cert_file: "$OutputDir/server.crt"
    key_file: "$OutputDir/server.key"
    client_auth:
      ca_file: "$OutputDir/ca.crt"
    sni:
      "api.example.com":
        cert_file: "$OutputDir/api.crt"
        key_file: "$OutputDir/api.key"
"@
    } else {
        Write-Error "Failed to generate test certificate suite"
        exit 1
    }
} else {
    Write-Host "Generating individual certificates for different scenarios..."

    # Basic self-signed certificate
    Write-Host "1. Generating basic self-signed certificate..."
    & ./polis-cert.exe generate -cn "localhost" -dns "localhost,127.0.0.1" -cert "$OutputDir/basic.crt" -key "$OutputDir/basic.key"

    # Wildcard certificate
    Write-Host "2. Generating wildcard certificate..."
    & ./polis-cert.exe generate -cn "*.example.com" -dns "*.example.com,example.com" -cert "$OutputDir/wildcard.crt" -key "$OutputDir/wildcard.key"

    # Multi-domain certificate
    Write-Host "3. Generating multi-domain certificate..."
    & ./polis-cert.exe generate -cn "api.example.com" -dns "api.example.com,web.example.com,admin.example.com" -cert "$OutputDir/multi-domain.crt" -key "$OutputDir/multi-domain.key"

    # CA certificate
    Write-Host "4. Generating CA certificate..."
    & ./polis-cert.exe generate -ca -cn "Development CA" -org "Development Organization" -cert "$OutputDir/dev-ca.crt" -key "$OutputDir/dev-ca.key" -valid-for 87600h

    # Long-term certificate
    Write-Host "5. Generating long-term certificate..."
    & ./polis-cert.exe generate -cn "long-term.example.com" -valid-for 17520h -cert "$OutputDir/long-term.crt" -key "$OutputDir/long-term.key"

    Write-Host ""
    Write-Host "✅ Individual certificates generated successfully in $OutputDir"
    Write-Host ""
    Write-Host "Generated files:"
    Get-ChildItem $OutputDir | ForEach-Object { Write-Host "  - $($_.Name)" }
}

Write-Host ""
Write-Host "Certificate validation examples:"
Write-Host "  # Inspect a certificate"
Write-Host "  ./polis-cert.exe inspect -cert $OutputDir/server.crt"
Write-Host ""
Write-Host "  # Validate certificate and key pair"
Write-Host "  ./polis-cert.exe validate -cert $OutputDir/server.crt -key $OutputDir/server.key"
Write-Host ""
Write-Host "  # Get certificate info as JSON"
Write-Host "  ./polis-cert.exe inspect -cert $OutputDir/server.crt -format json"
