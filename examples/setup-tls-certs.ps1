# PowerShell script to copy TLS certificates to example directories
# This makes it easier to run examples without relative path issues

Write-Host "Setting up TLS certificates for all examples..." -ForegroundColor Green

# Create certs directory in each example if it doesn't exist
$examples = @(
    "basic-passthrough",
    "observability",
    "pii-redaction",
    "llm-guardrails",
    "policy-enforcement",
    "tls-termination"
)

foreach ($example in $examples) {
    $certsDir = "examples/$example/certs"

    if (!(Test-Path $certsDir)) {
        New-Item -ItemType Directory -Path $certsDir -Force | Out-Null
        Write-Host "Created directory: $certsDir" -ForegroundColor Yellow
    }

    # Copy certificates
    Copy-Item "build/certs/*" $certsDir -Force
    Write-Host "Copied certificates to: $certsDir" -ForegroundColor Cyan
}

Write-Host "`nTLS certificates have been copied to all example directories!" -ForegroundColor Green
Write-Host "You can now run examples with local certificate paths." -ForegroundColor White
