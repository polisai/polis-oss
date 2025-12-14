# TLS Configuration for Polis Examples

All example configurations have been updated to use TLS by default. This document explains the TLS setup and how to use the examples.

## Certificate Setup

### Option 1: Use Relative Paths (Default)
All examples are configured to use certificates from `../../build/certs/` which points to the main certificate directory.

### Option 2: Copy Certificates Locally
Run the setup script to copy certificates to each example directory:

```powershell
# From the project root
.\examples\setup-tls-certs.ps1
```

Then update the certificate paths in each config to use local paths:
```yaml
cert_file: "certs/server.crt"
key_file: "certs/server.key"
```

## Generated Certificates

The following certificates are available in `build/certs/`:

- **server.crt/server.key**: Main server certificate (localhost, example.com, *.example.com)
- **ca.crt/ca.key**: Certificate Authority for validation
- **client.crt/client.key**: Client certificates for mutual TLS
- **api.crt/api.key**: SNI certificates for API domains

## Example Configurations

### Basic Passthrough (Port 8090)
```bash
# HTTPS proxy with dynamic routing
curl -k https://localhost:8090/test
```

### Observability (Port 8095)
```bash
# HTTPS with debug logging
curl -k https://localhost:8095/test
```

### PII Redaction (Port 8092)
```bash
# HTTPS with PII filtering
curl -k https://localhost:8092/test -d '{"ssn":"123-45-6789"}'
```

### LLM Guardrails (Port 8093)
```bash
# HTTPS with AI safety checks (requires OPENAI_API_KEY)
curl -k https://localhost:8093/test -d '{"message":"hello"}'
```

### Policy Enforcement (Port 8091)
```bash
# HTTPS with OPA policy enforcement
curl -k https://localhost:8091/test
```

### TLS Termination (Port 8090)
```bash
# Advanced TLS features (SNI, mTLS, etc.)
curl -k https://localhost:8090/test
```

## TLS Features Enabled

All examples now include:

- **TLS 1.2 minimum version**
- **Strong cipher suites**
- **Self-signed certificates for testing**
- **SNI support** (where applicable)
- **Client certificate support** (where applicable)

## Security Notes

⚠️ **The included certificates are for testing only!**

- Do not use these certificates in production
- Private keys are not password protected
- The CA certificate should not be trusted in production systems

## Running Examples

1. **Generate certificates** (if not already done):
   ```powershell
   go build -o build/polis-cert.exe ./cmd/polis-cert
   .\build\polis-cert.exe generate -test-suite -output-dir build/certs
   ```

2. **Run an example**:
   ```powershell
   # From project root
   .\build\polis.exe --config examples/basic-passthrough/config.yaml
   ```

3. **Test with curl**:
   ```bash
   # Use -k flag to skip certificate verification for self-signed certs
   curl -k https://localhost:8090/test
   ```

## Troubleshooting

### Certificate Path Issues
If you get certificate file not found errors:
1. Check that certificates exist in `build/certs/`
2. Verify the relative paths in your config
3. Consider using the setup script to copy certificates locally

### TLS Handshake Failures
- Ensure you're using `https://` not `http://`
- Use `-k` flag with curl for self-signed certificates
- Check that the port matches your configuration

### Permission Issues
- Ensure certificate files are readable
- Check file permissions on Windows/Linux
