# Certificate Generation Guide for Polis TLS Termination

This guide covers certificate generation, validation, and management for TLS termination in Polis.

## Quick Start

### Generate Test Certificates

The fastest way to get started is to generate a complete test certificate suite:

```bash
# Build the certificate utility
go build -o polis-cert ./cmd/polis-cert

# Generate a complete test certificate suite
./polis-cert generate -test-suite -output-dir ./certs

# This creates:
# - ca.crt/ca.key: Certificate Authority
# - server.crt/server.key: Server certificate for localhost, example.com
# - client.crt/client.key: Client certificate for mTLS
# - api.crt/api.key: SNI certificate for api.example.com
```

### Basic Certificate Generation

Generate a simple self-signed certificate:

```bash
# Basic certificate for localhost
./polis-cert generate -cn localhost -cert server.crt -key server.key

# Certificate with multiple DNS names and IP addresses
./polis-cert generate \
  -cn "example.com" \
  -dns "example.com,www.example.com,api.example.com" \
  -ips "192.168.1.100,10.0.0.1" \
  -cert multi-domain.crt \
  -key multi-domain.key
```

## Certificate Utility Commands

### Generate Command

```bash
./polis-cert generate [options]
```

**Options:**
- `-cn string`: Common name for the certificate (default: "localhost")
- `-org string`: Organization name (default: "Test Organization")
- `-country string`: Country code (default: "US")
- `-dns string`: Comma-separated list of DNS names (SANs)
- `-ips string`: Comma-separated list of IP addresses
- `-valid-for duration`: Certificate validity duration (default: 8760h = 1 year)
- `-key-size int`: RSA key size in bits (default: 2048)
- `-ca`: Generate a CA certificate
- `-cert string`: Output certificate file (default: "cert.pem")
- `-key string`: Output private key file (default: "key.pem")
- `-output-dir string`: Output directory (default: ".")
- `-test-suite`: Generate complete test certificate suite

**Examples:**

```bash
# Generate CA certificate
./polis-cert generate -ca -cn "My Test CA" -cert ca.crt -key ca.key -valid-for 87600h

# Generate wildcard certificate
./polis-cert generate -cn "*.example.com" -dns "*.example.com,example.com"

# Generate certificate with long validity
./polis-cert generate -cn "long-term.example.com" -valid-for 17520h  # 2 years

# Generate certificate with larger key size
./polis-cert generate -cn "secure.example.com" -key-size 4096
```

### Inspect Command

```bash
./polis-cert inspect -cert <certificate-file> [-format text|json]
```

**Examples:**

```bash
# Inspect certificate in human-readable format
./polis-cert inspect -cert server.crt

# Get certificate info as JSON
./polis-cert inspect -cert server.crt -format json

# Example output:
Certificate Information:
  File: server.crt
  Subject: CN=localhost,O=Test Organization,C=US
  Issuer: CN=Test CA,O=Test Organization,C=US
  Valid From: 2024-01-15T10:30:00Z
  Valid Until: 2025-01-15T10:30:00Z
  Status: ✅ VALID (expires in 8760h)
  DNS Names: localhost, example.com, *.example.com
  IP Addresses: 127.0.0.1, ::1
```

### Validate Command

```bash
./polis-cert validate -cert <certificate-file> [-key <key-file>] [-verbose]
```

**Examples:**

```bash
# Basic certificate validation
./polis-cert validate -cert server.crt

# Validate certificate and key pair
./polis-cert validate -cert server.crt -key server.key

# Verbose validation with detailed output
./polis-cert validate -cert server.crt -key server.key -verbose
```

## Certificate Types and Use Cases

### 1. Self-Signed Certificates

Best for development and testing environments.

```bash
# Basic self-signed certificate
./polis-cert generate -cn "dev.example.com" -cert dev.crt -key dev.key

# Self-signed with multiple domains
./polis-cert generate \
  -cn "dev.example.com" \
  -dns "dev.example.com,staging.example.com,*.dev.example.com" \
  -cert dev-multi.crt -key dev-multi.key
```

**Configuration:**
```yaml
server:
  tls:
    enabled: true
    cert_file: "./certs/dev.crt"
    key_file: "./certs/dev.key"
```

### 2. CA-Signed Certificates

For more realistic testing scenarios with certificate chains.

```bash
# Step 1: Generate CA
./polis-cert generate -ca -cn "Test CA" -cert ca.crt -key ca.key -valid-for 87600h

# Step 2: Generate server certificate (signed by CA)
# Note: This requires manual signing - use the test-suite for automatic CA signing
./polis-cert generate -test-suite -output-dir ./ca-certs
```

**Configuration:**
```yaml
server:
  tls:
    enabled: true
    cert_file: "./ca-certs/server.crt"
    key_file: "./ca-certs/server.key"
```

### 3. Client Certificates for mTLS

For mutual TLS authentication.

```bash
# Generate complete mTLS setup
./polis-cert generate -test-suite -output-dir ./mtls-certs
```

**Configuration:**
```yaml
server:
  tls:
    enabled: true
    cert_file: "./mtls-certs/server.crt"
    key_file: "./mtls-certs/server.key"
    client_auth:
      required: true
      ca_file: "./mtls-certs/ca.crt"
```

### 4. SNI Certificates

For serving multiple domains with different certificates.

```bash
# Generate certificates for different domains
./polis-cert generate -cn "api.example.com" -dns "api.example.com" -cert api.crt -key api.key
./polis-cert generate -cn "admin.example.com" -dns "admin.example.com" -cert admin.crt -key admin.key
./polis-cert generate -cn "*.staging.example.com" -dns "*.staging.example.com" -cert staging.crt -key staging.key
```

**Configuration:**
```yaml
server:
  tls:
    enabled: true
    cert_file: "./certs/default.crt"
    key_file: "./certs/default.key"
    sni:
      "api.example.com":
        cert_file: "./certs/api.crt"
        key_file: "./certs/api.key"
      "admin.example.com":
        cert_file: "./certs/admin.crt"
        key_file: "./certs/admin.key"
      "*.staging.example.com":
        cert_file: "./certs/staging.crt"
        key_file: "./certs/staging.key"
```

## Certificate Management Best Practices

### File Permissions

Ensure proper file permissions for security:

```bash
# Certificate files (public) - readable by all
chmod 644 *.crt

# Private key files - readable only by owner
chmod 600 *.key

# CA files - readable by group if needed
chmod 640 ca.crt
```

### Certificate Rotation

Monitor certificate expiration and plan for rotation:

```bash
# Check certificate expiration
./polis-cert inspect -cert server.crt | grep "Valid Until"

# Validate all certificates in a directory
for cert in *.crt; do
  echo "Checking $cert:"
  ./polis-cert validate -cert "$cert"
done
```

### Directory Structure

Organize certificates logically:

```
certs/
├── ca/
│   ├── ca.crt
│   └── ca.key
├── server/
│   ├── server.crt
│   └── server.key
├── client/
│   ├── client.crt
│   └── client.key
└── sni/
    ├── api.crt
    ├── api.key
    ├── admin.crt
    └── admin.key
```

## Integration with External Certificate Authorities

### Let's Encrypt Integration

For production environments, integrate with Let's Encrypt or other ACME providers:

```bash
# Example using certbot (not part of polis-cert)
certbot certonly --standalone -d example.com -d www.example.com

# Copy certificates to Polis directory
cp /etc/letsencrypt/live/example.com/fullchain.pem ./certs/server.crt
cp /etc/letsencrypt/live/example.com/privkey.pem ./certs/server.key
```

### Corporate PKI Integration

For enterprise environments with existing PKI:

1. Generate Certificate Signing Request (CSR) using standard tools
2. Submit CSR to corporate CA
3. Install signed certificate and intermediate chain
4. Configure Polis to use the certificate

```bash
# Generate CSR (using openssl)
openssl req -new -key server.key -out server.csr -subj "/CN=api.company.com/O=Company Inc/C=US"

# After receiving signed certificate from CA
./polis-cert validate -cert server.crt -key server.key -verbose
```

## Troubleshooting

### Common Issues

1. **Certificate/Key Mismatch**
   ```bash
   ./polis-cert validate -cert server.crt -key server.key
   # Error: private key does not match certificate
   ```

2. **Expired Certificates**
   ```bash
   ./polis-cert inspect -cert server.crt
   # Status: ❌ EXPIRED (30 days ago)
   ```

3. **Missing SAN Extensions**
   ```bash
   ./polis-cert inspect -cert server.crt
   # Warning: No Subject Alternative Names (SAN) present
   ```

4. **File Permission Issues**
   ```bash
   # Fix permissions
   chmod 644 server.crt
   chmod 600 server.key
   ```

### Debugging TLS Handshakes

Use standard tools to test TLS connectivity:

```bash
# Test TLS connection
openssl s_client -connect localhost:8443 -servername api.example.com

# Test with client certificate
openssl s_client -connect localhost:8443 -cert client.crt -key client.key

# Check certificate chain
openssl s_client -connect localhost:8443 -showcerts
```

## Security Considerations

### Development vs Production

**Development:**
- Self-signed certificates are acceptable
- Longer validity periods (1+ years) for convenience
- Relaxed file permissions for ease of use

**Production:**
- Use certificates from trusted CAs
- Shorter validity periods (90 days or less)
- Strict file permissions and access controls
- Regular certificate rotation
- Monitor certificate expiration

### Key Security

- Use minimum 2048-bit RSA keys (4096-bit for high security)
- Consider ECDSA keys for better performance
- Protect private keys with appropriate file permissions
- Never commit private keys to version control
- Use hardware security modules (HSMs) for production CAs

### Certificate Validation

- Always validate certificate chains
- Check certificate revocation status (CRL/OCSP)
- Monitor for certificate transparency logs
- Implement certificate pinning where appropriate

## Automation and CI/CD Integration

### Automated Certificate Generation

```bash
#!/bin/bash
# generate-test-certs.sh

CERT_DIR="./test-certs"
VALIDITY="8760h"  # 1 year

# Clean up old certificates
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"

# Generate test suite
./polis-cert generate -test-suite -output-dir "$CERT_DIR"

echo "Test certificates generated in $CERT_DIR"
echo "Valid for: $VALIDITY"
```

### CI/CD Pipeline Integration

```yaml
# .github/workflows/test-certs.yml
name: Generate Test Certificates

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  generate-certs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v3
        with:
          go-version: 1.21

      - name: Build certificate utility
        run: go build -o polis-cert ./cmd/polis-cert

      - name: Generate test certificates
        run: |
          ./polis-cert generate -test-suite -output-dir ./test-certs

      - name: Validate certificates
        run: |
          for cert in ./test-certs/*.crt; do
            ./polis-cert validate -cert "$cert" -verbose
          done

      - name: Upload certificates
        uses: actions/upload-artifact@v3
        with:
          name: test-certificates
          path: ./test-certs/
```

This comprehensive certificate generation and management system provides all the tools needed for TLS termination testing and development in Polis.
