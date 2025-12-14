# TLS Termination in Polis

This directory contains examples and documentation for configuring TLS termination in Polis.

## Overview

Polis supports flexible TLS configuration including:
- Basic TLS termination
- Mutual TLS (mTLS)
- Server Name Indication (SNI)
- Multiple Listeners (HTTP + HTTPS)
- Upstream TLS (re-encryption)

## Certificate Generation

The `polis-cert` utility allows you to generate certificates for development and testing.

### Quick Start
```bash
# Build the certificate utility
go build -o polis-cert ./cmd/polis-cert

# Generate a complete test certificate suite
./polis-cert generate -test-suite -output-dir ./certs
```
This generates:
- `ca.crt`/`ca.key`: Certificate Authority
- `server.crt`/`server.key`: Server certificate (localhost, etc.)
- `client.crt`/`client.key`: Client certificate for mTLS

### Basic Generation
```bash
# Basic certificate for localhost
./polis-cert generate -cn localhost -cert server.crt -key server.key

# With multiple DNS and IP
./polis-cert generate -cn "example.com" -dns "example.com,api.example.com" -ips "192.168.1.100"
```

### Validation and Inspection
```bash
# Inspect a certificate
./polis-cert inspect -cert server.crt

# Validate a certificate/key pair
./polis-cert validate -cert server.crt -key server.key
```

## Setup for Examples

All examples in this repository are configured to use certificates from `../../build/certs/`.

1. **Generate certificates**:
   ```powershell
   go build -o build/polis-cert.exe ./cmd/polis-cert
   .\build\polis-cert.exe generate -test-suite -output-dir build/certs
   ```
2. **Run an example**:
   ```powershell
   .\build\polis.exe --config examples/tls-termination/configs/basic-tls.yaml
   ```

## Configuration Guide

### Basic TLS
```yaml
server:
  tls:
    enabled: true
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
```

### Mutual TLS (mTLS)
```yaml
server:
  tls:
    enabled: true
    client_auth:
      required: true
      ca_file: "./certs/ca.crt"
```

### Server Name Indication (SNI)
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
```

### Multiple Listeners
```yaml
server:
  listen_params:
    - address: ":8090"
      protocol: "http"
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "./certs/server.crt"
        key_file: "./certs/server.key"
```

## Migration Guide (HTTP to HTTPS)

### Simple Migration (Add HTTPS, keep HTTP)
Change `server` config from `data_address: ":8090"` to:
```yaml
server:
  listen_params:
    - address: ":8090"
      protocol: "http"
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "./certs/server.crt"
        key_file: "./certs/server.key"
```

### Complete Migration (HTTPS Only)
```yaml
server:
  listen_params:
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "./certs/server.crt"
        key_file: "./certs/server.key"
```

## Security Best Practices
- **Production**: Use certificates from trusted CAs (e.g., Let's Encrypt).
- **Permissions**: `chmod 644 *.crt`, `chmod 600 *.key`.
- **Ciphers**: Configure strict cipher suites and TLS 1.2+ for production.
