# HTTP to HTTPS Migration Guide

This guide provides step-by-step instructions for migrating existing HTTP-only Polis configurations to support HTTPS with TLS termination.

## Overview

Migrating from HTTP to HTTPS in Polis is designed to be straightforward with minimal configuration changes. This guide covers:

1. **Simple Migration**: Adding HTTPS to existing HTTP configurations
2. **Gradual Migration**: Running HTTP and HTTPS simultaneously during transition
3. **Complete Migration**: Moving entirely from HTTP to HTTPS
4. **Rollback Procedures**: How to revert changes if needed

## Prerequisites

Before starting the migration:

1. **Certificate Requirements**: Obtain TLS certificates (self-signed for testing, CA-signed for production)
2. **Backup Configuration**: Create backups of existing configuration files
3. **Test Environment**: Validate changes in a test environment first
4. **Monitoring**: Ensure monitoring is in place to track the migration

## Migration Scenarios

### Scenario 1: Simple HTTPS Addition (Recommended)

This approach adds HTTPS support while keeping existing HTTP functionality intact.

#### Before (HTTP Only)
```yaml
server:
  admin_address: ":19090"
  data_address: ":8090"

pipelines:
  - id: "http-pipeline"
    version: 1
    description: "HTTP pipeline"
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "http://backend.internal:8080"
```

#### After (HTTP + HTTPS)
```yaml
server:
  admin_address: ":19090"

  # Multi-listener configuration
  listen_params:
    # Keep existing HTTP listener
    - address: ":8090"
      protocol: "http"

    # Add new HTTPS listener
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "./certs/server.crt"
        key_file: "./certs/server.key"
        min_version: "1.2"

pipelines:
  # Existing HTTP pipeline (unchanged)
  - id: "http-pipeline"
    version: 1
    description: "HTTP pipeline"
    agentId: "*"
    protocol: "http"
    match:
      listener_port: 8090
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "http://backend.internal:8080"

  # New HTTPS pipeline
  - id: "https-pipeline"
    version: 1
    description: "HTTPS pipeline with TLS termination"
    agentId: "*"
    protocol: "http"  # Decrypted HTTP after TLS termination
    match:
      listener_port: 8443
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "http://backend.internal:8080"
```

**Changes Made:**
- Replaced `data_address` with `listen_params` array
- Added HTTPS listener on port 8443
- Added TLS configuration with certificate files
- Added port-based pipeline matching
- Kept existing HTTP functionality intact

### Scenario 2: Legacy Configuration Migration

For existing configurations using server-level TLS, minimal changes are needed.

#### Before (HTTP Only)
```yaml
server:
  admin_address: ":19090"
  data_address: ":8090"

pipeline:
  file: "pipeline.yaml"
```

#### After (HTTPS with Legacy Support)
```yaml
server:
  admin_address: ":19090"
  data_address: ":8090"  # HTTP listener

  # Add TLS configuration (creates HTTPS listener on :8443)
  tls:
    enabled: true
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
    min_version: "1.2"

pipeline:
  file: "pipeline.yaml"  # Unchanged
```

**Changes Made:**
- Added `tls` section to server configuration
- Existing HTTP listener remains on port 8090
- New HTTPS listener automatically created on port 8443
- Pipeline configuration unchanged

### Scenario 3: Complete HTTPS Migration

For environments that want to completely replace HTTP with HTTPS.

#### Before (HTTP Only)
```yaml
server:
  admin_address: ":19090"
  data_address: ":8090"

pipelines:
  - id: "main-pipeline"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "http://backend.internal:8080"
```

#### After (HTTPS Only)
```yaml
server:
  admin_address: ":19090"

  listen_params:
    # Single HTTPS listener (replaces HTTP)
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "./certs/server.crt"
        key_file: "./certs/server.key"
        min_version: "1.2"
        cipher_suites:
          - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
          - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

pipelines:
  - id: "main-pipeline"
    version: 1
    agentId: "*"
    protocol: "http"  # Still HTTP after TLS termination
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "http://backend.internal:8080"
```

**Changes Made:**
- Replaced `data_address` with `listen_params`
- Changed from HTTP to HTTPS listener
- Added TLS configuration
- Pipeline protocol remains "http" (processes decrypted traffic)

## Step-by-Step Migration Process

### Step 1: Prepare Certificates

Generate or obtain TLS certificates for your domain:

```bash
# For testing: Generate self-signed certificates
./polis-cert generate -test-suite -output-dir ./certs

# For production: Use your existing certificates or generate CSR
# Place certificates in ./certs/ directory with proper permissions
chmod 644 ./certs/*.crt
chmod 600 ./certs/*.key
```

### Step 2: Backup Current Configuration

```bash
# Create backup of current configuration
cp config.yaml config.yaml.backup
cp pipeline.yaml pipeline.yaml.backup  # if using separate pipeline file
```

### Step 3: Update Configuration

Choose one of the migration scenarios above and update your configuration file.

### Step 4: Validate Configuration

```bash
# Test configuration syntax
./polis-core -config config.yaml -validate

# Check certificate validity
./polis-cert validate -cert ./certs/server.crt -key ./certs/server.key
```

### Step 5: Deploy and Test

```bash
# Start Polis with new configuration
./polis-core -config config.yaml

# Test HTTP endpoint (if still enabled)
curl http://localhost:8090/healthz

# Test HTTPS endpoint
curl -k https://localhost:8443/healthz

# Test with certificate verification (production)
curl --cacert ./certs/ca.crt https://localhost:8443/healthz
```

### Step 6: Update Client Applications

Update client applications to use HTTPS endpoints:

```bash
# Before
curl http://your-proxy:8090/api/endpoint

# After
curl https://your-proxy:8443/api/endpoint
```

## Environment Variable Migration

If using environment variables, update them for TLS support:

### Before
```bash
export PROXY_DATA_ADDRESS=":8090"
```

### After
```bash
# Option 1: Multi-listener with environment variables
export PROXY_LISTEN_PARAMS=":8090:http,:8443:https"
export PROXY_TLS_ENABLED=true
export PROXY_TLS_CERT_FILE="./certs/server.crt"
export PROXY_TLS_KEY_FILE="./certs/server.key"

# Option 2: Legacy TLS configuration
export PROXY_DATA_ADDRESS=":8090"
export PROXY_TLS_ENABLED=true
export PROXY_TLS_CERT_FILE="./certs/server.crt"
export PROXY_TLS_KEY_FILE="./certs/server.key"
```

## Pipeline Configuration Updates

### Adding Security to HTTPS Traffic

Take advantage of TLS termination to add security scanning:

```yaml
pipelines:
  - id: "secure-https-pipeline"
    version: 1
    description: "HTTPS pipeline with security scanning"
    agentId: "*"
    protocol: "http"
    match:
      listener_port: 8443
    nodes:
      # Add DLP scanning to decrypted HTTPS traffic
      - id: "dlp-scan"
        type: "policy.dlp"
        config:
          rules: ["pii-detection", "financial-data"]

      # Add WAF protection
      - id: "waf-check"
        type: "policy.waf"
        config:
          ruleset: "owasp-core"

      # Add rate limiting
      - id: "rate-limit"
        type: "governance.ratelimit"
        config:
          requests_per_minute: 1000

      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "http://backend.internal:8080"
```

### Upstream TLS Configuration

If your backend also supports HTTPS, configure upstream TLS:

```yaml
nodes:
  - id: "egress"
    type: "egress.http"
    config:
      upstream_url: "https://secure-backend.internal:8443"
      upstream_tls:
        enabled: true
        min_version: "1.2"
        ca_file: "./certs/backend-ca.crt"  # if using private CA
```

## Common Migration Patterns

### Pattern 1: Gradual Migration with Port-Based Routing

```yaml
server:
  admin_address: ":19090"
  listen_params:
    - address: ":8090"
      protocol: "http"
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "./certs/server.crt"
        key_file: "./certs/server.key"

pipelines:
  # Legacy HTTP traffic
  - id: "legacy-http"
    version: 1
    agentId: "*"
    protocol: "http"
    match:
      listener_port: 8090
    nodes:
      - id: "legacy-egress"
        type: "egress.http"
        config:
          upstream_url: "http://legacy-backend:8080"

  # New HTTPS traffic with enhanced security
  - id: "secure-https"
    version: 1
    agentId: "*"
    protocol: "http"
    match:
      listener_port: 8443
    nodes:
      - id: "security-scan"
        type: "policy.dlp"
        config:
          rules: ["comprehensive"]
      - id: "secure-egress"
        type: "egress.http"
        config:
          upstream_url: "https://secure-backend:8443"
          upstream_tls:
            enabled: true
            min_version: "1.2"
```

### Pattern 2: Domain-Based Migration with SNI

```yaml
server:
  admin_address: ":19090"
  listen_params:
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "./certs/default.crt"
        key_file: "./certs/default.key"
        sni:
          "api.example.com":
            cert_file: "./certs/api.crt"
            key_file: "./certs/api.key"
          "legacy.example.com":
            cert_file: "./certs/legacy.crt"
            key_file: "./certs/legacy.key"

pipelines:
  # New API with full security
  - id: "api-pipeline"
    version: 1
    agentId: "*"
    protocol: "http"
    match:
      headers:
        host: ["api.example.com"]
    nodes:
      - id: "api-security"
        type: "policy.dlp"
        config:
          rules: ["api-protection"]
      - id: "api-egress"
        type: "egress.http"
        config:
          upstream_url: "https://api-backend:8443"
          upstream_tls:
            enabled: true

  # Legacy system with minimal changes
  - id: "legacy-pipeline"
    version: 1
    agentId: "*"
    protocol: "http"
    match:
      headers:
        host: ["legacy.example.com"]
    nodes:
      - id: "legacy-egress"
        type: "egress.http"
        config:
          upstream_url: "http://legacy-backend:8080"
```

## Troubleshooting Migration Issues

### Common Issues and Solutions

1. **Certificate Errors**
   ```bash
   # Problem: Certificate file not found
   # Solution: Verify file paths and permissions
   ls -la ./certs/
   ./polis-cert validate -cert ./certs/server.crt -key ./certs/server.key
   ```

2. **Port Conflicts**
   ```bash
   # Problem: Port already in use
   # Solution: Check for conflicting processes
   netstat -an | grep :8443
   # Use different ports if needed
   ```

3. **TLS Handshake Failures**
   ```bash
   # Problem: TLS version mismatch
   # Solution: Check client TLS support
   openssl s_client -connect localhost:8443 -tls1_2
   ```

4. **Pipeline Routing Issues**
   ```bash
   # Problem: Requests not matching expected pipeline
   # Solution: Check pipeline matching criteria
   curl -H "Host: api.example.com" https://localhost:8443/test
   ```

### Validation Commands

```bash
# Test HTTP endpoint
curl -v http://localhost:8090/healthz

# Test HTTPS endpoint (skip cert verification)
curl -k -v https://localhost:8443/healthz

# Test HTTPS with proper certificate validation
curl --cacert ./certs/ca.crt -v https://localhost:8443/healthz

# Test SNI
curl -k -H "Host: api.example.com" https://localhost:8443/healthz

# Check TLS configuration
openssl s_client -connect localhost:8443 -servername api.example.com
```

## Rollback Procedures

If issues occur during migration, you can quickly rollback:

### Quick Rollback
```bash
# Restore original configuration
cp config.yaml.backup config.yaml
cp pipeline.yaml.backup pipeline.yaml  # if applicable

# Restart Polis
./polis-core -config config.yaml
```

### Gradual Rollback
If using multi-listener configuration, you can disable HTTPS while keeping HTTP:

```yaml
server:
  admin_address: ":19090"
  listen_params:
    # Keep only HTTP listener
    - address: ":8090"
      protocol: "http"
    # Comment out or remove HTTPS listener
    # - address: ":8443"
    #   protocol: "https"
    #   tls: ...
```

## Production Considerations

### Security Best Practices

1. **Certificate Management**
   - Use certificates from trusted CAs in production
   - Implement automated certificate renewal
   - Monitor certificate expiration dates
   - Use proper file permissions (644 for certs, 600 for keys)

2. **TLS Configuration**
   - Use TLS 1.2 or higher
   - Configure strong cipher suites
   - Disable weak protocols and ciphers
   - Consider HSTS headers for web applications

3. **Monitoring and Logging**
   - Monitor TLS handshake success rates
   - Log certificate validation events
   - Track TLS version usage
   - Monitor for certificate expiration warnings

### Performance Considerations

1. **TLS Overhead**
   - TLS adds computational overhead for handshakes
   - Consider connection pooling and keep-alive
   - Monitor CPU usage during peak traffic

2. **Certificate Loading**
   - Large certificate chains increase handshake time
   - Consider certificate chain optimization
   - Monitor memory usage with multiple certificates

### High Availability

1. **Certificate Synchronization**
   - Ensure certificates are synchronized across instances
   - Use shared storage or certificate management systems
   - Implement automated certificate distribution

2. **Rolling Updates**
   - Update certificates without service interruption
   - Use certificate reload functionality
   - Test certificate updates in staging first

## Migration Checklist

- [ ] **Pre-Migration**
  - [ ] Backup current configuration files
  - [ ] Obtain or generate TLS certificates
  - [ ] Validate certificates with polis-cert tool
  - [ ] Test configuration in staging environment
  - [ ] Plan rollback procedures

- [ ] **Migration**
  - [ ] Update configuration files
  - [ ] Validate new configuration syntax
  - [ ] Deploy configuration changes
  - [ ] Test HTTP endpoints (if still enabled)
  - [ ] Test HTTPS endpoints
  - [ ] Verify certificate validation

- [ ] **Post-Migration**
  - [ ] Update client applications
  - [ ] Update load balancer configurations
  - [ ] Update monitoring and alerting
  - [ ] Update documentation
  - [ ] Monitor for errors and performance issues

- [ ] **Cleanup**
  - [ ] Remove HTTP listeners (if doing complete migration)
  - [ ] Update firewall rules
  - [ ] Remove old configuration backups (after validation period)
  - [ ] Update operational procedures

This migration guide provides a comprehensive approach to moving from HTTP to HTTPS with minimal disruption and maximum flexibility.
