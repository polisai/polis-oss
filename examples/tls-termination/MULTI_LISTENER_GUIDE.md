# Multi-Listener Configuration Guide

This guide explains how to configure Polis to listen on multiple addresses with different protocols (HTTP and HTTPS) using the new multi-listener functionality.

## Overview

The multi-listener feature allows you to:
- Run HTTP and HTTPS listeners simultaneously on different ports
- Configure different TLS settings for different HTTPS listeners
- Maintain backward compatibility with existing single-listener configurations
- Use environment variables for dynamic configuration

## Configuration Options

### 1. Legacy Single-Listener Configuration (Backward Compatible)

```yaml
server:
  admin_address: ":19090"
  data_address: ":8090"  # HTTP listener
  tls:
    enabled: true
    cert_file: "certs/server.crt"
    key_file: "certs/server.key"
    # TLS server will listen on default port :8443
```

### 2. Multi-Listener Configuration

```yaml
server:
  admin_address: ":19090"
  data_address: ":8090"  # Ignored when listen_params is used

  listen_params:
    # HTTP listener
    - address: ":8080"
      protocol: "http"

    # HTTPS listener with TLS configuration
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "certs/server.crt"
        key_file: "certs/server.key"
        min_version: "1.2"
```

### 3. Multiple HTTPS Listeners with Different TLS Configurations

```yaml
server:
  admin_address: ":19090"

  listen_params:
    # Public HTTPS API
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "certs/public-api.crt"
        key_file: "certs/public-api.key"
        min_version: "1.2"
        sni:
          "api.example.com":
            cert_file: "certs/api-example-com.crt"
            key_file: "certs/api-example-com.key"

    # Internal HTTPS API with client authentication
    - address: ":9443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "certs/internal-api.crt"
        key_file: "certs/internal-api.key"
        min_version: "1.3"
        client_auth:
          required: true
          ca_file: "certs/client-ca.crt"
```

## Environment Variable Configuration

You can configure multiple listeners using environment variables:

```bash
# Basic TLS configuration
export PROXY_TLS_ENABLED=true
export PROXY_TLS_CERT_FILE="/path/to/cert.pem"
export PROXY_TLS_KEY_FILE="/path/to/key.pem"

# Multi-listener configuration
# Format: "address1:protocol1,address2:protocol2"
export PROXY_LISTEN_PARAMS=":8080:http,:8443:https"
```

## Configuration Validation

The system validates configurations to ensure:

1. **No duplicate addresses**: Each listener must use a unique address
2. **No conflicts with admin address**: Listeners cannot use the same address as the admin interface
3. **HTTPS requires TLS**: HTTPS listeners must have valid TLS configuration
4. **TLS consistency**: TLS configuration must be consistent across server and listener levels

### Valid Configuration Examples

✅ **Mixed HTTP/HTTPS listeners**
```yaml
listen_params:
  - address: ":8080"
    protocol: "http"
  - address: ":8443"
    protocol: "https"
    tls:
      enabled: true
      cert_file: "server.crt"
      key_file: "server.key"
```

✅ **Multiple HTTP listeners**
```yaml
listen_params:
  - address: ":8080"
    protocol: "http"
  - address: ":8081"
    protocol: "http"
```

### Invalid Configuration Examples

❌ **Duplicate addresses**
```yaml
listen_params:
  - address: ":8080"
    protocol: "http"
  - address: ":8080"  # Error: duplicate address
    protocol: "https"
```

❌ **HTTPS without TLS configuration**
```yaml
listen_params:
  - address: ":8443"
    protocol: "https"  # Error: HTTPS requires TLS configuration
```

❌ **Conflict with admin address**
```yaml
server:
  admin_address: ":19090"
  listen_params:
    - address: ":19090"  # Error: conflicts with admin_address
      protocol: "http"
```

## Migration from Single to Multi-Listener

### Step 1: Identify Current Configuration
If you have:
```yaml
server:
  data_address: ":8090"
  tls:
    enabled: true
    cert_file: "server.crt"
    key_file: "server.key"
```

### Step 2: Convert to Multi-Listener
Replace with:
```yaml
server:
  listen_params:
    - address: ":8090"
      protocol: "http"
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "server.crt"
        key_file: "server.key"
```

### Step 3: Test Configuration
```bash
# Validate configuration
./polis-core -config config.yaml

# Check listeners are working
curl http://localhost:8090/healthz
curl -k https://localhost:8443/healthz
```

## Best Practices

1. **Use specific ports**: Avoid using port 0 (random port assignment) in production
2. **Separate HTTP and HTTPS**: Use different ports for HTTP and HTTPS listeners
3. **TLS security**: Always use TLS 1.2 or higher for HTTPS listeners
4. **Certificate management**: Use different certificates for different domains/purposes
5. **Monitoring**: Monitor all configured listeners in your observability setup

## Troubleshooting

### Common Issues

1. **Port already in use**
   - Check if another process is using the port: `netstat -an | grep :8080`
   - Use different ports or stop conflicting processes

2. **Certificate errors**
   - Verify certificate files exist and are readable
   - Check certificate validity: `openssl x509 -in cert.crt -text -noout`

3. **TLS handshake failures**
   - Check TLS version compatibility
   - Verify cipher suite support
   - Review certificate chain completeness

### Debugging Commands

```bash
# Test HTTP listener
curl -v http://localhost:8080/healthz

# Test HTTPS listener (skip certificate verification)
curl -k -v https://localhost:8443/healthz

# Test HTTPS with certificate verification
curl --cacert ca.crt https://localhost:8443/healthz

# Check TLS configuration
openssl s_client -connect localhost:8443 -servername api.example.com
```

## Performance Considerations

- Each listener runs in its own goroutine
- TLS handshakes add computational overhead
- Consider connection pooling for high-traffic scenarios
- Monitor memory usage with multiple TLS configurations
- Use appropriate timeout values for different listener types

## Security Considerations

- Use strong cipher suites for HTTPS listeners
- Implement proper certificate validation
- Consider client certificate authentication for internal APIs
- Regularly rotate TLS certificates
- Monitor certificate expiration dates
- Use different certificates for different security domains
