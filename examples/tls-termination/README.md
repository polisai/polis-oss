# TLS Termination Configuration Example

This example demonstrates how to configure TLS termination in the Polis proxy system.

## Configuration Options

### Basic TLS Configuration

The simplest TLS configuration requires enabling TLS and specifying certificate files:

```yaml
server:
  tls:
    enabled: true
    cert_file: "/path/to/server.crt"
    key_file: "/path/to/server.key"
```

### Advanced TLS Configuration

For production deployments, you can configure additional security settings:

```yaml
server:
  tls:
    enabled: true
    cert_file: "/path/to/server.crt"
    key_file: "/path/to/server.key"
    min_version: "1.2"  # Minimum TLS version (1.0, 1.1, 1.2, 1.3)
    max_version: "1.3"  # Maximum TLS version (optional)
    cipher_suites:
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

### Client Certificate Authentication (mTLS)

Enable mutual TLS for client certificate authentication:

```yaml
server:
  tls:
    enabled: true
    cert_file: "/path/to/server.crt"
    key_file: "/path/to/server.key"
    client_auth:
      required: true
      ca_file: "/path/to/client-ca.crt"
      verify_mode: "strict"  # Options: none, request, require, verify-if-given
```

### SNI (Server Name Indication) Support

Configure different certificates for different domains:

```yaml
server:
  tls:
    enabled: true
    cert_file: "/path/to/default.crt"
    key_file: "/path/to/default.key"
    sni:
      "api.example.com":
        cert_file: "/path/to/api.crt"
        key_file: "/path/to/api.key"
      "admin.example.com":
        cert_file: "/path/to/admin.crt"
        key_file: "/path/to/admin.key"
```

### Multiple Listeners

Configure separate HTTP and HTTPS listeners:

```yaml
server:
  listen_params:
    - address: ":8080"
      protocol: "http"
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "/path/to/https.crt"
        key_file: "/path/to/https.key"
        min_version: "1.3"
```

## Environment Variable Overrides

TLS configuration can be overridden using environment variables:

- `PROXY_TLS_ENABLED=true` - Enable TLS
- `PROXY_TLS_CERT_FILE=/path/to/cert.pem` - Certificate file path
- `PROXY_TLS_KEY_FILE=/path/to/key.pem` - Private key file path
- `PROXY_TLS_MIN_VERSION=1.3` - Minimum TLS version

## Certificate Requirements

### Certificate Files

- **Certificate file**: Must contain the server certificate and any intermediate certificates in PEM format
- **Private key file**: Must contain the private key corresponding to the server certificate in PEM format
- **CA file**: For client authentication, must contain trusted CA certificates in PEM format

### File Permissions

Ensure proper file permissions for security:

```bash
chmod 644 /path/to/server.crt
chmod 600 /path/to/server.key
chmod 644 /path/to/client-ca.crt
```

### Self-Signed Certificates for Testing

For development and testing, you can generate self-signed certificates:

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate self-signed certificate
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/C=US/ST=CA/L=San Francisco/O=Test/CN=localhost"
```

## Security Considerations

1. **TLS Version**: Use TLS 1.2 or higher for production deployments
2. **Cipher Suites**: Configure strong cipher suites and disable weak ones
3. **Certificate Validation**: Always validate certificates in production
4. **Private Key Security**: Protect private keys with appropriate file permissions
5. **Certificate Rotation**: Implement automated certificate renewal and rotation

## Upstream TLS Configuration

The egress handler supports upstream TLS configuration for secure connections to backend services. This enables multiple TLS termination modes:

### HTTPS → HTTP Mode

Terminate TLS at the proxy and forward as HTTP to internal services:

```yaml
pipelines:
  - id: "https-to-http"
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "http://internal-api.company.com"
          # No upstream_tls config - forwards as HTTP
```

### HTTPS → HTTPS Mode

Terminate TLS at the proxy and re-encrypt for upstream services:

```yaml
pipelines:
  - id: "https-to-https"
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "https://api.external-service.com"
          upstream_tls:
            enabled: true
            server_name: "api.external-service.com"
            min_version: "1.2"
            cipher_suites:
              - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
              - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

### HTTP → HTTPS Mode

Accept HTTP and encrypt for upstream services:

```yaml
pipelines:
  - id: "http-to-https"
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "https://secure-backend.company.com"
          upstream_tls:
            enabled: true
            min_version: "1.2"
```

### Mutual TLS (mTLS) with Upstream

Configure client certificates for upstream authentication:

```yaml
pipelines:
  - id: "mtls-upstream"
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "https://mtls-api.partner.com"
          upstream_tls:
            enabled: true
            server_name: "mtls-api.partner.com"
            ca_file: "/etc/polis/certs/partner-ca.crt"
            cert_file: "/etc/polis/certs/client.crt"
            key_file: "/etc/polis/certs/client.key"
            min_version: "1.2"
```

### Custom CA Bundle

Use custom certificate authorities for private PKI:

```yaml
pipelines:
  - id: "custom-ca"
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "https://internal-api.corp"
          upstream_tls:
            enabled: true
            ca_file: "/etc/polis/certs/corporate-ca-bundle.crt"
            server_name: "internal-api.corp"
            min_version: "1.2"
```

### Development Mode

Skip certificate verification for development (not recommended for production):

```yaml
pipelines:
  - id: "dev-mode"
    nodes:
      - id: "egress"
        type: "egress.http"
        config:
          upstream_url: "https://dev-api.localhost:8443"
          upstream_tls:
            enabled: true
            insecure_skip_verify: true  # Only for development!
            min_version: "1.2"
```

### Upstream TLS Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Enable upstream TLS | `false` |
| `server_name` | Server name for SNI | Hostname from URL |
| `insecure_skip_verify` | Skip certificate verification | `false` |
| `ca_file` | Custom CA bundle file | System trust store |
| `cert_file` | Client certificate file | None |
| `key_file` | Client private key file | None |
| `min_version` | Minimum TLS version | `1.2` |
| `cipher_suites` | Allowed cipher suites | Go defaults |

## Integration with Pipeline Components

TLS termination works seamlessly with all pipeline components:

- **DLP**: Scans decrypted HTTPS traffic for sensitive data
- **WAF**: Applies web application firewall rules to decrypted traffic
- **LLM Judge**: Analyzes decrypted content using configured models
- **Policy Engine**: Enforces policies on decrypted requests and responses

The pipeline receives standard HTTP requests after TLS termination, ensuring compatibility with all existing security features. Upstream TLS configuration allows secure communication with backend services while maintaining full visibility and control over the traffic.

## Migration from HTTP to HTTPS

For detailed instructions on migrating existing HTTP configurations to support HTTPS, see the [HTTP to HTTPS Migration Guide](HTTP_TO_HTTPS_MIGRATION_GUIDE.md).

## Additional Resources

- **[Certificate Generation Guide](CERTIFICATE_GENERATION.md)**: Comprehensive guide for generating and managing certificates
- **[Multi-Listener Guide](MULTI_LISTENER_GUIDE.md)**: Instructions for configuring multiple HTTP/HTTPS listeners
- **[Testing Guide](TESTING_GUIDE.md)**: Complete testing procedures and validation steps
- **[Migration Guide](HTTP_TO_HTTPS_MIGRATION_GUIDE.md)**: Step-by-step migration from HTTP to HTTPS

## Configuration Examples

The `configs/` directory contains example configurations for various scenarios:

- **[basic-tls.yaml](configs/basic-tls.yaml)**: Simple TLS termination setup
- **[mtls.yaml](configs/mtls.yaml)**: Mutual TLS with client certificate authentication
- **[sni-multi-domain.yaml](configs/sni-multi-domain.yaml)**: SNI configuration for multiple domains
- **[mixed-listeners.yaml](configs/mixed-listeners.yaml)**: HTTP and HTTPS listeners simultaneously
- **[multi-listener.yaml](configs/multi-listener.yaml)**: Multiple listeners with different TLS configurations
- **[backward-compatible.yaml](configs/backward-compatible.yaml)**: Legacy configuration compatibility
- **[production-ready.yaml](configs/production-ready.yaml)**: Production-ready configuration with security best practices
- **[development.yaml](configs/development.yaml)**: Development-friendly configuration with self-signed certificates
- **[termination-modes.yaml](configs/termination-modes.yaml)**: All TLS termination modes (HTTPS→HTTP, HTTPS→HTTPS, HTTP→HTTPS)
