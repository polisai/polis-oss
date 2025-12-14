# TLS Security and Performance Optimization Guide

This guide explains the security hardening and performance optimizations implemented in the Polis TLS termination system.

## Security Hardening

### 1. Secure Protocol Versions

**Default Configuration:**
- Minimum TLS version: 1.2
- Maximum TLS version: Latest supported (1.3 preferred)

**Security Benefits:**
- TLS 1.0 and 1.1 are deprecated and vulnerable
- TLS 1.2 provides strong security with wide compatibility
- TLS 1.3 offers improved security and performance

**Configuration:**
```yaml
tls:
  min_version: "1.2"  # Never use versions below 1.2
  max_version: "1.3"  # Optional: restrict to TLS 1.3 only
```

### 2. Secure Cipher Suites

**Default Cipher Suite Priority:**
1. `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` - Strongest ECDSA
2. `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` - Strongest RSA
3. `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` - Fast ECDSA
4. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` - Fast RSA
5. `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` - Mobile optimized
6. `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` - Mobile optimized

**Security Features:**
- **Forward Secrecy**: All cipher suites use ECDHE key exchange
- **AEAD Encryption**: GCM and Poly1305 provide authenticated encryption
- **No Weak Ciphers**: RC4, 3DES, and CBC-mode ciphers are excluded

**Automatically Rejected Ciphers:**
- RC4 ciphers (cryptographically broken)
- 3DES ciphers (weak and deprecated)
- CBC-mode ciphers (vulnerable to padding oracle attacks)

### 3. Security Headers

**Automatically Added Headers:**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Benefits:**
- **HSTS**: Forces HTTPS connections for 1 year
- **Content Protection**: Prevents MIME sniffing and XSS
- **Clickjacking Protection**: Prevents embedding in frames
- **Privacy**: Limits referrer information leakage

### 4. Certificate Security

**Validation Features:**
- Automatic certificate chain validation
- Certificate expiration monitoring
- File permission checks (recommends 600)
- SNI certificate selection security

**Best Practices:**
- Store private keys with restricted permissions (600)
- Use strong key sizes (2048-bit RSA minimum, 256-bit ECDSA)
- Implement certificate rotation procedures
- Monitor certificate expiration dates

### 5. Client Authentication (mTLS)

**Configuration Options:**
```yaml
client_auth:
  required: true
  ca_file: "/path/to/client-ca.crt"
  verify_mode: "strict"  # or "trust-bundle-only"
```

**Security Modes:**
- **strict**: Full certificate chain validation
- **trust-bundle-only**: Accept any certificate from trusted CA

## Performance Optimizations

### 1. Session Resumption

**Features:**
- TLS session tickets enabled by default
- Session ticket key rotation (24-hour intervals)
- Client session cache (1000 sessions)
- Session timeout: 24 hours

**Benefits:**
- Reduces handshake overhead for returning clients
- Improves connection establishment time
- Reduces CPU usage on both client and server

### 2. Connection Pooling

**Upstream Connection Pool:**
- Maximum idle connections: 100
- Maximum idle connections per host: 10
- Idle connection timeout: 90 seconds
- Automatic cleanup of expired connections

**Benefits:**
- Reuses existing connections to upstream services
- Reduces connection establishment overhead
- Improves overall throughput

### 3. Memory Optimization

**Buffer Pooling:**
- Read buffer size: 32KB
- Write buffer size: 32KB
- Automatic buffer reuse and cleanup
- Sensitive data clearing before buffer reuse

**Benefits:**
- Reduces memory allocation overhead
- Improves garbage collection performance
- Prevents memory leaks

### 4. Handshake Optimization

**Features:**
- Handshake timeout: 10 seconds
- Server cipher suite preference enabled
- Renegotiation disabled for security and performance
- Optimized certificate selection for SNI

**Benefits:**
- Prevents resource exhaustion attacks
- Ensures consistent cipher suite selection
- Eliminates renegotiation overhead

### 5. TLS 1.3 Optimizations

**Automatic Benefits:**
- Reduced handshake round trips (1-RTT vs 2-RTT)
- Improved cipher suite negotiation
- Better forward secrecy
- Reduced connection establishment time

## Configuration Examples

### Basic Secure Configuration

```yaml
server:
  tls:
    enabled: true
    cert_file: "/path/to/server.crt"
    key_file: "/path/to/server.key"
    min_version: "1.2"
```

### High-Security Configuration

```yaml
server:
  tls:
    enabled: true
    cert_file: "/path/to/server.crt"
    key_file: "/path/to/server.key"
    min_version: "1.3"  # TLS 1.3 only
    cipher_suites:
      - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    client_auth:
      required: true
      ca_file: "/path/to/client-ca.crt"
      verify_mode: "strict"
```

### Multi-Domain Configuration

```yaml
server:
  tls:
    enabled: true
    cert_file: "/path/to/default.crt"
    key_file: "/path/to/default.key"
    min_version: "1.2"
    sni:
      "api.example.com":
        cert_file: "/path/to/api.crt"
        key_file: "/path/to/api.key"
      "secure.example.com":
        cert_file: "/path/to/secure.crt"
        key_file: "/path/to/secure.key"
```

## Monitoring and Metrics

### TLS Metrics

The system exposes comprehensive TLS metrics:

- **Connection Metrics**: Total, active, and error counts
- **Handshake Metrics**: Duration, success/failure rates
- **Certificate Metrics**: Expiration warnings, validation errors
- **Security Metrics**: Cipher suite distribution, protocol versions

### Certificate Monitoring

**Automatic Monitoring:**
- Certificate expiration warnings (30, 7, 1 days before expiry)
- Certificate validation status
- File permission checks
- Certificate chain validation

### Performance Monitoring

**Key Performance Indicators:**
- Handshake duration (target: <100ms)
- Connection establishment time
- Session resumption rate (target: >80%)
- Memory usage patterns

## Security Best Practices

### 1. Certificate Management

- Use certificates from trusted Certificate Authorities
- Implement automated certificate renewal (Let's Encrypt, ACME)
- Store private keys securely (HSM, encrypted storage)
- Regular certificate rotation (annually or bi-annually)

### 2. Configuration Security

- Never use `insecure_skip_verify: true` in production
- Regularly update cipher suite configurations
- Monitor security advisories for TLS vulnerabilities
- Use configuration validation tools

### 3. Network Security

- Implement proper firewall rules
- Use network segmentation
- Monitor for suspicious connection patterns
- Implement rate limiting and DDoS protection

### 4. Operational Security

- Regular security audits and penetration testing
- Log analysis and anomaly detection
- Incident response procedures
- Security awareness training

## Performance Tuning

### 1. Hardware Considerations

- Use hardware with AES-NI support for AES-GCM performance
- Consider dedicated crypto accelerators for high-throughput scenarios
- Ensure sufficient CPU cores for concurrent connections
- Use fast storage for certificate and key files

### 2. Operating System Tuning

- Optimize TCP settings for high-throughput connections
- Increase file descriptor limits
- Configure appropriate buffer sizes
- Use high-resolution timers for accurate metrics

### 3. Application Tuning

- Monitor and adjust connection pool sizes
- Tune handshake timeouts based on network conditions
- Optimize certificate loading and caching
- Use appropriate logging levels (avoid debug in production)

## Troubleshooting

### Common Issues

1. **Handshake Failures**
   - Check cipher suite compatibility
   - Verify certificate validity and chain
   - Confirm TLS version support

2. **Performance Issues**
   - Monitor session resumption rates
   - Check connection pool utilization
   - Analyze handshake duration metrics

3. **Certificate Problems**
   - Verify file permissions and paths
   - Check certificate expiration dates
   - Validate certificate chains

### Diagnostic Tools

- Use `openssl s_client` for connection testing
- Monitor TLS metrics and logs
- Use network analysis tools (Wireshark, tcpdump)
- Implement health checks for certificate status

## Compliance and Standards

### Security Standards

- **NIST SP 800-52**: Guidelines for TLS implementations
- **RFC 8446**: TLS 1.3 specification
- **OWASP**: Web application security guidelines
- **PCI DSS**: Payment card industry requirements

### Compliance Features

- Strong cryptographic algorithms
- Proper certificate validation
- Secure key management
- Comprehensive audit logging
- Regular security assessments

This guide provides a comprehensive overview of the security and performance optimizations implemented in the Polis TLS termination system. Regular review and updates of these configurations ensure continued security and optimal performance.
