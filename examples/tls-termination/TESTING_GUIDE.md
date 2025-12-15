# TLS Termination Testing Guide

This guide provides comprehensive testing procedures for TLS termination functionality in Polis, covering certificate generation, configuration validation, and end-to-end testing scenarios.

## Prerequisites

Before starting testing, ensure you have:

1. **Polis Binary**: Built and available (`./polis-core`)
2. **Certificate Utility**: Built and available (`./polis-cert`)
3. **Test Environment**: Clean environment for testing
4. **Network Tools**: `curl`, `openssl`, `netstat` available

## Quick Start Testing

### 1. Generate Test Certificates

```bash
# Build certificate utility
go build -o polis-cert ./cmd/polis-cert

# Generate complete test certificate suite
./polis-cert generate -test-suite -output-dir ./test-certs

# Verify certificates were created
ls -la ./test-certs/
```

### 2. Basic TLS Test

```bash
# Use basic TLS configuration
cp examples/tls-termination/configs/basic-tls.yaml test-config.yaml

# Update certificate paths in configuration
sed -i 's|./certs/|./test-certs/|g' test-config.yaml

# Start Polis
./polis-core -config test-config.yaml &
POLIS_PID=$!

# Test HTTPS endpoint
curl -k https://localhost:8443/healthz

# Cleanup
kill $POLIS_PID
```

## Certificate Generation Testing

### Test Self-Signed Certificate Generation

```bash
# Test basic certificate generation
./polis-cert generate -cn "test.example.com" -cert test.crt -key test.key

# Validate generated certificate
./polis-cert validate -cert test.crt -key test.key

# Inspect certificate details
./polis-cert inspect -cert test.crt

# Expected output should show:
# - Valid certificate
# - Correct common name
# - Appropriate validity period
# - No validation errors
```

### Test Multi-Domain Certificates

```bash
# Generate certificate with multiple domains
./polis-cert generate \
  -cn "api.example.com" \
  -dns "api.example.com,web.example.com,admin.example.com" \
  -ips "127.0.0.1,192.168.1.100" \
  -cert multi-domain.crt \
  -key multi-domain.key

# Validate multi-domain certificate
./polis-cert inspect -cert multi-domain.crt

# Verify SAN extensions are present
openssl x509 -in multi-domain.crt -text -noout | grep -A 5 "Subject Alternative Name"
```

### Test Certificate Authority Generation

```bash
# Generate CA certificate
./polis-cert generate -ca -cn "Test CA" -cert test-ca.crt -key test-ca.key -valid-for 87600h

# Validate CA certificate
./polis-cert inspect -cert test-ca.crt

# Verify CA extensions
openssl x509 -in test-ca.crt -text -noout | grep -A 5 "Basic Constraints"
```

### Test Certificate Validation

```bash
# Test valid certificate/key pair
./polis-cert validate -cert test.crt -key test.key
# Expected: Validation successful

# Test mismatched certificate/key pair
./polis-cert generate -cn "cert1.example.com" -cert cert1.crt -key key1.key
./polis-cert generate -cn "cert2.example.com" -cert cert2.crt -key key2.key
./polis-cert validate -cert cert1.crt -key key2.key
# Expected: Validation error - key mismatch

# Test expired certificate (if available)
# ./polis-cert validate -cert expired.crt -key expired.key
# Expected: Validation warning about expiration
```

## Configuration Testing

### Test Basic TLS Configuration

```bash
# Create test configuration
cat > basic-tls-test.yaml << EOF
server:
  admin_address: ":19091"
  data_address: ":8444"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"
    min_version: "1.2"

pipelines:
  - id: "test-pipeline"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "echo"
        type: "transform.response"
        config:
          status: 200
          body: "TLS Test Successful"
EOF

# Validate configuration
./polis-core -config basic-tls-test.yaml -validate

# Start server
./polis-core -config basic-tls-test.yaml &
POLIS_PID=$!

# Wait for startup
sleep 2

# Test HTTPS connection
curl -k https://localhost:8444/ -v

# Cleanup
kill $POLIS_PID
```

### Test Multi-Listener Configuration

```bash
# Create multi-listener test configuration
cat > multi-listener-test.yaml << EOF
server:
  admin_address: ":19092"
  listen_params:
    - address: ":8081"
      protocol: "http"
    - address: ":8445"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "./test-certs/server.crt"
        key_file: "./test-certs/server.key"

pipelines:
  - id: "http-test"
    version: 1
    agentId: "*"
    protocol: "http"
    match:
      listener_port: 8081
    nodes:
      - id: "http-response"
        type: "transform.response"
        config:
          body: "HTTP Test"

  - id: "https-test"
    version: 1
    agentId: "*"
    protocol: "http"
    match:
      listener_port: 8445
    nodes:
      - id: "https-response"
        type: "transform.response"
        config:
          body: "HTTPS Test"
EOF

# Start server
./polis-core -config multi-listener-test.yaml &
POLIS_PID=$!
sleep 2

# Test HTTP endpoint
curl http://localhost:8081/ -v

# Test HTTPS endpoint
curl -k https://localhost:8445/ -v

# Cleanup
kill $POLIS_PID
```

### Test SNI Configuration

```bash
# Create SNI test configuration
cat > sni-test.yaml << EOF
server:
  admin_address: ":19093"
  data_address: ":8446"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"
    sni:
      "api.example.com":
        cert_file: "./test-certs/api.crt"
        key_file: "./test-certs/api.key"

pipelines:
  - id: "default-sni"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "default-response"
        type: "transform.response"
        config:
          body: "Default SNI"

  - id: "api-sni"
    version: 1
    agentId: "*"
    protocol: "http"
    match:
      headers:
        host: ["api.example.com"]
    nodes:
      - id: "api-response"
        type: "transform.response"
        config:
          body: "API SNI"
EOF

# Start server
./polis-core -config sni-test.yaml &
POLIS_PID=$!
sleep 2

# Test default SNI
curl -k https://localhost:8446/ -v

# Test specific SNI
curl -k -H "Host: api.example.com" https://localhost:8446/ -v

# Test SNI with openssl
openssl s_client -connect localhost:8446 -servername api.example.com

# Cleanup
kill $POLIS_PID
```

## TLS Termination Mode Testing

### Test HTTPS → HTTP Mode

```bash
# Create termination mode test
cat > termination-test.yaml << EOF
server:
  admin_address: ":19094"
  data_address: ":8447"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"

pipelines:
  - id: "https-to-http"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "add-headers"
        type: "transform.headers"
        config:
          add:
            "x-forwarded-proto": "https"
            "x-tls-terminated": "true"
      - id: "mock-backend"
        type: "transform.response"
        config:
          status: 200
          headers:
            "content-type": "application/json"
          body: '{"mode": "https-to-http", "tls_terminated": true}'
EOF

# Start server
./polis-core -config termination-test.yaml &
POLIS_PID=$!
sleep 2

# Test termination
response=$(curl -k -s https://localhost:8447/)
echo "Response: $response"

# Verify headers are added
curl -k -I https://localhost:8447/

# Cleanup
kill $POLIS_PID
```

### Test HTTPS → HTTPS Mode

```bash
# Start mock HTTPS backend
python3 -c "
import http.server
import ssl
import socketserver

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"backend\": \"https\", \"path\": \"' + self.path.encode() + b'\"}')

httpd = socketserver.TCPServer(('localhost', 8448), Handler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./test-certs/server.crt', keyfile='./test-certs/server.key', server_side=True)
httpd.serve_forever()
" &
BACKEND_PID=$!

# Create HTTPS to HTTPS test
cat > https-to-https-test.yaml << EOF
server:
  admin_address: ":19095"
  data_address: ":8449"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"

pipelines:
  - id: "https-to-https"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "upstream-https"
        type: "egress.http"
        config:
          upstream_url: "https://localhost:8448"
          upstream_tls:
            enabled: true
            insecure_skip_verify: true
EOF

# Start proxy
./polis-core -config https-to-https-test.yaml &
POLIS_PID=$!
sleep 2

# Test HTTPS to HTTPS
curl -k https://localhost:8449/test -v

# Cleanup
kill $POLIS_PID $BACKEND_PID
```

## Security Testing

### Test TLS Version Enforcement

```bash
# Create TLS version test configuration
cat > tls-version-test.yaml << EOF
server:
  admin_address: ":19096"
  data_address: ":8450"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"
    min_version: "1.3"  # Require TLS 1.3

pipelines:
  - id: "version-test"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "version-response"
        type: "transform.response"
        config:
          body: "TLS 1.3 Required"
EOF

# Start server
./polis-core -config tls-version-test.yaml &
POLIS_PID=$!
sleep 2

# Test with TLS 1.3 (should succeed)
openssl s_client -connect localhost:8450 -tls1_3 -quiet

# Test with TLS 1.2 (should fail)
openssl s_client -connect localhost:8450 -tls1_2 -quiet

# Cleanup
kill $POLIS_PID
```

### Test Cipher Suite Restrictions

```bash
# Create cipher suite test
cat > cipher-test.yaml << EOF
server:
  admin_address: ":19097"
  data_address: ":8451"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"
    min_version: "1.2"
    cipher_suites:
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

pipelines:
  - id: "cipher-test"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "cipher-response"
        type: "transform.response"
        config:
          body: "Cipher Suite Test"
EOF

# Start server
./polis-core -config cipher-test.yaml &
POLIS_PID=$!
sleep 2

# Test cipher suite negotiation
openssl s_client -connect localhost:8451 -cipher 'ECDHE-RSA-AES256-GCM-SHA384'

# Test with unsupported cipher (should fail)
openssl s_client -connect localhost:8451 -cipher 'RC4-SHA'

# Cleanup
kill $POLIS_PID
```

### Test Client Certificate Authentication

```bash
# Create mTLS test configuration
cat > mtls-test.yaml << EOF
server:
  admin_address: ":19098"
  data_address: ":8452"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"
    client_auth:
      required: true
      ca_file: "./test-certs/ca.crt"

pipelines:
  - id: "mtls-test"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "mtls-response"
        type: "transform.response"
        config:
          body: "mTLS Authentication Successful"
EOF

# Start server
./polis-core -config mtls-test.yaml &
POLIS_PID=$!
sleep 2

# Test with client certificate (should succeed)
curl -k --cert ./test-certs/client.crt --key ./test-certs/client.key https://localhost:8452/

# Test without client certificate (should fail)
curl -k https://localhost:8452/

# Cleanup
kill $POLIS_PID
```

## Performance Testing

### Test TLS Handshake Performance

```bash
# Create performance test configuration
cat > perf-test.yaml << EOF
server:
  admin_address: ":19099"
  data_address: ":8453"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"

pipelines:
  - id: "perf-test"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "perf-response"
        type: "transform.response"
        config:
          body: "Performance Test"
EOF

# Start server
./polis-core -config perf-test.yaml &
POLIS_PID=$!
sleep 2

# Test handshake performance
echo "Testing TLS handshake performance..."
time for i in {1..10}; do
  curl -k -s https://localhost:8453/ > /dev/null
done

# Test concurrent connections
echo "Testing concurrent connections..."
for i in {1..5}; do
  curl -k -s https://localhost:8453/ &
done
wait

# Cleanup
kill $POLIS_PID
```

### Test Certificate Reload

```bash
# Create reload test configuration
cat > reload-test.yaml << EOF
server:
  admin_address: ":19100"
  data_address: ":8454"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"

pipelines:
  - id: "reload-test"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "reload-response"
        type: "transform.response"
        config:
          body: "Certificate Reload Test"
EOF

# Start server
./polis-core -config reload-test.yaml &
POLIS_PID=$!
sleep 2

# Test initial certificate
openssl s_client -connect localhost:8454 -showcerts 2>/dev/null | openssl x509 -noout -subject

# Generate new certificate
./polis-cert generate -cn "reloaded.example.com" -cert ./test-certs/server-new.crt -key ./test-certs/server-new.key

# Replace certificate files
cp ./test-certs/server-new.crt ./test-certs/server.crt
cp ./test-certs/server-new.key ./test-certs/server.key

# Wait for reload (if automatic reload is implemented)
sleep 5

# Test reloaded certificate
openssl s_client -connect localhost:8454 -showcerts 2>/dev/null | openssl x509 -noout -subject

# Cleanup
kill $POLIS_PID
```

## Error Testing

### Test Invalid Certificate Configuration

```bash
# Test with missing certificate file
cat > error-test-1.yaml << EOF
server:
  admin_address: ":19101"
  data_address: ":8455"
  tls:
    enabled: true
    cert_file: "./nonexistent.crt"
    key_file: "./test-certs/server.key"

pipelines:
  - id: "error-test"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "error-response"
        type: "transform.response"
        config:
          body: "Should not reach here"
EOF

# This should fail with certificate error
./polis-core -config error-test-1.yaml
# Expected: Configuration error about missing certificate file
```

### Test Certificate/Key Mismatch

```bash
# Generate mismatched certificate and key
./polis-cert generate -cn "cert1.example.com" -cert cert1.crt -key key1.key
./polis-cert generate -cn "cert2.example.com" -cert cert2.crt -key key2.key

# Test with mismatched cert/key
cat > error-test-2.yaml << EOF
server:
  admin_address: ":19102"
  data_address: ":8456"
  tls:
    enabled: true
    cert_file: "./cert1.crt"
    key_file: "./key2.key"  # Mismatched key

pipelines:
  - id: "error-test"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "error-response"
        type: "transform.response"
        config:
          body: "Should not reach here"
EOF

# This should fail with key mismatch error
./polis-core -config error-test-2.yaml
# Expected: Configuration error about certificate/key mismatch

# Cleanup
rm cert1.crt key1.key cert2.crt key2.key
```

### Test Invalid TLS Configuration

```bash
# Test with invalid TLS version
cat > error-test-3.yaml << EOF
server:
  admin_address: ":19103"
  data_address: ":8457"
  tls:
    enabled: true
    cert_file: "./test-certs/server.crt"
    key_file: "./test-certs/server.key"
    min_version: "invalid-version"

pipelines:
  - id: "error-test"
    version: 1
    agentId: "*"
    protocol: "http"
    nodes:
      - id: "error-response"
        type: "transform.response"
        config:
          body: "Should not reach here"
EOF

# This should fail with invalid TLS version error
./polis-core -config error-test-3.yaml
# Expected: Configuration error about invalid TLS version
```

## Automated Testing Script

Create a comprehensive test script:

```bash
#!/bin/bash
# tls-test-suite.sh - Comprehensive TLS testing script

set -e

echo "=== TLS Termination Test Suite ==="

# Build utilities
echo "Building utilities..."
go build -o polis-cert ./cmd/polis-cert
go build -o polis-core ./cmd/polis-core

# Generate test certificates
echo "Generating test certificates..."
./polis-cert generate -test-suite -output-dir ./test-certs

# Test certificate generation
echo "Testing certificate generation..."
./polis-cert validate -cert ./test-certs/server.crt -key ./test-certs/server.key
./polis-cert inspect -cert ./test-certs/server.crt

# Test basic TLS configuration
echo "Testing basic TLS configuration..."
cp examples/tls-termination/configs/basic-tls.yaml test-basic.yaml
sed -i 's|./certs/|./test-certs/|g' test-basic.yaml
./polis-core -config test-basic.yaml -validate

# Test multi-listener configuration
echo "Testing multi-listener configuration..."
cp examples/tls-termination/configs/multi-listener.yaml test-multi.yaml
sed -i 's|certs/|test-certs/|g' test-multi.yaml
./polis-core -config test-multi.yaml -validate

# Test SNI configuration
echo "Testing SNI configuration..."
cp examples/tls-termination/configs/sni-multi-domain.yaml test-sni.yaml
sed -i 's|./certs/|./test-certs/|g' test-sni.yaml
./polis-core -config test-sni.yaml -validate

echo "=== All tests passed! ==="

# Cleanup
rm -f test-*.yaml
rm -rf test-certs/
rm -f polis-cert polis-core
```

Make the script executable and run it:

```bash
chmod +x tls-test-suite.sh
./tls-test-suite.sh
```

## Troubleshooting Common Issues

### Certificate Issues

1. **Certificate not found**
   ```bash
   # Check file paths and permissions
   ls -la ./certs/
   ./polis-cert validate -cert ./certs/server.crt -key ./certs/server.key
   ```

2. **Certificate/key mismatch**
   ```bash
   # Validate certificate and key pair
   ./polis-cert validate -cert server.crt -key server.key -verbose
   ```

3. **Certificate expired**
   ```bash
   # Check certificate validity
   ./polis-cert inspect -cert server.crt
   openssl x509 -in server.crt -noout -dates
   ```

### Connection Issues

1. **TLS handshake failure**
   ```bash
   # Test with openssl
   openssl s_client -connect localhost:8443 -debug
   ```

2. **SNI not working**
   ```bash
   # Test SNI with specific server name
   openssl s_client -connect localhost:8443 -servername api.example.com
   ```

3. **Client certificate issues**
   ```bash
   # Test mTLS connection
   curl -k --cert client.crt --key client.key https://localhost:8443/ -v
   ```

This comprehensive testing guide covers all aspects of TLS termination functionality and provides the tools needed to validate proper implementation according to the requirements.
