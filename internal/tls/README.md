# TLS Certificate Management System

This package provides a comprehensive TLS certificate management system for the Polis proxy, implementing certificate loading, validation, SNI support, and automatic reloading.

## Components

### CertificateManager Interface

The `CertificateManager` interface defines the contract for certificate management operations:

- `LoadCertificate(certFile, keyFile string)` - Loads and validates a certificate/key pair
- `ValidateCertificate(cert *tls.Certificate)` - Validates a loaded certificate
- `GetCertificateForSNI(serverName string)` - Returns the appropriate certificate for SNI
- `ReloadCertificates()` - Reloads all managed certificates
- `WatchCertificateFiles(callback func())` - Starts watching certificate files for changes
- `Close()` - Stops file watching and cleans up resources

### FileCertificateManager

The `FileCertificateManager` is the primary implementation that manages certificates loaded from files:

- **Certificate Loading**: Loads certificates from PEM files with comprehensive validation
- **SNI Support**: Supports Server Name Indication with wildcard matching
- **File Watching**: Automatically reloads certificates when files change
- **Validation**: Validates certificate chains, expiration dates, and file permissions
- **Thread Safety**: All operations are thread-safe using read-write mutexes

### TLSTerminator

The `TLSTerminator` provides high-level TLS configuration building:

- **Server Configuration**: Builds `tls.Config` for downstream listeners
- **Client Configuration**: Builds `tls.Config` for upstream connections
- **SNI Integration**: Integrates with certificate manager for SNI support
- **Protocol Support**: Configurable TLS versions and cipher suites

## Features

### Certificate Validation

- **File Access**: Validates file existence and permissions
- **Certificate Parsing**: Validates PEM format and X.509 structure
- **Chain Validation**: Validates certificate chains when present
- **Expiration Checking**: Checks certificate validity periods
- **Expiration Warnings**: Logs warnings for certificates expiring within 30 days

### SNI Support

- **Exact Matching**: Direct server name to certificate mapping
- **Wildcard Matching**: Supports wildcard certificates (*.example.com)
- **Default Fallback**: Falls back to default certificate when no match found

### File Watching

- **Automatic Reloading**: Detects file changes and reloads certificates
- **Graceful Updates**: Reloads without dropping existing connections
- **Error Handling**: Continues operation even if some certificates fail to reload
- **Callback Support**: Executes callbacks after successful reloads

### Certificate Generation Utilities

- **Self-Signed Certificates**: Generates certificates for testing and development
- **Certificate Chains**: Supports CA and intermediate certificate generation
- **Flexible Configuration**: Configurable validity periods, key sizes, and extensions
- **Test Certificate Sets**: Generates complete certificate sets for testing

## Usage Examples

### Basic Certificate Management

```go
// Create certificate manager
logger := slog.Default()
manager := NewFileCertificateManager(logger)
defer manager.Close()

// Add certificates
err := manager.AddCertificate("", "server.crt", "server.key")
err = manager.AddCertificate("api.example.com", "api.crt", "api.key")

// Get certificate for SNI
cert, err := manager.GetCertificateForSNI("api.example.com")
```

### TLS Configuration Building

```go
// Create TLS terminator
terminator := NewTLSTerminator(logger)
defer terminator.Close()

// Configure TLS
tlsConfig := config.TLSConfig{
    Enabled:    true,
    CertFile:   "server.crt",
    KeyFile:    "server.key",
    MinVersion: "1.2",
    SNI: map[string]config.TLSCertConfig{
        "api.example.com": {
            CertFile: "api.crt",
            KeyFile:  "api.key",
        },
    },
}

// Build server configuration
serverTLSConfig, err := terminator.BuildServerConfig(tlsConfig)
```

### Certificate File Watching

```go
// Start watching certificate files
callback := func() {
    log.Println("Certificates reloaded successfully")
}

err := manager.WatchCertificateFiles(callback)
```

### Test Certificate Generation

```go
// Generate complete test certificate set
err := GenerateTestCertificates("./certs")

// This creates:
// - ca.crt, ca.key (Certificate Authority)
// - server.crt, server.key (Server certificate)
// - client.crt, client.key (Client certificate)
// - api.crt, api.key (SNI certificate for api.example.com)
```

## Configuration Integration

The certificate management system integrates with the existing Polis configuration system through the `config.TLSConfig` structure:

```yaml
tls:
  enabled: true
  cert_file: "/path/to/server.crt"
  key_file: "/path/to/server.key"
  min_version: "1.2"
  cipher_suites:
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  client_auth:
    required: false
    ca_file: "/path/to/client-ca.crt"
  sni:
    "api.example.com":
      cert_file: "/path/to/api.crt"
      key_file: "/path/to/api.key"
```

## Security Considerations

- **File Permissions**: Private keys should have restricted permissions (600)
- **Memory Protection**: Certificates are validated before loading into memory
- **Error Handling**: Sensitive information is not exposed in error messages
- **Certificate Validation**: Comprehensive validation prevents invalid certificates
- **Secure Defaults**: Uses TLS 1.2+ and secure cipher suites by default

## Testing

The package includes comprehensive tests covering:

- Certificate loading and validation
- SNI certificate selection
- File watching and reloading
- TLS configuration building
- Certificate generation utilities
- Error handling scenarios

Run tests with:
```bash
go test ./internal/tls/ -v
```

## Requirements Satisfied

This implementation satisfies the following requirements from the TLS termination specification:

- **1.1**: Certificate loading and validation
- **7.1**: Loading certificates from file paths
- **7.2**: Automatic certificate reloading
- **7.3**: SNI-based certificate selection
- **7.4**: Detailed error messages for parsing failures
- **7.5**: File permission error detection and reporting
