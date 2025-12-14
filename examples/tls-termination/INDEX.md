# TLS Termination Documentation Index

This directory contains comprehensive documentation and examples for TLS termination in Polis. Use this index to navigate to the appropriate documentation for your needs.

## Quick Start

1. **[README.md](README.md)** - Main TLS termination documentation with configuration examples
2. **[CERTIFICATE_GENERATION.md](CERTIFICATE_GENERATION.md)** - Generate certificates for testing and development
3. **[HTTP_TO_HTTPS_MIGRATION_GUIDE.md](HTTP_TO_HTTPS_MIGRATION_GUIDE.md)** - Migrate existing HTTP configurations to HTTPS

## Documentation by Use Case

### Getting Started
- **New to TLS termination?** → Start with [README.md](README.md)
- **Need certificates for testing?** → Use [CERTIFICATE_GENERATION.md](CERTIFICATE_GENERATION.md)
- **Want to test your setup?** → Follow [TESTING_GUIDE.md](TESTING_GUIDE.md)

### Migration and Integration
- **Migrating from HTTP to HTTPS?** → Follow [HTTP_TO_HTTPS_MIGRATION_GUIDE.md](HTTP_TO_HTTPS_MIGRATION_GUIDE.md)
- **Need multiple listeners?** → See [MULTI_LISTENER_GUIDE.md](MULTI_LISTENER_GUIDE.md)
- **Want production-ready config?** → Use [configs/production-ready.yaml](configs/production-ready.yaml)

### Development and Testing
- **Development environment?** → Use [configs/development.yaml](configs/development.yaml)
- **Testing different modes?** → Try [configs/termination-modes.yaml](configs/termination-modes.yaml)
- **Need comprehensive testing?** → Follow [TESTING_GUIDE.md](TESTING_GUIDE.md)

### Advanced Configurations
- **Multiple domains (SNI)?** → See [configs/sni-multi-domain.yaml](configs/sni-multi-domain.yaml)
- **Client certificate auth (mTLS)?** → Use [configs/mtls.yaml](configs/mtls.yaml)
- **Mixed HTTP/HTTPS listeners?** → Try [configs/mixed-listeners.yaml](configs/mixed-listeners.yaml)

## Documentation Files

### Core Documentation
| File | Purpose | Audience |
|------|---------|----------|
| [README.md](README.md) | Main TLS termination guide | All users |
| [CERTIFICATE_GENERATION.md](CERTIFICATE_GENERATION.md) | Certificate generation and management | Developers, Operators |
| [HTTP_TO_HTTPS_MIGRATION_GUIDE.md](HTTP_TO_HTTPS_MIGRATION_GUIDE.md) | Migration from HTTP to HTTPS | System Integrators |
| [MULTI_LISTENER_GUIDE.md](MULTI_LISTENER_GUIDE.md) | Multiple listener configuration | Advanced Users |
| [TESTING_GUIDE.md](TESTING_GUIDE.md) | Testing procedures and validation | Developers, QA |

### Configuration Examples
| File | Use Case | Description |
|------|----------|-------------|
| [configs/basic-tls.yaml](configs/basic-tls.yaml) | Simple setup | Basic TLS termination |
| [configs/production-ready.yaml](configs/production-ready.yaml) | Production | Security-hardened configuration |
| [configs/development.yaml](configs/development.yaml) | Development | Developer-friendly setup |
| [configs/mtls.yaml](configs/mtls.yaml) | Security | Mutual TLS authentication |
| [configs/sni-multi-domain.yaml](configs/sni-multi-domain.yaml) | Multi-domain | SNI with different certificates |
| [configs/mixed-listeners.yaml](configs/mixed-listeners.yaml) | Flexibility | HTTP and HTTPS simultaneously |
| [configs/multi-listener.yaml](configs/multi-listener.yaml) | Advanced | Multiple listeners with different TLS |
| [configs/backward-compatible.yaml](configs/backward-compatible.yaml) | Legacy | Backward compatibility |
| [configs/termination-modes.yaml](configs/termination-modes.yaml) | Testing | All termination modes |

### Utility Scripts
| File | Purpose | Usage |
|------|---------|-------|
| [generate-certs.ps1](generate-certs.ps1) | Certificate generation | PowerShell script for Windows |

## Common Workflows

### 1. First-Time Setup
```bash
# 1. Generate test certificates
./polis-cert generate -test-suite -output-dir ./certs

# 2. Use basic configuration
cp examples/tls-termination/configs/basic-tls.yaml config.yaml

# 3. Update certificate paths
sed -i 's|./certs/|./certs/|g' config.yaml

# 4. Start Polis
./polis-core -config config.yaml

# 5. Test HTTPS
curl -k https://localhost:8443/healthz
```

### 2. HTTP to HTTPS Migration
```bash
# 1. Backup current configuration
cp config.yaml config.yaml.backup

# 2. Follow migration guide
# See: HTTP_TO_HTTPS_MIGRATION_GUIDE.md

# 3. Test new configuration
./polis-core -config config.yaml -validate

# 4. Deploy gradually
# Use multi-listener approach for zero-downtime migration
```

### 3. Production Deployment
```bash
# 1. Use production-ready configuration
cp examples/tls-termination/configs/production-ready.yaml config.yaml

# 2. Update with your certificates
# Replace certificate paths with your CA-signed certificates

# 3. Validate configuration
./polis-core -config config.yaml -validate

# 4. Deploy with monitoring
# Ensure monitoring is in place before deployment
```

### 4. Development Testing
```bash
# 1. Use development configuration
cp examples/tls-termination/configs/development.yaml config.yaml

# 2. Generate development certificates
./polis-cert generate -test-suite -output-dir ./certs

# 3. Run comprehensive tests
# Follow TESTING_GUIDE.md for complete test procedures
```

## Requirements Coverage

This documentation addresses the following requirements:

### Requirement 2.2: Certificate Generation Documentation
- **[CERTIFICATE_GENERATION.md](CERTIFICATE_GENERATION.md)** - Complete certificate generation procedures
- **[generate-certs.ps1](generate-certs.ps1)** - Automated certificate generation script
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Certificate testing procedures

### Requirement 8.5: HTTP to HTTPS Migration Documentation
- **[HTTP_TO_HTTPS_MIGRATION_GUIDE.md](HTTP_TO_HTTPS_MIGRATION_GUIDE.md)** - Step-by-step migration guide
- **[configs/backward-compatible.yaml](configs/backward-compatible.yaml)** - Backward compatibility example
- **[MULTI_LISTENER_GUIDE.md](MULTI_LISTENER_GUIDE.md)** - Multi-listener migration approach

## Support and Troubleshooting

### Common Issues
1. **Certificate errors** → See [CERTIFICATE_GENERATION.md](CERTIFICATE_GENERATION.md#troubleshooting)
2. **Configuration errors** → See [README.md](README.md#troubleshooting)
3. **Migration issues** → See [HTTP_TO_HTTPS_MIGRATION_GUIDE.md](HTTP_TO_HTTPS_MIGRATION_GUIDE.md#troubleshooting-migration-issues)
4. **Testing failures** → See [TESTING_GUIDE.md](TESTING_GUIDE.md#troubleshooting-common-issues)

### Getting Help
- Review the appropriate documentation file for your use case
- Check the configuration examples in the `configs/` directory
- Run the testing procedures in [TESTING_GUIDE.md](TESTING_GUIDE.md)
- Validate your configuration with `./polis-core -config config.yaml -validate`

## Contributing

When adding new TLS termination features or documentation:

1. Update the appropriate documentation files
2. Add configuration examples to the `configs/` directory
3. Include testing procedures in [TESTING_GUIDE.md](TESTING_GUIDE.md)
4. Update this index file with new content

## Version Information

This documentation covers TLS termination features as implemented in Polis. For the latest updates and changes, refer to the main project documentation and release notes.
