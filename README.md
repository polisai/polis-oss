# Secure AI Proxy

Protocol-aware sidecar proxy for the Agent Trust Mesh. It enforces zero-trust, policy-driven governance for AI agent traffic with HTTP support in Phase 1 (protocol awareness for MCP/A2A to follow), high performance (Go + net/http), and strong observability (OpenTelemetry).

## Highlights

- **Security-First**: OAuth 2.1 resource server, confused-deputy mitigation, fail-closed auth
- **Policy-Driven**: OPA/Rego engine with DLP, WAF, rate limiting, circuit breaking
- **Protocol-Aware**: HTTP/1.1, HTTP/2, streaming (SSE, WebSocket)
- **Observability**: OpenTelemetry with enriched traces, metrics, and logs
- **Dynamic Config**: Zero-downtime reload via Control Plane gRPC stream
- **High Performance**: <10ms p99 latency, 5K RPS/core target

## Quick Start

### Prerequisites

- Go 1.25 or later
- Git
- (Optional) `golangci-lint` in `PATH` for local linting. When using Go 1.25, install from the official release archive instead of `go install`.

### Build and Test

```bash
# Clone the repository
git clone https://github.com/polisai/proxy.git
cd proxy

# Download dependencies
go mod download

# Build via PowerShell helper (Windows or cross-platform PowerShell 7)
# If pwsh is unavailable, use: powershell -ExecutionPolicy Bypass -File build.ps1 <command>
# Windows PowerShell supports running the script directly: .\build.ps1 build
pwsh -File build.ps1 build

# Run tests (coverage files output to tests/coverage/)
pwsh -File build.ps1 test

# View coverage report
pwsh -File build.ps1 test-coverage
```

### Running Locally

```bash
# Set required environment variables
export PROXY_LOG_LEVEL=debug
export OIDC_ISSUER=https://your-issuer.example.com
export OIDC_AUDIENCE=https://api.example.com

# Run the proxy
./secure-ai-proxy
```

For detailed setup and development instructions, see [AGENTS.md](AGENTS.md).

## Documentation

### Core Documentation
- [Architecture Overview](docs/proxy-architecture-overview.md) - System design and components
- [Requirements](docs/proxy-requirements.md) - Functional and non-functional requirements
- [Protocol Awareness](docs/proxy-protocols-awareness.md) - Protocol support details
- [Performance Validation](docs/performance-validation.md) - Performance targets and validation
- [Policy & Telemetry Examples](docs/policy-and-telemetry-examples.md) - Configuration examples

### Development Guides
- [AGENTS.md](AGENTS.md) - Agent-focused development guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute to this project

### Specifications
- [Feature Spec](specs/001-secure-ai-proxy/spec.md) - Detailed feature specification
- [Task Tracking](specs/001-secure-ai-proxy/tasks.md) - Implementation progress
- [API Contracts](specs/001-secure-ai-proxy/contracts/openapi.yaml) - OpenAPI specification

## CI/CD Pipeline

This project uses a comprehensive CI/CD pipeline with multiple quality gates:

### Quality Gates (All PRs)
- ✅ Code formatting (gofmt)
- ✅ Static analysis (golangci-lint, go vet)
- ✅ Security scanning (Gosec, Snyk, TruffleHog)
- ✅ Unit tests with race detector
- ✅ 70% minimum test coverage (Phase 1 baseline)

### Security Scanning
- **Gosec**: Go-specific security analysis
- **Snyk**: SAST (code) and SCA (dependencies)
- **TruffleHog**: Secret detection
- **License Compliance**: Blocks GPL variants

### Automated Workflows
- **CI Pipeline**: Runs on every PR and push
- **Performance Tests**: Daily automated benchmarks
- **Dependency Updates**: Weekly automated PRs

## Project Structure

```
├── cmd/
│   └── proxy/             # Application entry point (main.go)
├── internal/              # Private packages (Go compiler-enforced)
│   ├── domain/            # Pure business logic (zero external deps)
│   ├── admin/             # Admin HTTP API (health, metrics, reload)
│   ├── auth/              # Authentication & authorization
│   ├── routing/           # Request routing & pipeline orchestration
│   ├── policy/            # OPA/Rego policy engine & enforcement
│   │   ├── dlp/           # Data Loss Prevention filters
│   │   └── waf/           # Web Application Firewall filters
│   ├── governance/        # Rate limiting, circuit breakers, retries
│   ├── controlplane/      # Control plane communication & config reload
│   ├── stream/            # Streaming support (SSE, WebSocket)
│   ├── telemetry/         # OpenTelemetry integration
│   └── tls/               # mTLS policy enforcement
├── tests/
│   ├── unit/              # Package-level unit tests
│   ├── integration/       # End-to-end integration tests
│   ├── e2e/               # Full binary E2E tests
│   ├── contract/          # API contract tests
│   ├── fuzz/              # Fuzz testing
│   └── perf/              # Performance benchmarks
├── docs/                  # Documentation
├── specs/                 # Feature specifications
└── .github/workflows/     # CI/CD workflows
```

**Architecture Notes**:
- `internal/` packages are private by Go compiler (cannot be imported by external projects)
- `domain/` layer has zero external dependencies (only stdlib: context, errors, time)
- Clear separation: domain → infrastructure → application layers

## Technology Stack

- **Language**: Go 1.25
- **HTTP**: net/http (HTTP/1.1, HTTP/2)
- **gRPC**: Control Plane communication
- **Auth**: JWT/OIDC (golang-jwt, lestrrat-go/jwx)
- **Policy**: OPA/Rego
- **Telemetry**: OpenTelemetry (OTLP)
- **Config**: YAML (gopkg.in/yaml.v3)

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting PRs.

### Before You Contribute

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
2. Check [open issues](https://github.com/polisai/proxy/issues)
3. Review the [feature spec](specs/001-secure-ai-proxy/spec.md)
4. Follow the [constitution](.specify/memory/constitution.md)

### Development Workflow

1. Fork the repository
2. Create a feature branch (`feature/your-feature`)
3. Make your changes with tests
4. Run quality checks locally
5. Submit a pull request

### Quality Requirements

All contributions must:
- ✅ Pass all CI checks
- ✅ Include unit tests (80%+ coverage)
- ✅ Follow Go best practices
- ✅ Pass security scans
- ✅ Update relevant documentation

## Security

Security is a top priority. We enforce:

- **No hardcoded credentials** - Use environment variables or secret managers
- **Modern cryptography** - TLS 1.2+, SHA-2 family, AES-256, RSA-2048+
- **Input validation** - All external inputs sanitized
- **Secure defaults** - Fail-closed, least privilege
- **Regular scanning** - Automated security scans on all PRs

See security guidelines in [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities. Instead, email security@polisai.com with details.

## License

[License information to be added]

## Acknowledgments

Built with focus on security, performance, and observability for AI agent deployments.
