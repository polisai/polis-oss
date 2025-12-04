# CI/CD Workflows

This directory contains GitHub Actions workflows for automated testing, security scanning, and quality assurance.

## Workflows Overview

### Main Workflows

#### 1. CI Pipeline (`ci.yml`)

**Triggers**: Push to main/feature branches, Pull Requests

Comprehensive continuous integration pipeline with multiple jobs:

- **Code Quality**: Format checking, linting, go vet, mod tidy verification
- **Security Scanning**: Gosec, Snyk Code/OSS, TruffleHog secret detection
- **Build & Test**: Ubuntu builds, race detector, coverage
- **Integration Tests**: End-to-end integration tests (when present)
- **Contract Tests**: API contract validation (when present)
- **Performance**: Benchmark execution (when present)
- **Summary**: Aggregated results and compliance mapping

**Quality Gates**:
- Minimum 80% test coverage
- No security vulnerabilities (high/critical)
- All linter checks passing
- No hardcoded secrets

#### 2. Performance Smoke Tests (`perf-smoke.yml`)

**Triggers**: Workflow dispatch, Daily schedule (2 AM UTC), PR to main affecting performance-critical paths

Tests performance against success criteria:
- SC-001: Latency (<10ms p99 added latency)
- SC-002: Throughput (5,000 RPS per core)
- SC-003: Memory footprint (<512MB steady-state RSS)

**Parameters**:
- `scenario`: baseline, auth, dlp, waf, governance, all
- `duration`: Test duration in seconds (default: 30)

### Security Workflows

#### 3. Dependency Review (`dependency-review.yml`)

**Triggers**: Pull Requests to main

Reviews new dependencies for:
- Security vulnerabilities (moderate+ severity fails)
- License compliance (GPL variants denied)
- go.sum verification

#### 4. Dependency Updates (`dependency-updates.yml`)

**Triggers**: Weekly schedule (Monday 8 AM UTC), Manual dispatch

Automatically creates PRs for dependency updates:
- Updates to latest minor/patch versions
- Runs tests to verify compatibility
- Creates PR with change summary

### Release Workflow

#### 5. Release (`release.yml`)

**Triggers**: Version tags (v*), Manual dispatch

Creates GitHub releases:
- Multiple architectures (amd64, arm64)
- SHA256 checksums
- Release notes generation

**Note**: Containerization (Docker) will be added in a future phase when deployment requirements are defined.

## Secrets Configuration

Required repository secrets:

```

| Secret | Purpose | Required For |
|--------|---------|--------------|
| `SNYK_TOKEN` | Snyk vulnerability scanning | CI security job |
| `CODECOV_TOKEN` | Coverage reporting | Coverage workflow |
| `GITHUB_TOKEN` | Automatically provided | All workflows |

## Branch Protection Rules

Recommended settings for `main` branch:

- ✅ Require pull request reviews (1 approver)
- ✅ Require status checks to pass:
  - `Code Quality & Static Analysis`
  - `Security & Vulnerability Scanning`
  - `Build & Unit Tests`
- ✅ Require branches to be up to date
- ✅ Require conversation resolution
- ✅ Require signed commits (optional but recommended)
- ✅ Include administrators
- ✅ Restrict pushes (no direct commits)

## Local Development

Run CI checks locally before pushing:

```bash
# All checks
pwsh -File build.ps1 ci

# Individual checks
pwsh -File build.ps1 fmt-check  # Formatting
pwsh -File build.ps1 lint       # Linting
pwsh -File build.ps1 vet        # Static analysis
pwsh -File build.ps1 test       # Tests with coverage

# Pre-commit hook
pre-commit install
pre-commit run --all-files
```

> Tip: On Windows PowerShell 5.1 use `powershell -ExecutionPolicy Bypass -File build.ps1 <command>` or run the script directly via `./build.ps1 <command>`.
> Ensure `golangci-lint` is installed and on `PATH`. On Go 1.25, prefer downloading the official release archive over `go install`.

## Workflow Maintenance

### Adding New Workflows

1. Create workflow file in `.github/workflows/`
2. Follow naming convention: `kebab-case.yml`
3. Include clear documentation
4. Test with workflow_dispatch trigger first
5. Update this README

### Modifying Existing Workflows

1. Test changes in a fork first
2. Use semantic versioning for actions
3. Update dependent documentation
4. Coordinate with team on breaking changes

## Troubleshooting

### Common Issues

#### Failed Security Scans

- Review SARIF uploads in Security tab
- Check Snyk dashboard for details
- Fix or suppress findings with justification

#### Coverage Failures

- Run `pwsh -File build.ps1 test-coverage` locally
- Add tests for uncovered code
- Check for flaky tests affecting coverage

#### Build Failures

- Ensure `go mod tidy` is current
- Check Go version compatibility
- Verify all imports resolve

### Getting Help

- Check workflow logs for detailed errors
- Review [GitHub Actions documentation](https://docs.github.com/actions)
- Open an issue with `ci/cd` label

## Success Criteria Mapping

The CI/CD pipeline validates these success criteria:

| Criteria | Workflow | Validation Method |
|----------|----------|-------------------|
| SC-001 (Latency) | perf-smoke.yml | p99 latency measurement |
| SC-002 (Throughput) | perf-smoke.yml | RPS benchmarking |
| SC-003 (Footprint) | perf-smoke.yml | Memory profiling |
| SC-004 (Zero-downtime) | integration tests | Graceful reload testing |
| FR-011 (Routing) | contract tests | OpenAPI validation |

## Continuous Improvement

The CI/CD pipeline evolves with the project:

- ✅ Phase 1: Core quality gates (current)
- 🔄 Phase 2: Enhanced performance testing
- 📋 Phase 3: Integration & contract tests
- 📋 Phase 4: Deployment automation (containerization, staging/production)

## References

- [GitHub Actions Documentation](https://docs.github.com/actions)
- [Contributing Guide](../../CONTRIBUTING.md)
- [Project Requirements](../../docs/proxy-requirements.md)
- [Architecture Overview](../../docs/proxy-architecture-overview.md)

---

Last Updated: 2025-10-25
