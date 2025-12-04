package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/polisai/polis-oss/pkg/config"
)

// CertificateProvider supplies certificates for upstream and downstream mTLS handshakes.
type CertificateProvider interface {
	DownstreamCertificate(policyID string) (tls.Certificate, error)
	UpstreamCertificate(policyID string) (tls.Certificate, error)
}

// PolicyMTLS evaluates policy-driven mTLS requirements and produces tls.Config instances.
type PolicyMTLS struct {
	certs CertificateProvider

	mu           sync.RWMutex
	trustBundles map[string]*config.TrustBundle

	systemPoolOnce sync.Once
	systemPool     *x509.CertPool
	systemPoolErr  error
}

// NewPolicyMTLS constructs a new policy-aware mTLS helper.
func NewPolicyMTLS(provider CertificateProvider) (*PolicyMTLS, error) {
	if provider == nil {
		return nil, errors.New("policy mTLS requires a certificate provider")
	}
	return &PolicyMTLS{
		certs:        provider,
		trustBundles: map[string]*config.TrustBundle{},
	}, nil
}

// UpdateTrustBundles replaces the current trust bundle map.
func (m *PolicyMTLS) UpdateTrustBundles(bundles map[string]*config.TrustBundle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trustBundles = make(map[string]*config.TrustBundle, len(bundles))
	for name, bundle := range bundles {
		m.trustBundles[name] = bundle
	}
}

// DownstreamConfig builds the server-side tls.Config when downstream mTLS is required.
func (m *PolicyMTLS) DownstreamConfig(policy config.PolicySpec) (*tls.Config, error) {
	direction := policy.MTLS.Downstream
	if !direction.Require {
		return nil, nil
	}

	certificate, err := m.certs.DownstreamCertificate(policy.ID)
	if err != nil {
		return nil, fmt.Errorf("downstream certificate: %w", err)
	}

	pool, err := m.poolFor(direction.TrustBundle)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	cfg.ClientCAs = pool
	return cfg, nil
}

// UpstreamConfig builds the client-side tls.Config when upstream mTLS is required.
func (m *PolicyMTLS) UpstreamConfig(policy config.PolicySpec, serverName string) (*tls.Config, error) {
	direction := policy.MTLS.Upstream
	if !direction.Require {
		return nil, nil
	}

	certificate, err := m.certs.UpstreamCertificate(policy.ID)
	if err != nil {
		return nil, fmt.Errorf("upstream certificate: %w", err)
	}

	pool, err := m.poolFor(direction.TrustBundle)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
	}

	switch direction.PeerVerification {
	case config.PeerVerificationStrict:
		name := strings.TrimSpace(serverName)
		if name == "" {
			return nil, errors.New("peer verification requires server name")
		}
		cfg.ServerName = name
	case config.PeerVerificationTrustBundleOnly:
		// No additional settings: SAN enforcement is intentionally skipped.
	default:
		return nil, fmt.Errorf("unsupported peer verification mode %q", direction.PeerVerification)
	}

	return cfg, nil
}

// poolFor resolves a trust bundle (or system roots) into an *x509.CertPool.
func (m *PolicyMTLS) poolFor(name string) (*x509.CertPool, error) {
	bundleName := strings.TrimSpace(name)
	if bundleName == "" {
		return m.systemCertPool()
	}

	m.mu.RLock()
	bundle, ok := m.trustBundles[bundleName]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("trust bundle %s not found", bundleName)
	}
	return bundle.CertPool()
}

func (m *PolicyMTLS) systemCertPool() (*x509.CertPool, error) {
	m.systemPoolOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil {
			m.systemPoolErr = err
			return
		}
		m.systemPool = pool
	})
	if m.systemPoolErr != nil {
		return nil, fmt.Errorf("system trust store: %w", m.systemPoolErr)
	}
	if m.systemPool == nil {
		return nil, errors.New("system trust store unavailable")
	}
	return m.systemPool, nil
}
