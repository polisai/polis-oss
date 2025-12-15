package tls

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"

	"github.com/polisai/polis-oss/pkg/config"
)

// TLSTerminator handles TLS termination operations
type TLSTerminator interface {
	BuildServerConfig(config config.TLSConfig) (*tls.Config, error)
	BuildClientConfig(config config.UpstreamTLSConfig) (*tls.Config, error)
	GetCertificateManager() CertificateManager
	GetHandshakeOptimizer() *HandshakeOptimizer
	GetMemoryOptimizer() *MemoryOptimizer
	GetSecurityDefaults() *SecurityDefaults
	GetPerformanceDefaults() *PerformanceOptimizations
	StartCertificateWatching(callback func()) error
	Close() error
}

// DefaultTLSTerminator implements TLS termination operations
type DefaultTLSTerminator struct {
	certManager         CertificateManager
	handshakeOptimizer  *HandshakeOptimizer
	memoryOptimizer     *MemoryOptimizer
	securityDefaults    *SecurityDefaults
	performanceDefaults *PerformanceOptimizations
	logger              *slog.Logger
}

// NewTLSTerminator creates a new TLS terminator with certificate management and optimizations
func NewTLSTerminator(logger *slog.Logger) *DefaultTLSTerminator {
	if logger == nil {
		logger = slog.Default()
	}

	// Initialize performance and security components
	securityDefaults := GetSecurityDefaults()
	performanceDefaults := GetPerformanceDefaults()
	handshakeOptimizer := NewHandshakeOptimizer(performanceDefaults.SessionCacheSize, logger)
	memoryOptimizer := NewMemoryOptimizer(performanceDefaults.ReadBufferSize, performanceDefaults.WriteBufferSize, logger)

	return &DefaultTLSTerminator{
		certManager:         NewFileCertificateManager(logger),
		handshakeOptimizer:  handshakeOptimizer,
		memoryOptimizer:     memoryOptimizer,
		securityDefaults:    securityDefaults,
		performanceDefaults: performanceDefaults,
		logger:              logger,
	}
}

// GetCertificateManager returns the certificate manager
func (t *DefaultTLSTerminator) GetCertificateManager() CertificateManager {
	return t.certManager
}

// BuildServerConfig constructs a TLS configuration for downstream listeners with SNI support
func (t *DefaultTLSTerminator) BuildServerConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("TLS is not enabled")
	}

	// Load the default certificate
	defaultCert, err := t.certManager.LoadCertificate(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load default certificate: %w", err)
	}

	// Add default certificate to manager
	if err := t.certManager.(*FileCertificateManager).AddCertificate("", cfg.CertFile, cfg.KeyFile); err != nil {
		return nil, fmt.Errorf("failed to add default certificate to manager: %w", err)
	}

	// Load SNI certificates
	for serverName, sniConfig := range cfg.SNI {
		if err := t.certManager.(*FileCertificateManager).AddCertificate(serverName, sniConfig.CertFile, sniConfig.KeyFile); err != nil {
			return nil, fmt.Errorf("failed to load SNI certificate for %q: %w", serverName, err)
		}
	}

	// Build TLS configuration with security and performance optimizations
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*defaultCert},
		MinVersion:   t.parseTLSVersion(cfg.MinVersion, t.securityDefaults.MinTLSVersion),
		MaxVersion:   t.parseTLSVersion(cfg.MaxVersion, t.securityDefaults.MaxTLSVersion),
		CipherSuites: t.parseCipherSuites(cfg.CipherSuites),
	}

	// Apply security defaults
	ApplySecureDefaults(tlsConfig, t.securityDefaults)

	// Apply performance optimizations
	OptimizeTLSConfig(tlsConfig, t.performanceDefaults)
	t.handshakeOptimizer.OptimizeServerConfig(tlsConfig)

	// Validate cipher suite security
	if err := ValidateCipherSuiteSecurity(tlsConfig.CipherSuites); err != nil {
		t.logger.Warn("Cipher suite security validation failed", "error", err)
		// Use secure defaults instead
		tlsConfig.CipherSuites = t.securityDefaults.SecureCipherSuites
		t.logger.Info("Applied secure cipher suite defaults")
	}

	// Set up SNI certificate selection
	tlsConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := t.certManager.GetCertificateForSNI(clientHello.ServerName)
		if err != nil {
			t.logger.Warn("SNI certificate selection failed, using default",
				"server_name", clientHello.ServerName,
				"error", err)
			return defaultCert, nil
		}
		return cert, nil
	}

	// Configure client authentication if required
	if cfg.ClientAuth.Required {
		if cfg.ClientAuth.CAFile == "" {
			return nil, fmt.Errorf("client CA file is required when client authentication is enabled")
		}

		caPool, err := loadCertPool(cfg.ClientAuth.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client CA bundle: %w", err)
		}

		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		// Set verify mode
		switch strings.ToLower(cfg.ClientAuth.VerifyMode) {
		case "strict", "":
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		case "trust-bundle-only":
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		default:
			return nil, fmt.Errorf("unsupported client auth verify mode: %q", cfg.ClientAuth.VerifyMode)
		}
	}

	return tlsConfig, nil
}

// BuildClientConfig constructs a TLS configuration for upstream clients
func (t *DefaultTLSTerminator) BuildClientConfig(cfg config.UpstreamTLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	clientConfig := &tls.Config{
		MinVersion:         t.parseTLSVersion(cfg.MinVersion, t.securityDefaults.MinTLSVersion),
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		CipherSuites:       t.parseCipherSuites(cfg.CipherSuites),
	}

	// Apply security defaults for client config
	ApplySecureDefaults(clientConfig, t.securityDefaults)

	// Apply performance optimizations for client config
	OptimizeTLSConfig(clientConfig, t.performanceDefaults)
	t.handshakeOptimizer.OptimizeClientConfig(clientConfig)

	// Validate cipher suite security for client
	if err := ValidateCipherSuiteSecurity(clientConfig.CipherSuites); err != nil {
		t.logger.Warn("Client cipher suite security validation failed", "error", err)
		// Use secure defaults instead
		clientConfig.CipherSuites = t.securityDefaults.SecureCipherSuites
		t.logger.Info("Applied secure client cipher suite defaults")
	}

	// Load client certificate if provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := t.certManager.LoadCertificate(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		clientConfig.Certificates = []tls.Certificate{*cert}
	}

	// Load custom CA bundle if provided
	if cfg.CAFile != "" {
		caPool, err := loadCertPool(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load upstream CA bundle: %w", err)
		}
		clientConfig.RootCAs = caPool
	}

	return clientConfig, nil
}

// parseTLSVersion converts string version to TLS constant
func (t *DefaultTLSTerminator) parseTLSVersion(version string, defaultVersion uint16) uint16 {
	if version == "" {
		return defaultVersion
	}

	switch strings.TrimSpace(version) {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		t.logger.Warn("Unknown TLS version, using default", "version", version, "default", defaultVersion)
		return defaultVersion
	}
}

// parseCipherSuites converts cipher suite names to constants
func (t *DefaultTLSTerminator) parseCipherSuites(suites []string) []uint16 {
	if len(suites) == 0 {
		return nil // Use default cipher suites
	}

	var cipherSuites []uint16
	cipherMap := map[string]uint16{
		"TLS_RSA_WITH_RC4_128_SHA":                      tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	for _, suite := range suites {
		if cipherID, exists := cipherMap[strings.TrimSpace(suite)]; exists {
			cipherSuites = append(cipherSuites, cipherID)
		} else {
			t.logger.Warn("Unknown cipher suite", "suite", suite)
		}
	}

	return cipherSuites
}

// StartCertificateWatching starts watching certificate files for changes
func (t *DefaultTLSTerminator) StartCertificateWatching(callback func()) error {
	return t.certManager.WatchCertificateFiles(callback)
}

// GetHandshakeOptimizer returns the handshake optimizer
func (t *DefaultTLSTerminator) GetHandshakeOptimizer() *HandshakeOptimizer {
	return t.handshakeOptimizer
}

// GetMemoryOptimizer returns the memory optimizer
func (t *DefaultTLSTerminator) GetMemoryOptimizer() *MemoryOptimizer {
	return t.memoryOptimizer
}

// GetSecurityDefaults returns the security defaults
func (t *DefaultTLSTerminator) GetSecurityDefaults() *SecurityDefaults {
	return t.securityDefaults
}

// GetPerformanceDefaults returns the performance defaults
func (t *DefaultTLSTerminator) GetPerformanceDefaults() *PerformanceOptimizations {
	return t.performanceDefaults
}

// Close cleans up resources
func (t *DefaultTLSTerminator) Close() error {
	var errs []error

	if err := t.certManager.Close(); err != nil {
		errs = append(errs, fmt.Errorf("certificate manager: %w", err))
	}

	if err := t.handshakeOptimizer.Close(); err != nil {
		errs = append(errs, fmt.Errorf("handshake optimizer: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("multiple errors during close: %v", errs)
	}

	return nil
}
