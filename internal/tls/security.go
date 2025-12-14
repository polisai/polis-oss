package tls

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SecurityDefaults provides secure default configurations for TLS
type SecurityDefaults struct {
	// Secure cipher suites ordered by preference (strongest first)
	SecureCipherSuites []uint16
	// Minimum TLS version for security
	MinTLSVersion uint16
	// Maximum TLS version (0 means use Go's default)
	MaxTLSVersion uint16
	// Security headers to add to responses
	SecurityHeaders map[string]string
	// Session ticket keys rotation interval
	SessionTicketKeyRotationInterval time.Duration
}

// GetSecurityDefaults returns the recommended secure defaults for TLS configuration
func GetSecurityDefaults() *SecurityDefaults {
	return &SecurityDefaults{
		// Secure cipher suites in order of preference
		// Prioritize AEAD ciphers with forward secrecy
		SecureCipherSuites: []uint16{
			// TLS 1.3 cipher suites (handled automatically by Go)
			// TLS 1.2 ECDHE with AES-GCM (strongest)
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// ChaCha20-Poly1305 for mobile/ARM optimization
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		MinTLSVersion: tls.VersionTLS12, // TLS 1.2 minimum for security
		MaxTLSVersion: 0,                // Use Go's default (latest supported)
		SecurityHeaders: map[string]string{
			// HSTS - Force HTTPS for 1 year, include subdomains
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			// Prevent MIME type sniffing
			"X-Content-Type-Options": "nosniff",
			// XSS protection
			"X-XSS-Protection": "1; mode=block",
			// Prevent clickjacking
			"X-Frame-Options": "DENY",
			// Referrer policy for privacy
			"Referrer-Policy": "strict-origin-when-cross-origin",
			// Content Security Policy (basic)
			"Content-Security-Policy": "default-src 'self'",
			// Permissions policy
			"Permissions-Policy": "geolocation=(), microphone=(), camera=()",
		},
		SessionTicketKeyRotationInterval: 24 * time.Hour, // Rotate daily
	}
}

// ApplySecureDefaults applies secure defaults to a TLS configuration
func ApplySecureDefaults(config *tls.Config, defaults *SecurityDefaults) {
	if config == nil || defaults == nil {
		return
	}

	// Apply secure cipher suites if none are configured
	if len(config.CipherSuites) == 0 {
		config.CipherSuites = defaults.SecureCipherSuites
	}

	// Apply minimum TLS version if not set or insecure
	if config.MinVersion == 0 || config.MinVersion < defaults.MinTLSVersion {
		config.MinVersion = defaults.MinTLSVersion
	}

	// Apply maximum TLS version if specified
	if defaults.MaxTLSVersion > 0 {
		config.MaxVersion = defaults.MaxTLSVersion
	}

	// Enable session ticket key rotation for performance
	if config.SessionTicketKey == [32]byte{} {
		// Go will generate a random key automatically
		// We'll implement rotation in the server
	}

	// Performance optimizations
	config.PreferServerCipherSuites = true      // Server chooses cipher suite
	config.SessionTicketsDisabled = false       // Enable session resumption
	config.Renegotiation = tls.RenegotiateNever // Disable renegotiation for security
}

// ValidateCipherSuiteSecurity checks if cipher suites meet security requirements
func ValidateCipherSuiteSecurity(cipherSuites []uint16) error {
	if len(cipherSuites) == 0 {
		return nil // Will use secure defaults
	}

	insecureCiphers := map[uint16]string{
		// RC4 ciphers (broken)
		tls.TLS_RSA_WITH_RC4_128_SHA:         "RC4 is cryptographically broken",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:   "RC4 is cryptographically broken",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: "RC4 is cryptographically broken",

		// 3DES ciphers (weak)
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       "3DES is weak and deprecated",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "3DES is weak and deprecated",

		// Non-AEAD CBC ciphers (vulnerable to padding oracle attacks)
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:         "CBC mode without AEAD is vulnerable",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:         "CBC mode without AEAD is vulnerable",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:   "CBC mode without AEAD is vulnerable",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:   "CBC mode without AEAD is vulnerable",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: "CBC mode without AEAD is vulnerable",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: "CBC mode without AEAD is vulnerable",
	}

	var insecureFound []string
	for _, cipher := range cipherSuites {
		if reason, isInsecure := insecureCiphers[cipher]; isInsecure {
			cipherName := getCipherSuiteName(cipher)
			insecureFound = append(insecureFound, fmt.Sprintf("%s: %s", cipherName, reason))
		}
	}

	if len(insecureFound) > 0 {
		return fmt.Errorf("insecure cipher suites detected:\n%s", strings.Join(insecureFound, "\n"))
	}

	return nil
}

// getCipherSuiteName returns the name of a cipher suite
func getCipherSuiteName(suite uint16) string {
	names := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                      "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:                  "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:                  "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               "TLS_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               "TLS_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               "TLS_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	if name, exists := names[suite]; exists {
		return name
	}
	return fmt.Sprintf("unknown(0x%04x)", suite)
}

// SecurityHeadersMiddleware adds security headers to HTTP responses
type SecurityHeadersMiddleware struct {
	headers map[string]string
}

// NewSecurityHeadersMiddleware creates a new security headers middleware
func NewSecurityHeadersMiddleware(headers map[string]string) *SecurityHeadersMiddleware {
	if headers == nil {
		headers = GetSecurityDefaults().SecurityHeaders
	}
	return &SecurityHeadersMiddleware{
		headers: headers,
	}
}

// AddSecurityHeaders adds security headers to an HTTP response
func (m *SecurityHeadersMiddleware) AddSecurityHeaders(w http.ResponseWriter) {
	for name, value := range m.headers {
		// Don't override existing headers
		if w.Header().Get(name) == "" {
			w.Header().Set(name, value)
		}
	}
}

// WrapHandler wraps an HTTP handler to add security headers
func (m *SecurityHeadersMiddleware) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.AddSecurityHeaders(w)
		next.ServeHTTP(w, r)
	})
}

// PerformanceOptimizations contains TLS performance optimization settings
type PerformanceOptimizations struct {
	// Connection pooling settings
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration

	// TLS handshake settings
	HandshakeTimeout time.Duration

	// Buffer sizes for optimization
	ReadBufferSize  int
	WriteBufferSize int

	// Session resumption settings
	SessionCacheSize int
	SessionTimeout   time.Duration
}

// GetPerformanceDefaults returns optimized performance settings
func GetPerformanceDefaults() *PerformanceOptimizations {
	return &PerformanceOptimizations{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		HandshakeTimeout:    10 * time.Second,
		ReadBufferSize:      32 * 1024, // 32KB
		WriteBufferSize:     32 * 1024, // 32KB
		SessionCacheSize:    1000,      // Cache 1000 sessions
		SessionTimeout:      24 * time.Hour,
	}
}

// OptimizeTLSConfig applies performance optimizations to TLS configuration
func OptimizeTLSConfig(config *tls.Config, opts *PerformanceOptimizations) {
	if config == nil || opts == nil {
		return
	}

	// Enable session resumption for performance
	config.SessionTicketsDisabled = false

	// Create session cache for resumption
	if config.ClientSessionCache == nil {
		config.ClientSessionCache = tls.NewLRUClientSessionCache(opts.SessionCacheSize)
	}

	// Prefer server cipher suites for consistent performance
	config.PreferServerCipherSuites = true

	// Disable renegotiation for security and performance
	config.Renegotiation = tls.RenegotiateNever
}
