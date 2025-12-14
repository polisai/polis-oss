package tls

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetSecurityDefaults(t *testing.T) {
	defaults := GetSecurityDefaults()

	if defaults == nil {
		t.Fatal("Security defaults should not be nil")
	}

	// Check that secure cipher suites are configured
	if len(defaults.SecureCipherSuites) == 0 {
		t.Error("Expected secure cipher suites to be configured")
	}

	// Check minimum TLS version
	if defaults.MinTLSVersion != tls.VersionTLS12 {
		t.Errorf("Expected minimum TLS version to be 1.2, got %d", defaults.MinTLSVersion)
	}

	// Check security headers
	expectedHeaders := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"X-Frame-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
		"Permissions-Policy",
	}

	for _, header := range expectedHeaders {
		if _, exists := defaults.SecurityHeaders[header]; !exists {
			t.Errorf("Expected security header %s to be configured", header)
		}
	}
}

func TestApplySecureDefaults(t *testing.T) {
	config := &tls.Config{}
	defaults := GetSecurityDefaults()

	ApplySecureDefaults(config, defaults)

	// Check cipher suites were applied
	if len(config.CipherSuites) == 0 {
		t.Error("Expected cipher suites to be applied")
	}

	// Check minimum TLS version
	if config.MinVersion != defaults.MinTLSVersion {
		t.Errorf("Expected MinVersion to be %d, got %d", defaults.MinTLSVersion, config.MinVersion)
	}

	// Check performance settings
	if !config.PreferServerCipherSuites {
		t.Error("Expected PreferServerCipherSuites to be true")
	}

	if config.SessionTicketsDisabled {
		t.Error("Expected SessionTicketsDisabled to be false for performance")
	}

	if config.Renegotiation != tls.RenegotiateNever {
		t.Error("Expected Renegotiation to be RenegotiateNever for security")
	}
}

func TestValidateCipherSuiteSecurity(t *testing.T) {
	tests := []struct {
		name         string
		cipherSuites []uint16
		expectError  bool
	}{
		{
			name:         "Empty cipher suites (use defaults)",
			cipherSuites: []uint16{},
			expectError:  false,
		},
		{
			name: "Secure cipher suites",
			cipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			expectError: false,
		},
		{
			name: "Insecure RC4 cipher",
			cipherSuites: []uint16{
				tls.TLS_RSA_WITH_RC4_128_SHA,
			},
			expectError: true,
		},
		{
			name: "Insecure 3DES cipher",
			cipherSuites: []uint16{
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			expectError: true,
		},
		{
			name: "Vulnerable CBC cipher",
			cipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCipherSuiteSecurity(tt.cipherSuites)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	headers := map[string]string{
		"X-Test-Header": "test-value",
		"X-Security":    "enabled",
	}

	middleware := NewSecurityHeadersMiddleware(headers)

	// Test with httptest
	handler := middleware.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check that security headers were added
	for name, expectedValue := range headers {
		if actualValue := w.Header().Get(name); actualValue != expectedValue {
			t.Errorf("Expected header %s to be %s, got %s", name, expectedValue, actualValue)
		}
	}
}

func TestSecurityHeadersMiddleware_DoesNotOverrideExisting(t *testing.T) {
	headers := map[string]string{
		"X-Test-Header": "middleware-value",
	}

	middleware := NewSecurityHeadersMiddleware(headers)

	handler := middleware.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set header before middleware
		w.Header().Set("X-Test-Header", "handler-value")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should keep the handler's value, not override with middleware value
	if actualValue := w.Header().Get("X-Test-Header"); actualValue != "handler-value" {
		t.Errorf("Expected header to keep handler value 'handler-value', got %s", actualValue)
	}
}

func TestGetCipherSuiteName(t *testing.T) {
	tests := []struct {
		suite    uint16
		expected string
	}{
		{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{tls.TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA"},
		{0x9999, "unknown(0x9999)"}, // Unknown cipher suite
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			actual := getCipherSuiteName(tt.suite)
			if actual != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, actual)
			}
		})
	}
}
