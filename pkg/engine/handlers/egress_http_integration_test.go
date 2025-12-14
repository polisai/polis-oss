package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

func TestEgressHTTPHandler_TLSTerminationModes(t *testing.T) {
	// Create test HTTPS server
	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message": "Hello from HTTPS upstream", "path": "%s"}`, r.URL.Path)
	}))
	defer httpsServer.Close()

	// Create test HTTP server
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message": "Hello from HTTP upstream", "path": "%s"}`, r.URL.Path)
	}))
	defer httpServer.Close()

	logger := slog.Default()
	handler := NewEgressHTTPHandler(logger)

	tests := []struct {
		name            string
		nodeConfig      map[string]interface{}
		upstreamURL     string
		expectError     bool
		expectTransport bool
		description     string
	}{
		{
			name: "HTTP to HTTP mode",
			nodeConfig: map[string]interface{}{
				"upstream_url": httpServer.URL,
			},
			upstreamURL:     httpServer.URL,
			expectError:     false,
			expectTransport: false,
			description:     "Standard HTTP to HTTP forwarding",
		},
		{
			name: "HTTPS to HTTPS mode - insecure skip verify",
			nodeConfig: map[string]interface{}{
				"upstream_url": httpsServer.URL,
				"upstream_tls": map[string]interface{}{
					"enabled":              true,
					"insecure_skip_verify": true,
				},
			},
			upstreamURL:     httpsServer.URL,
			expectError:     false,
			expectTransport: true,
			description:     "HTTPS to HTTPS with insecure skip verify",
		},
		{
			name: "HTTPS to HTTPS mode - with server name",
			nodeConfig: map[string]interface{}{
				"upstream_url": httpsServer.URL,
				"upstream_tls": map[string]interface{}{
					"enabled":              true,
					"server_name":          "example.com",
					"insecure_skip_verify": true, // Skip verify for test server
				},
			},
			upstreamURL:     httpsServer.URL,
			expectError:     false,
			expectTransport: true,
			description:     "HTTPS to HTTPS with custom server name",
		},
		{
			name: "HTTPS to HTTPS mode - TLS 1.2 minimum",
			nodeConfig: map[string]interface{}{
				"upstream_url": httpsServer.URL,
				"upstream_tls": map[string]interface{}{
					"enabled":              true,
					"min_version":          "1.2",
					"insecure_skip_verify": true,
				},
			},
			upstreamURL:     httpsServer.URL,
			expectError:     false,
			expectTransport: true,
			description:     "HTTPS to HTTPS with TLS 1.2 minimum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &domain.PipelineNode{
				ID:     "test-egress",
				Type:   "egress.http",
				Config: tt.nodeConfig,
			}

			pipelineCtx := &domain.PipelineContext{
				Request: domain.RequestContext{
					Method:  "GET",
					Path:    "/test",
					Headers: map[string][]string{},
				},
				Variables: make(map[string]interface{}),
			}

			// Execute the handler
			result, err := handler.Execute(context.Background(), node, pipelineCtx)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result.Outcome != runtime.OutcomeSuccess {
				t.Errorf("Expected success outcome, got %v", result.Outcome)
			}

			// Verify target URL is set
			targetURL, ok := pipelineCtx.Variables["egress.target_url"].(string)
			if !ok {
				t.Errorf("Expected egress.target_url to be set")
				return
			}

			expectedURL := tt.upstreamURL + "/test" // Path is appended by the handler
			if targetURL != expectedURL {
				t.Errorf("Expected target URL %s, got %s", expectedURL, targetURL)
			}

			// Verify TLS transport configuration
			if tt.expectTransport {
				if _, ok := pipelineCtx.Variables["egress.tls_transport"]; !ok {
					t.Errorf("Expected TLS transport to be configured")
				}
			} else {
				if _, ok := pipelineCtx.Variables["egress.tls_transport"]; ok {
					t.Errorf("Did not expect TLS transport to be configured")
				}
			}

			t.Logf("✓ %s: %s", tt.name, tt.description)
		})
	}
}

func TestEgressHTTPHandler_TLSConfigurationValidation(t *testing.T) {
	logger := slog.Default()
	handler := NewEgressHTTPHandler(logger)

	tests := []struct {
		name        string
		nodeConfig  map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "Invalid TLS version",
			nodeConfig: map[string]interface{}{
				"upstream_url": "https://example.com",
				"upstream_tls": map[string]interface{}{
					"enabled":     true,
					"min_version": "invalid_version",
				},
			},
			expectError: true,
			errorMsg:    "invalid min_version",
		},
		{
			name: "Invalid cipher suite",
			nodeConfig: map[string]interface{}{
				"upstream_url": "https://example.com",
				"upstream_tls": map[string]interface{}{
					"enabled":       true,
					"cipher_suites": []interface{}{"INVALID_CIPHER_SUITE"},
				},
			},
			expectError: true,
			errorMsg:    "invalid cipher_suites",
		},
		{
			name: "Client cert without key",
			nodeConfig: map[string]interface{}{
				"upstream_url": "https://example.com",
				"upstream_tls": map[string]interface{}{
					"enabled":   true,
					"cert_file": "/path/to/cert.pem",
					// Missing key_file
				},
			},
			expectError: true,
			errorMsg:    "key_file is required when cert_file is specified",
		},
		{
			name: "Client key without cert",
			nodeConfig: map[string]interface{}{
				"upstream_url": "https://example.com",
				"upstream_tls": map[string]interface{}{
					"enabled":  true,
					"key_file": "/path/to/key.pem",
					// Missing cert_file
				},
			},
			expectError: true,
			errorMsg:    "cert_file is required when key_file is specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &domain.PipelineNode{
				ID:     "test-egress",
				Type:   "egress.http",
				Config: tt.nodeConfig,
			}

			pipelineCtx := &domain.PipelineContext{
				Request: domain.RequestContext{
					Method:  "GET",
					Path:    "/test",
					Headers: map[string][]string{},
				},
				Variables: make(map[string]interface{}),
			}

			_, err := handler.Execute(context.Background(), node, pipelineCtx)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q but got none", tt.errorMsg)
					return
				}
				if tt.errorMsg != "" && !containsString(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestEgressHTTPHandler_TLSTransportCustomization(t *testing.T) {
	logger := slog.Default()
	handler := NewEgressHTTPHandler(logger)

	node := &domain.PipelineNode{
		ID:   "test-egress",
		Type: "egress.http",
		Config: map[string]interface{}{
			"upstream_url": "https://api.example.com",
			"upstream_tls": map[string]interface{}{
				"enabled":              true,
				"server_name":          "custom.example.com",
				"insecure_skip_verify": true,
				"min_version":          "1.2",
				"cipher_suites": []interface{}{
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				},
			},
		},
	}

	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:  "GET",
			Path:    "/api/v1/data",
			Headers: map[string][]string{},
		},
		Variables: make(map[string]interface{}),
	}

	_, err := handler.Execute(context.Background(), node, pipelineCtx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify TLS transport is configured
	transport, ok := pipelineCtx.Variables["egress.tls_transport"].(*http.Transport)
	if !ok {
		t.Fatalf("Expected TLS transport to be configured")
	}

	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		t.Fatalf("Expected TLS config to be set on transport")
	}

	// Verify TLS configuration
	if tlsConfig.ServerName != "custom.example.com" {
		t.Errorf("Expected ServerName=custom.example.com, got %s", tlsConfig.ServerName)
	}

	if !tlsConfig.InsecureSkipVerify {
		t.Errorf("Expected InsecureSkipVerify=true")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion=TLS 1.2, got %d", tlsConfig.MinVersion)
	}

	expectedCipherSuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	if len(tlsConfig.CipherSuites) != len(expectedCipherSuites) {
		t.Errorf("Expected %d cipher suites, got %d", len(expectedCipherSuites), len(tlsConfig.CipherSuites))
	}

	for i, expected := range expectedCipherSuites {
		if i >= len(tlsConfig.CipherSuites) || tlsConfig.CipherSuites[i] != expected {
			t.Errorf("Expected cipher suite %d at index %d, got %d", expected, i, tlsConfig.CipherSuites[i])
		}
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 0; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}
