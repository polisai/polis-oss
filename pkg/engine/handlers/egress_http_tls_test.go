package handlers

import (
	"crypto/tls"
	"log/slog"
	"net/url"
	"testing"

	"github.com/polisai/polis-oss/pkg/config"
	"github.com/polisai/polis-oss/pkg/domain"
)

func TestEgressHTTPHandler_ConfigureUpstreamTLS(t *testing.T) {
	logger := slog.Default()
	handler := NewEgressHTTPHandler(logger)

	tests := []struct {
		name            string
		nodeConfig      map[string]interface{}
		targetURL       string
		expectError     bool
		expectTransport bool
	}{
		{
			name:            "HTTP URL - no TLS needed",
			nodeConfig:      map[string]interface{}{},
			targetURL:       "http://example.com",
			expectError:     false,
			expectTransport: false,
		},
		{
			name:            "HTTPS URL - no upstream TLS config",
			nodeConfig:      map[string]interface{}{},
			targetURL:       "https://example.com",
			expectError:     false,
			expectTransport: false,
		},
		{
			name: "HTTPS URL - upstream TLS disabled",
			nodeConfig: map[string]interface{}{
				"upstream_tls": map[string]interface{}{
					"enabled": false,
				},
			},
			targetURL:       "https://example.com",
			expectError:     false,
			expectTransport: false,
		},
		{
			name: "HTTPS URL - basic upstream TLS config",
			nodeConfig: map[string]interface{}{
				"upstream_tls": map[string]interface{}{
					"enabled":     true,
					"server_name": "api.example.com",
					"min_version": "1.2",
				},
			},
			targetURL:       "https://example.com",
			expectError:     false,
			expectTransport: true,
		},
		{
			name: "HTTPS URL - insecure skip verify",
			nodeConfig: map[string]interface{}{
				"upstream_tls": map[string]interface{}{
					"enabled":              true,
					"insecure_skip_verify": true,
				},
			},
			targetURL:       "https://example.com",
			expectError:     false,
			expectTransport: true,
		},
		{
			name: "HTTPS URL - invalid TLS version",
			nodeConfig: map[string]interface{}{
				"upstream_tls": map[string]interface{}{
					"enabled":     true,
					"min_version": "invalid",
				},
			},
			targetURL:   "https://example.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &domain.PipelineNode{
				ID:     "test-node",
				Config: tt.nodeConfig,
			}

			pipelineCtx := &domain.PipelineContext{
				Variables: make(map[string]interface{}),
			}

			targetURL, err := url.Parse(tt.targetURL)
			if err != nil {
				t.Fatalf("Failed to parse target URL: %v", err)
			}

			err = handler.configureUpstreamTLS(node, pipelineCtx, targetURL)

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

			if tt.expectTransport {
				if _, ok := pipelineCtx.Variables["egress.tls_transport"]; !ok {
					t.Errorf("Expected TLS transport to be configured")
				}
			} else {
				if _, ok := pipelineCtx.Variables["egress.tls_transport"]; ok {
					t.Errorf("Did not expect TLS transport to be configured")
				}
			}
		})
	}
}

func TestEgressHTTPHandler_ExtractUpstreamTLSConfig(t *testing.T) {
	handler := NewEgressHTTPHandler(slog.Default())

	tests := []struct {
		name        string
		nodeConfig  map[string]interface{}
		expectNil   bool
		expectError bool
		expected    *config.UpstreamTLSConfig
	}{
		{
			name:       "No upstream TLS config",
			nodeConfig: map[string]interface{}{},
			expectNil:  true,
		},
		{
			name: "Upstream TLS disabled",
			nodeConfig: map[string]interface{}{
				"upstream_tls": map[string]interface{}{
					"enabled": false,
				},
			},
			expectNil: true,
		},
		{
			name: "Basic upstream TLS config",
			nodeConfig: map[string]interface{}{
				"upstream_tls": map[string]interface{}{
					"enabled":     true,
					"server_name": "api.example.com",
					"min_version": "1.2",
				},
			},
			expected: &config.UpstreamTLSConfig{
				Enabled:    true,
				ServerName: "api.example.com",
				MinVersion: "1.2",
			},
		},
		{
			name: "Full upstream TLS config",
			nodeConfig: map[string]interface{}{
				"upstream_tls": map[string]interface{}{
					"enabled":              true,
					"server_name":          "api.example.com",
					"insecure_skip_verify": true,
					"ca_file":              "/path/to/ca.crt",
					"cert_file":            "/path/to/client.crt",
					"key_file":             "/path/to/client.key",
					"min_version":          "1.2",
					"cipher_suites":        []interface{}{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				},
			},
			expected: &config.UpstreamTLSConfig{
				Enabled:            true,
				ServerName:         "api.example.com",
				InsecureSkipVerify: true,
				CAFile:             "/path/to/ca.crt",
				CertFile:           "/path/to/client.crt",
				KeyFile:            "/path/to/client.key",
				MinVersion:         "1.2",
				CipherSuites:       []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			},
		},
		{
			name: "Invalid upstream TLS config - not an object",
			nodeConfig: map[string]interface{}{
				"upstream_tls": "invalid",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.extractUpstreamTLSConfig(tt.nodeConfig)

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

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result but got: %+v", result)
				}
				return
			}

			if result == nil {
				t.Errorf("Expected non-nil result")
				return
			}

			if result.Enabled != tt.expected.Enabled {
				t.Errorf("Expected Enabled=%v, got %v", tt.expected.Enabled, result.Enabled)
			}
			if result.ServerName != tt.expected.ServerName {
				t.Errorf("Expected ServerName=%q, got %q", tt.expected.ServerName, result.ServerName)
			}
			if result.InsecureSkipVerify != tt.expected.InsecureSkipVerify {
				t.Errorf("Expected InsecureSkipVerify=%v, got %v", tt.expected.InsecureSkipVerify, result.InsecureSkipVerify)
			}
			if result.MinVersion != tt.expected.MinVersion {
				t.Errorf("Expected MinVersion=%q, got %q", tt.expected.MinVersion, result.MinVersion)
			}
		})
	}
}

func TestEgressHTTPHandler_BuildUpstreamTLSConfig(t *testing.T) {
	handler := NewEgressHTTPHandler(slog.Default())

	tests := []struct {
		name        string
		upstreamTLS *config.UpstreamTLSConfig
		targetURL   string
		expectError bool
		validate    func(*testing.T, *tls.Config)
	}{
		{
			name: "Basic TLS config",
			upstreamTLS: &config.UpstreamTLSConfig{
				Enabled:    true,
				ServerName: "api.example.com",
				MinVersion: "1.2",
			},
			targetURL: "https://example.com",
			validate: func(t *testing.T, cfg *tls.Config) {
				if cfg.ServerName != "api.example.com" {
					t.Errorf("Expected ServerName=api.example.com, got %s", cfg.ServerName)
				}
				if cfg.MinVersion != tls.VersionTLS12 {
					t.Errorf("Expected MinVersion=TLS 1.2, got %d", cfg.MinVersion)
				}
			},
		},
		{
			name: "Insecure skip verify",
			upstreamTLS: &config.UpstreamTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
			targetURL: "https://example.com",
			validate: func(t *testing.T, cfg *tls.Config) {
				if !cfg.InsecureSkipVerify {
					t.Errorf("Expected InsecureSkipVerify=true")
				}
				if cfg.ServerName != "example.com" {
					t.Errorf("Expected ServerName=example.com (from URL), got %s", cfg.ServerName)
				}
			},
		},
		{
			name: "Invalid TLS version",
			upstreamTLS: &config.UpstreamTLSConfig{
				Enabled:    true,
				MinVersion: "invalid",
			},
			targetURL:   "https://example.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetURL, err := url.Parse(tt.targetURL)
			if err != nil {
				t.Fatalf("Failed to parse target URL: %v", err)
			}

			result, err := handler.buildUpstreamTLSConfig(tt.upstreamTLS, targetURL)

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

			if result == nil {
				t.Errorf("Expected non-nil TLS config")
				return
			}

			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestEgressHTTPHandler_ParseTLSVersion(t *testing.T) {
	handler := NewEgressHTTPHandler(slog.Default())

	tests := []struct {
		version  string
		expected uint16
		wantErr  bool
	}{
		{"1.0", tls.VersionTLS10, false},
		{"1.1", tls.VersionTLS11, false},
		{"1.2", tls.VersionTLS12, false},
		{"1.3", tls.VersionTLS13, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result, err := handler.parseTLSVersion(tt.version)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for version %q", tt.version)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for version %q: %v", tt.version, err)
				return
			}

			if result != tt.expected {
				t.Errorf("Expected %d for version %q, got %d", tt.expected, tt.version, result)
			}
		})
	}
}

func TestEgressHTTPHandler_ParseCipherSuites(t *testing.T) {
	handler := NewEgressHTTPHandler(slog.Default())

	tests := []struct {
		name        string
		suiteNames  []string
		expectError bool
		expected    []uint16
	}{
		{
			name:       "Valid cipher suites",
			suiteNames: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			expected:   []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		{
			name:        "Invalid cipher suite",
			suiteNames:  []string{"INVALID_CIPHER_SUITE"},
			expectError: true,
		},
		{
			name:     "Empty list",
			expected: []uint16{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.parseCipherSuites(tt.suiteNames)

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

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d cipher suites, got %d", len(tt.expected), len(result))
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("Expected cipher suite %d at index %d, got %d", expected, i, result[i])
				}
			}
		})
	}
}
