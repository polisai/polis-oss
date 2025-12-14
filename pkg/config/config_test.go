package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigWithTLS(t *testing.T) {
	// Create a temporary config file with TLS settings
	configContent := `
server:
  admin_address: ":19090"
  data_address: ":8090"
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
    min_version: "1.2"
    cipher_suites:
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    client_auth:
      required: false
      ca_file: "/path/to/ca.pem"
    sni:
      "api.example.com":
        cert_file: "/path/to/api-cert.pem"
        key_file: "/path/to/api-key.pem"
  listen_params:
    - address: ":8080"
      protocol: "http"
    - address: ":8443"
      protocol: "https"
      tls:
        enabled: true
        cert_file: "/path/to/https-cert.pem"
        key_file: "/path/to/https-key.pem"
        min_version: "1.3"

telemetry:
  otlp_endpoint: "http://localhost:4317"
  insecure: true

control_plane:
  address: "localhost:9090"
  mtls_enabled: false

pipeline:
  file: "pipeline.yaml"

logging:
  level: "info"
`

	// Create temporary file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load configuration
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify TLS configuration
	if cfg.Server.TLS == nil {
		t.Fatal("Expected TLS configuration to be present")
	}

	tls := cfg.Server.TLS
	if !tls.Enabled {
		t.Error("Expected TLS to be enabled")
	}
	if tls.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected cert_file to be '/path/to/cert.pem', got %q", tls.CertFile)
	}
	if tls.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected key_file to be '/path/to/key.pem', got %q", tls.KeyFile)
	}
	if tls.MinVersion != "1.2" {
		t.Errorf("Expected min_version to be '1.2', got %q", tls.MinVersion)
	}

	// Verify cipher suites
	expectedCipherSuites := []string{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
	if len(tls.CipherSuites) != len(expectedCipherSuites) {
		t.Errorf("Expected %d cipher suites, got %d", len(expectedCipherSuites), len(tls.CipherSuites))
	}
	for i, expected := range expectedCipherSuites {
		if i >= len(tls.CipherSuites) || tls.CipherSuites[i] != expected {
			t.Errorf("Expected cipher suite %d to be %q, got %q", i, expected, tls.CipherSuites[i])
		}
	}

	// Verify client auth
	if tls.ClientAuth.Required {
		t.Error("Expected client auth to not be required")
	}
	if tls.ClientAuth.CAFile != "/path/to/ca.pem" {
		t.Errorf("Expected client auth ca_file to be '/path/to/ca.pem', got %q", tls.ClientAuth.CAFile)
	}

	// Verify SNI configuration
	if len(tls.SNI) != 1 {
		t.Errorf("Expected 1 SNI configuration, got %d", len(tls.SNI))
	}
	sniConfig, exists := tls.SNI["api.example.com"]
	if !exists {
		t.Error("Expected SNI configuration for 'api.example.com'")
	} else {
		if sniConfig.CertFile != "/path/to/api-cert.pem" {
			t.Errorf("Expected SNI cert_file to be '/path/to/api-cert.pem', got %q", sniConfig.CertFile)
		}
		if sniConfig.KeyFile != "/path/to/api-key.pem" {
			t.Errorf("Expected SNI key_file to be '/path/to/api-key.pem', got %q", sniConfig.KeyFile)
		}
	}

	// Verify listen parameters
	if len(cfg.Server.ListenParams) != 2 {
		t.Errorf("Expected 2 listen parameters, got %d", len(cfg.Server.ListenParams))
	}

	// Check HTTP listener
	httpListener := cfg.Server.ListenParams[0]
	if httpListener.Address != ":8080" {
		t.Errorf("Expected HTTP listener address to be ':8080', got %q", httpListener.Address)
	}
	if httpListener.Protocol != "http" {
		t.Errorf("Expected HTTP listener protocol to be 'http', got %q", httpListener.Protocol)
	}

	// Check HTTPS listener
	httpsListener := cfg.Server.ListenParams[1]
	if httpsListener.Address != ":8443" {
		t.Errorf("Expected HTTPS listener address to be ':8443', got %q", httpsListener.Address)
	}
	if httpsListener.Protocol != "https" {
		t.Errorf("Expected HTTPS listener protocol to be 'https', got %q", httpsListener.Protocol)
	}
	if httpsListener.TLS == nil {
		t.Fatal("Expected HTTPS listener to have TLS configuration")
	}
	if !httpsListener.TLS.Enabled {
		t.Error("Expected HTTPS listener TLS to be enabled")
	}
	if httpsListener.TLS.MinVersion != "1.3" {
		t.Errorf("Expected HTTPS listener min_version to be '1.3', got %q", httpsListener.TLS.MinVersion)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		wantErr     bool
		expectedErr string
	}{
		{
			name: "valid config without TLS",
			config: Config{
				Server: ServerConfig{
					AdminAddress: ":19090",
					DataAddress:  ":8090",
				},
				Pipeline: PipelineConfig{
					File: "pipeline.yaml",
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with TLS",
			config: Config{
				Server: ServerConfig{
					AdminAddress: ":19090",
					DataAddress:  ":8090",
					TLS: &TLSConfig{
						Enabled:  true,
						CertFile: "/path/to/cert.pem",
						KeyFile:  "/path/to/key.pem",
					},
				},
				Pipeline: PipelineConfig{
					File: "pipeline.yaml",
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid TLS config",
			config: Config{
				Server: ServerConfig{
					AdminAddress: ":19090",
					DataAddress:  ":8090",
					TLS: &TLSConfig{
						Enabled: true,
						// Missing cert and key files
					},
				},
				Pipeline: PipelineConfig{
					File: "pipeline.yaml",
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr:     true,
			expectedErr: "required field 'cert_file' is missing",
		},
		{
			name: "invalid log level",
			config: Config{
				Server: ServerConfig{
					AdminAddress: ":19090",
					DataAddress:  ":8090",
				},
				Pipeline: PipelineConfig{
					File: "pipeline.yaml",
				},
				Logging: LoggingConfig{
					Level: "invalid",
				},
			},
			wantErr:     true,
			expectedErr: "invalid log level",
		},
		{
			name: "duplicate listen parameter addresses",
			config: Config{
				Server: ServerConfig{
					AdminAddress: ":19090",
					DataAddress:  ":8090",
					ListenParams: []ListenParamConfig{
						{Address: ":8080", Protocol: "http"},
						{
							Address:  ":8080",
							Protocol: "https",
							TLS: &TLSConfig{
								Enabled:  true,
								CertFile: "/path/to/cert.pem",
								KeyFile:  "/path/to/key.pem",
							},
						},
					},
				},
				Pipeline: PipelineConfig{
					File: "pipeline.yaml",
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr:     true,
			expectedErr: "duplicate listen parameter address",
		},
		{
			name: "listen parameter conflicts with admin address",
			config: Config{
				Server: ServerConfig{
					AdminAddress: ":19090",
					DataAddress:  ":8090",
					ListenParams: []ListenParamConfig{
						{Address: ":19090", Protocol: "http"},
					},
				},
				Pipeline: PipelineConfig{
					File: "pipeline.yaml",
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr:     true,
			expectedErr: "conflicts with admin_address",
		},
		{
			name: "HTTPS listener without TLS configuration",
			config: Config{
				Server: ServerConfig{
					AdminAddress: ":19090",
					DataAddress:  ":8090",
					ListenParams: []ListenParamConfig{
						{Address: ":8443", Protocol: "https"},
					},
				},
				Pipeline: PipelineConfig{
					File: "pipeline.yaml",
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr:     true,
			expectedErr: "TLS configuration is required for HTTPS protocol",
		},
		{
			name: "valid mixed HTTP/HTTPS listeners",
			config: Config{
				Server: ServerConfig{
					AdminAddress: ":19090",
					DataAddress:  ":8090",
					ListenParams: []ListenParamConfig{
						{Address: ":8080", Protocol: "http"},
						{
							Address:  ":8443",
							Protocol: "https",
							TLS: &TLSConfig{
								Enabled:  true,
								CertFile: "/path/to/cert.pem",
								KeyFile:  "/path/to/key.pem",
							},
						},
					},
				},
				Pipeline: PipelineConfig{
					File: "pipeline.yaml",
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Config.Validate() expected error but got none")
				} else if tt.expectedErr != "" && !contains(err.Error(), tt.expectedErr) {
					t.Errorf("Config.Validate() error = %v, expected to contain %q", err, tt.expectedErr)
				}
			} else {
				if err != nil {
					t.Errorf("Config.Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestEnvironmentOverrides(t *testing.T) {
	// Set environment variables
	os.Setenv("PROXY_TLS_ENABLED", "true")
	os.Setenv("PROXY_TLS_CERT_FILE", "/env/cert.pem")
	os.Setenv("PROXY_TLS_KEY_FILE", "/env/key.pem")
	os.Setenv("PROXY_TLS_MIN_VERSION", "1.3")
	os.Setenv("PROXY_PIPELINE_FILE", "test-pipeline.yaml")
	defer func() {
		os.Unsetenv("PROXY_TLS_ENABLED")
		os.Unsetenv("PROXY_TLS_CERT_FILE")
		os.Unsetenv("PROXY_TLS_KEY_FILE")
		os.Unsetenv("PROXY_TLS_MIN_VERSION")
		os.Unsetenv("PROXY_PIPELINE_FILE")
	}()

	// Load config without file (should use defaults + env overrides)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify TLS configuration from environment
	if cfg.Server.TLS == nil {
		t.Fatal("Expected TLS configuration to be present from environment")
	}

	tls := cfg.Server.TLS
	if !tls.Enabled {
		t.Error("Expected TLS to be enabled from environment")
	}
	if tls.CertFile != "/env/cert.pem" {
		t.Errorf("Expected cert_file to be '/env/cert.pem', got %q", tls.CertFile)
	}
	if tls.KeyFile != "/env/key.pem" {
		t.Errorf("Expected key_file to be '/env/key.pem', got %q", tls.KeyFile)
	}
	if tls.MinVersion != "1.3" {
		t.Errorf("Expected min_version to be '1.3', got %q", tls.MinVersion)
	}
}

func TestMultiListenerEnvironmentOverrides(t *testing.T) {
	// Set environment variables for multi-listener configuration
	os.Setenv("PROXY_TLS_ENABLED", "true")
	os.Setenv("PROXY_TLS_CERT_FILE", "/env/cert.pem")
	os.Setenv("PROXY_TLS_KEY_FILE", "/env/key.pem")
	os.Setenv("PROXY_LISTEN_PARAMS", ":8080:http,:8443:https")
	os.Setenv("PROXY_PIPELINE_FILE", "test-pipeline.yaml")
	defer func() {
		os.Unsetenv("PROXY_TLS_ENABLED")
		os.Unsetenv("PROXY_TLS_CERT_FILE")
		os.Unsetenv("PROXY_TLS_KEY_FILE")
		os.Unsetenv("PROXY_LISTEN_PARAMS")
		os.Unsetenv("PROXY_PIPELINE_FILE")
	}()

	// Load config without file (should use defaults + env overrides)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify listen parameters from environment
	if len(cfg.Server.ListenParams) != 2 {
		t.Errorf("Expected 2 listen parameters from environment, got %d", len(cfg.Server.ListenParams))
	}

	// Check HTTP listener
	httpListener := cfg.Server.ListenParams[0]
	if httpListener.Address != ":8080" {
		t.Errorf("Expected HTTP listener address to be ':8080', got %q", httpListener.Address)
	}
	if httpListener.Protocol != "http" {
		t.Errorf("Expected HTTP listener protocol to be 'http', got %q", httpListener.Protocol)
	}

	// Check HTTPS listener
	httpsListener := cfg.Server.ListenParams[1]
	if httpsListener.Address != ":8443" {
		t.Errorf("Expected HTTPS listener address to be ':8443', got %q", httpsListener.Address)
	}
	if httpsListener.Protocol != "https" {
		t.Errorf("Expected HTTPS listener protocol to be 'https', got %q", httpsListener.Protocol)
	}
	if httpsListener.TLS == nil {
		t.Fatal("Expected HTTPS listener to have TLS configuration")
	}
	if !httpsListener.TLS.Enabled {
		t.Error("Expected HTTPS listener TLS to be enabled")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
