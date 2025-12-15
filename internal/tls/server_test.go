package tls

import (
	"context"
	"crypto/tls"
	"log/slog"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/config"
	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
	"github.com/polisai/polis-oss/pkg/storage"
)

func TestNewTLSServer(t *testing.T) {
	logger := slog.Default()

	// Create a minimal DAG handler for testing
	registry := pipelinepkg.NewPipelineRegistry(pipelinepkg.NewEngineFactory(storage.NewMemoryPolicyStore(), logger))
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
		Logger:   logger,
	})

	tests := []struct {
		name        string
		config      *config.TLSConfig
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "disabled TLS",
			config: &config.TLSConfig{
				Enabled: false,
			},
			expectError: true,
		},
		{
			name: "missing certificate files",
			config: &config.TLSConfig{
				Enabled:  true,
				CertFile: "",
				KeyFile:  "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewTLSServer(tt.config, dagHandler, logger)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if server != nil {
					t.Errorf("Expected nil server but got %v", server)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if server == nil {
					t.Errorf("Expected server but got nil")
				}
			}
		})
	}
}

func TestTLSServer_GetTLSMetrics(t *testing.T) {
	logger := slog.Default()

	// Create a minimal DAG handler for testing
	registry := pipelinepkg.NewPipelineRegistry(pipelinepkg.NewEngineFactory(storage.NewMemoryPolicyStore(), logger))
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
		Logger:   logger,
	})

	// Create TLS server with valid config (will fail cert loading but that's ok for metrics test)
	cfg := &config.TLSConfig{
		Enabled:  true,
		CertFile: "nonexistent.crt",
		KeyFile:  "nonexistent.key",
	}

	// This will fail due to missing cert files, but we can still test the metrics structure
	server, err := NewTLSServer(cfg, dagHandler, logger)
	if err == nil {
		t.Skip("Expected cert loading to fail, but it didn't - skipping metrics test")
	}

	// Create server with minimal setup for metrics testing
	server = &TLSServer{
		config: cfg,
		logger: logger,
		metrics: &TLSMetrics{
			TLSVersionDistribution:  make(map[string]int64),
			CipherSuiteDistribution: make(map[string]int64),
		},
	}

	// Test initial metrics
	metrics := server.GetTLSMetrics()
	if metrics == nil {
		t.Fatal("Expected metrics but got nil")
	}

	if metrics.ConnectionsTotal != 0 {
		t.Errorf("Expected 0 total connections, got %d", metrics.ConnectionsTotal)
	}

	if metrics.ConnectionsActive != 0 {
		t.Errorf("Expected 0 active connections, got %d", metrics.ConnectionsActive)
	}

	if len(metrics.TLSVersionDistribution) != 0 {
		t.Errorf("Expected empty TLS version distribution, got %v", metrics.TLSVersionDistribution)
	}
}

func TestTLSServer_UpdateConnectionMetrics(t *testing.T) {
	server := &TLSServer{
		logger: slog.Default(),
		metrics: &TLSMetrics{
			TLSVersionDistribution:  make(map[string]int64),
			CipherSuiteDistribution: make(map[string]int64),
		},
	}

	// Test incrementing active connections
	server.updateConnectionMetrics(1, 0)
	metrics := server.GetTLSMetrics()

	if metrics.ConnectionsTotal != 1 {
		t.Errorf("Expected 1 total connection, got %d", metrics.ConnectionsTotal)
	}
	if metrics.ConnectionsActive != 1 {
		t.Errorf("Expected 1 active connection, got %d", metrics.ConnectionsActive)
	}

	// Test decrementing active connections
	server.updateConnectionMetrics(-1, 0)
	metrics = server.GetTLSMetrics()

	if metrics.ConnectionsTotal != 1 {
		t.Errorf("Expected 1 total connection, got %d", metrics.ConnectionsTotal)
	}
	if metrics.ConnectionsActive != 0 {
		t.Errorf("Expected 0 active connections, got %d", metrics.ConnectionsActive)
	}

	// Test incrementing errors
	server.updateConnectionMetrics(0, 1)
	metrics = server.GetTLSMetrics()

	if metrics.HandshakeErrors != 1 {
		t.Errorf("Expected 1 handshake error, got %d", metrics.HandshakeErrors)
	}
}

func TestTLSServer_TLSVersionString(t *testing.T) {
	server := &TLSServer{logger: slog.Default()}

	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "1.0"},
		{tls.VersionTLS11, "1.1"},
		{tls.VersionTLS12, "1.2"},
		{tls.VersionTLS13, "1.3"},
		{0x9999, "unknown(0x9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := server.tlsVersionString(tt.version)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestTLSServer_CipherSuiteString(t *testing.T) {
	server := &TLSServer{logger: slog.Default()}

	tests := []struct {
		suite    uint16
		expected string
	}{
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{0x9999, "unknown(0x9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := server.cipherSuiteString(tt.suite)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestTLSServer_UpdateHandshakeMetrics(t *testing.T) {
	server := &TLSServer{
		logger: slog.Default(),
		metrics: &TLSMetrics{
			TLSVersionDistribution:  make(map[string]int64),
			CipherSuiteDistribution: make(map[string]int64),
		},
	}

	tlsCtx := &domain.TLSContext{
		Version:           "1.2",
		CipherSuite:       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		HandshakeDuration: 100 * time.Millisecond,
	}

	server.updateHandshakeMetrics(tlsCtx)
	metrics := server.GetTLSMetrics()

	if metrics.TLSVersionDistribution["1.2"] != 1 {
		t.Errorf("Expected TLS 1.2 count to be 1, got %d", metrics.TLSVersionDistribution["1.2"])
	}

	if metrics.CipherSuiteDistribution["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] != 1 {
		t.Errorf("Expected cipher suite count to be 1, got %d", metrics.CipherSuiteDistribution["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"])
	}

	if metrics.HandshakeDuration != 100*time.Millisecond {
		t.Errorf("Expected handshake duration to be 100ms, got %v", metrics.HandshakeDuration)
	}
}

func TestTLSServer_Shutdown(t *testing.T) {
	server := &TLSServer{
		logger:   slog.Default(),
		running:  false,
		shutdown: make(chan struct{}),
		metrics: &TLSMetrics{
			TLSVersionDistribution:  make(map[string]int64),
			CipherSuiteDistribution: make(map[string]int64),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Test shutdown of non-running server
	err := server.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected error shutting down non-running server: %v", err)
	}
}
