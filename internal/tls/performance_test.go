package tls

import (
	"crypto/tls"
	"log/slog"
	"testing"
	"time"
)

func TestGetPerformanceDefaults(t *testing.T) {
	defaults := GetPerformanceDefaults()

	if defaults == nil {
		t.Fatal("Performance defaults should not be nil")
	}

	// Check reasonable defaults
	if defaults.MaxIdleConns <= 0 {
		t.Error("Expected MaxIdleConns to be positive")
	}

	if defaults.HandshakeTimeout <= 0 {
		t.Error("Expected HandshakeTimeout to be positive")
	}

	if defaults.ReadBufferSize <= 0 {
		t.Error("Expected ReadBufferSize to be positive")
	}

	if defaults.WriteBufferSize <= 0 {
		t.Error("Expected WriteBufferSize to be positive")
	}

	if defaults.SessionCacheSize <= 0 {
		t.Error("Expected SessionCacheSize to be positive")
	}
}

func TestOptimizeTLSConfig(t *testing.T) {
	config := &tls.Config{}
	opts := GetPerformanceDefaults()

	OptimizeTLSConfig(config, opts)

	// Check that performance optimizations were applied
	if config.SessionTicketsDisabled {
		t.Error("Expected SessionTicketsDisabled to be false for performance")
	}

	if config.ClientSessionCache == nil {
		t.Error("Expected ClientSessionCache to be configured")
	}

	if !config.PreferServerCipherSuites {
		t.Error("Expected PreferServerCipherSuites to be true")
	}

	if config.Renegotiation != tls.RenegotiateNever {
		t.Error("Expected Renegotiation to be RenegotiateNever")
	}
}

func TestNewConnectionPool(t *testing.T) {
	logger := slog.Default()
	pool := NewConnectionPool(10, 5*time.Minute, logger)

	if pool == nil {
		t.Fatal("Connection pool should not be nil")
	}

	// Test cleanup
	defer pool.Close()

	// Pool should be empty initially
	pool.mu.RLock()
	if len(pool.connections) != 0 {
		t.Error("Expected empty connection pool initially")
	}
	pool.mu.RUnlock()
}

func TestNewHandshakeOptimizer(t *testing.T) {
	logger := slog.Default()
	optimizer := NewHandshakeOptimizer(100, logger)

	if optimizer == nil {
		t.Fatal("Handshake optimizer should not be nil")
	}

	defer optimizer.Close()

	if optimizer.sessionCache == nil {
		t.Error("Expected session cache to be configured")
	}
}

func TestHandshakeOptimizer_OptimizeServerConfig(t *testing.T) {
	logger := slog.Default()
	optimizer := NewHandshakeOptimizer(100, logger)
	defer optimizer.Close()

	config := &tls.Config{}
	optimizer.OptimizeServerConfig(config)

	// Check optimizations were applied
	if config.SessionTicketsDisabled {
		t.Error("Expected SessionTicketsDisabled to be false")
	}

	if !config.PreferServerCipherSuites {
		t.Error("Expected PreferServerCipherSuites to be true")
	}

	if config.Renegotiation != tls.RenegotiateNever {
		t.Error("Expected Renegotiation to be RenegotiateNever")
	}
}

func TestHandshakeOptimizer_OptimizeClientConfig(t *testing.T) {
	logger := slog.Default()
	optimizer := NewHandshakeOptimizer(100, logger)
	defer optimizer.Close()

	config := &tls.Config{}
	optimizer.OptimizeClientConfig(config)

	// Check client optimizations were applied
	if config.ClientSessionCache == nil {
		t.Error("Expected ClientSessionCache to be configured")
	}
}

func TestNewBufferPool(t *testing.T) {
	size := 1024
	pool := NewBufferPool(size)

	if pool == nil {
		t.Fatal("Buffer pool should not be nil")
	}

	// Test getting and putting buffers
	buf1 := pool.Get()
	if len(buf1) != size {
		t.Errorf("Expected buffer size %d, got %d", size, len(buf1))
	}

	buf2 := pool.Get()
	if len(buf2) != size {
		t.Errorf("Expected buffer size %d, got %d", size, len(buf2))
	}

	// Put buffers back
	pool.Put(buf1)
	pool.Put(buf2)

	// Get again - should reuse
	buf3 := pool.Get()
	if len(buf3) != size {
		t.Errorf("Expected buffer size %d, got %d", size, len(buf3))
	}
}

func TestNewMemoryOptimizer(t *testing.T) {
	logger := slog.Default()
	optimizer := NewMemoryOptimizer(1024, 2048, logger)

	if optimizer == nil {
		t.Fatal("Memory optimizer should not be nil")
	}

	// Test read buffer operations
	readBuf := optimizer.GetReadBuffer()
	if len(readBuf) != 1024 {
		t.Errorf("Expected read buffer size 1024, got %d", len(readBuf))
	}

	// Modify buffer to test clearing
	readBuf[0] = 0xFF
	optimizer.PutReadBuffer(readBuf)

	// Test write buffer operations
	writeBuf := optimizer.GetWriteBuffer()
	if len(writeBuf) != 2048 {
		t.Errorf("Expected write buffer size 2048, got %d", len(writeBuf))
	}

	// Modify buffer to test clearing
	writeBuf[0] = 0xFF
	optimizer.PutWriteBuffer(writeBuf)
}

func TestOptimizedTLSConfig(t *testing.T) {
	baseConfig := &tls.Config{
		MinVersion: tls.VersionTLS11, // Will be upgraded by security defaults
	}

	opts := GetPerformanceDefaults()
	security := GetSecurityDefaults()

	optimized := OptimizedTLSConfig(baseConfig, opts, security)

	if optimized == nil {
		t.Fatal("Optimized config should not be nil")
	}

	// Check that security defaults were applied (min version upgraded)
	if optimized.MinVersion < tls.VersionTLS12 {
		t.Errorf("Expected minimum TLS version to be upgraded to 1.2, got %d", optimized.MinVersion)
	}

	// Check that performance optimizations were applied
	if optimized.SessionTicketsDisabled {
		t.Error("Expected SessionTicketsDisabled to be false")
	}

	if optimized.ClientSessionCache == nil {
		t.Error("Expected ClientSessionCache to be configured")
	}

	// Check that cipher suites were applied
	if len(optimized.CipherSuites) == 0 {
		t.Error("Expected cipher suites to be configured")
	}
}

func TestOptimizedTLSConfig_NilInputs(t *testing.T) {
	// Test with nil base config
	optimized := OptimizedTLSConfig(nil, nil, nil)
	if optimized == nil {
		t.Fatal("Should create new config when base is nil")
	}

	// Test with nil options
	baseConfig := &tls.Config{}
	optimized = OptimizedTLSConfig(baseConfig, nil, nil)
	if optimized == nil {
		t.Fatal("Should handle nil options gracefully")
	}
}
