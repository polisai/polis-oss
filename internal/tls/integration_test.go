package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/config"
	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
	"github.com/polisai/polis-oss/pkg/storage"
)

func TestTLSServerIntegration(t *testing.T) {
	// Skip if we can't create test certificates
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "server.crt")
	keyFile := filepath.Join(certDir, "server.key")

	// Generate test certificates
	if err := GenerateTestCertificates(certDir); err != nil {
		t.Skipf("Cannot generate test certificates: %v", err)
	}

	// Use the generated server certificate files
	certFile = filepath.Join(certDir, "server.crt")
	keyFile = filepath.Join(certDir, "server.key")

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create pipeline registry with a simple passthrough pipeline
	policyStore := storage.NewMemoryPolicyStore()
	engineFactory := pipelinepkg.NewEngineFactory(policyStore, logger)
	registry := pipelinepkg.NewPipelineRegistry(engineFactory)

	// Add a simple pipeline
	pipeline := domain.Pipeline{
		ID:       "test-tls-pipeline",
		Version:  1,
		AgentID:  "*",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "allow",
				Type: "terminal.allow",
			},
		},
	}

	ctx := context.Background()
	if err := registry.UpdatePipelines(ctx, []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("Failed to update pipelines: %v", err)
	}

	// Create DAG handler
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
		Logger:   logger,
	})

	// Create TLS configuration
	tlsConfig := &config.TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		MinVersion: "1.2",
	}

	// Create TLS server
	tlsServer, err := NewTLSServer(tlsConfig, dagHandler, logger)
	if err != nil {
		t.Fatalf("Failed to create TLS server: %v", err)
	}

	// Start TLS server on a random port
	addresses := []string{"127.0.0.1:0"}
	if err := tlsServer.Start(ctx, addresses); err != nil {
		t.Fatalf("Failed to start TLS server: %v", err)
	}

	// Get the actual listening address
	if len(tlsServer.listeners) == 0 {
		t.Fatal("No listeners created")
	}
	serverAddr := tlsServer.listeners[0].Addr().String()
	t.Logf("TLS server listening on %s", serverAddr)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Create HTTPS client that accepts self-signed certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	// Test HTTPS request
	resp, err := client.Get(fmt.Sprintf("https://%s/test", serverAddr))
	if err != nil {
		t.Fatalf("Failed to make HTTPS request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	t.Logf("Response status: %d", resp.StatusCode)
	t.Logf("Response body: %s", string(body))

	// Verify we got a successful response (terminal.allow should return 200)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check TLS metrics
	metrics := tlsServer.GetTLSMetrics()
	if metrics.ConnectionsTotal == 0 {
		t.Error("Expected at least one connection in metrics")
	}

	t.Logf("TLS Metrics: Total=%d, Active=%d, Errors=%d",
		metrics.ConnectionsTotal, metrics.ConnectionsActive, metrics.HandshakeErrors)

	// Shutdown server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tlsServer.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Failed to shutdown TLS server: %v", err)
	}
}

func TestTLSServerWithClientAuth(t *testing.T) {
	// Skip if we can't create test certificates
	certDir := t.TempDir()
	serverCertFile := filepath.Join(certDir, "server.crt")
	serverKeyFile := filepath.Join(certDir, "server.key")
	clientCertFile := filepath.Join(certDir, "client.crt")
	clientKeyFile := filepath.Join(certDir, "client.key")
	caFile := filepath.Join(certDir, "ca.crt")

	// Generate test certificates with CA
	if err := GenerateTestCertificates(certDir); err != nil {
		t.Skipf("Cannot generate test certificates with CA: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create pipeline registry
	policyStore := storage.NewMemoryPolicyStore()
	engineFactory := pipelinepkg.NewEngineFactory(policyStore, logger)
	registry := pipelinepkg.NewPipelineRegistry(engineFactory)

	// Add a simple pipeline
	pipeline := domain.Pipeline{
		ID:       "test-mtls-pipeline",
		Version:  1,
		AgentID:  "*",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "allow",
				Type: "terminal.allow",
			},
		},
	}

	ctx := context.Background()
	if err := registry.UpdatePipelines(ctx, []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("Failed to update pipelines: %v", err)
	}

	// Create DAG handler
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
		Logger:   logger,
	})

	// Create TLS configuration with client authentication
	tlsConfig := &config.TLSConfig{
		Enabled:    true,
		CertFile:   serverCertFile,
		KeyFile:    serverKeyFile,
		MinVersion: "1.2",
		ClientAuth: config.TLSClientAuthConfig{
			Required: true,
			CAFile:   caFile,
		},
	}

	// Create TLS server
	tlsServer, err := NewTLSServer(tlsConfig, dagHandler, logger)
	if err != nil {
		t.Fatalf("Failed to create TLS server: %v", err)
	}

	// Start TLS server on a random port
	addresses := []string{"127.0.0.1:0"}
	if err := tlsServer.Start(ctx, addresses); err != nil {
		t.Fatalf("Failed to start TLS server: %v", err)
	}

	// Get the actual listening address
	if len(tlsServer.listeners) == 0 {
		t.Fatal("No listeners created")
	}
	serverAddr := tlsServer.listeners[0].Addr().String()
	t.Logf("mTLS server listening on %s", serverAddr)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}

	// Create HTTPS client with client certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{clientCert},
			},
		},
		Timeout: 5 * time.Second,
	}

	// Test HTTPS request with client certificate
	resp, err := client.Get(fmt.Sprintf("https://%s/test", serverAddr))
	if err != nil {
		t.Fatalf("Failed to make mTLS request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	t.Logf("mTLS Response status: %d", resp.StatusCode)
	t.Logf("mTLS Response body: %s", string(body))

	// Verify we got a successful response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check TLS metrics
	metrics := tlsServer.GetTLSMetrics()
	if metrics.ConnectionsTotal == 0 {
		t.Error("Expected at least one connection in metrics")
	}

	// Shutdown server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tlsServer.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Failed to shutdown TLS server: %v", err)
	}
}
