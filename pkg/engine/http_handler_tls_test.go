package engine

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
)

func TestDAGHandler_buildPipelineContext_WithTLS(t *testing.T) {
	// Create a DAG handler
	handler := &DAGHandler{
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	// Create a mock TLS context
	tlsCtx := &domain.TLSContext{
		Version:           "1.3",
		CipherSuite:       "TLS_AES_256_GCM_SHA384",
		ServerName:        "example.com",
		ClientAuth:        false,
		HandshakeDuration: 5 * time.Millisecond,
		PeerCertificates:  []string{"CN=Test Client"},
	}

	// Create a request with TLS context
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.Header.Set("X-Agent-ID", "test-agent")

	// Add TLS context to request context
	ctx := context.WithValue(req.Context(), "tls_context", tlsCtx)
	req = req.WithContext(ctx)

	// Build pipeline context
	pipelineCtx := handler.buildPipelineContext(req, "test-agent")

	// Verify TLS context is included in the pipeline context
	if pipelineCtx.Request.TLS == nil {
		t.Fatal("TLS context is nil in pipeline request")
	}

	// Verify TLS context values
	if pipelineCtx.Request.TLS.Version != tlsCtx.Version {
		t.Errorf("Expected TLS version %s, got %s", tlsCtx.Version, pipelineCtx.Request.TLS.Version)
	}
	if pipelineCtx.Request.TLS.CipherSuite != tlsCtx.CipherSuite {
		t.Errorf("Expected cipher suite %s, got %s", tlsCtx.CipherSuite, pipelineCtx.Request.TLS.CipherSuite)
	}
	if pipelineCtx.Request.TLS.ServerName != tlsCtx.ServerName {
		t.Errorf("Expected server name %s, got %s", tlsCtx.ServerName, pipelineCtx.Request.TLS.ServerName)
	}

	// Verify TLS variables are set
	expectedVars := []string{
		"tls.version",
		"tls.cipher_suite",
		"tls.server_name",
		"tls.client_auth",
		"tls.handshake_duration_ms",
		"tls.peer_certificates",
		"tls.peer_certificate_count",
	}

	for _, varName := range expectedVars {
		if _, exists := pipelineCtx.Variables[varName]; !exists {
			t.Errorf("Expected TLS variable %s not found", varName)
		}
	}

	// Verify specific variable values
	if version, ok := pipelineCtx.Variables["tls.version"].(string); !ok || version != tlsCtx.Version {
		t.Errorf("Expected tls.version = %s, got %v", tlsCtx.Version, pipelineCtx.Variables["tls.version"])
	}
	if clientAuth, ok := pipelineCtx.Variables["tls.client_auth"].(bool); !ok || clientAuth != tlsCtx.ClientAuth {
		t.Errorf("Expected tls.client_auth = %v, got %v", tlsCtx.ClientAuth, pipelineCtx.Variables["tls.client_auth"])
	}

	t.Log("TLS context successfully integrated into pipeline context")
}

func TestDAGHandler_buildPipelineContext_WithoutTLS(t *testing.T) {
	// Create a DAG handler
	handler := &DAGHandler{
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	// Create a request without TLS context (regular HTTP)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Agent-ID", "test-agent")

	// Build pipeline context
	pipelineCtx := handler.buildPipelineContext(req, "test-agent")

	// Verify TLS context is nil for HTTP requests
	if pipelineCtx.Request.TLS != nil {
		t.Error("TLS context should be nil for HTTP requests")
	}

	// Verify TLS variables are not set
	tlsVars := []string{
		"tls.version",
		"tls.cipher_suite",
		"tls.server_name",
		"tls.client_auth",
	}

	for _, varName := range tlsVars {
		if _, exists := pipelineCtx.Variables[varName]; exists {
			t.Errorf("TLS variable %s should not be set for HTTP requests", varName)
		}
	}

	t.Log("HTTP request correctly processed without TLS context")
}
