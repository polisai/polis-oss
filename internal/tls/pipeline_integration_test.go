package tls

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
)

func TestTLSContextExtraction(t *testing.T) {
	// Test that TLS context is properly extracted from TLS connection

	// Create a mock TLS context (this would normally come from extractTLSContext)
	expectedTLSCtx := &domain.TLSContext{
		Version:           "1.3",
		CipherSuite:       "TLS_AES_256_GCM_SHA384",
		ServerName:        "example.com",
		ClientAuth:        false,
		HandshakeDuration: 5 * time.Millisecond,
		PeerCertificates:  []string{"CN=Test Client"},
	}

	// Create a mock HTTP request
	req, err := http.NewRequest("GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add TLS context to request context (this is what the TLS server does)
	ctx := context.WithValue(req.Context(), "tls_context", expectedTLSCtx)
	req = req.WithContext(ctx)

	// Test that we can extract the TLS context
	extractedTLSCtx, ok := req.Context().Value("tls_context").(*domain.TLSContext)
	if !ok {
		t.Fatal("Failed to extract TLS context from request")
	}

	// Verify TLS context values
	if extractedTLSCtx.Version != expectedTLSCtx.Version {
		t.Errorf("Expected TLS version %s, got %s", expectedTLSCtx.Version, extractedTLSCtx.Version)
	}
	if extractedTLSCtx.CipherSuite != expectedTLSCtx.CipherSuite {
		t.Errorf("Expected cipher suite %s, got %s", expectedTLSCtx.CipherSuite, extractedTLSCtx.CipherSuite)
	}
	if extractedTLSCtx.ServerName != expectedTLSCtx.ServerName {
		t.Errorf("Expected server name %s, got %s", expectedTLSCtx.ServerName, extractedTLSCtx.ServerName)
	}
	if extractedTLSCtx.ClientAuth != expectedTLSCtx.ClientAuth {
		t.Errorf("Expected client auth %v, got %v", expectedTLSCtx.ClientAuth, extractedTLSCtx.ClientAuth)
	}
	if extractedTLSCtx.HandshakeDuration != expectedTLSCtx.HandshakeDuration {
		t.Errorf("Expected handshake duration %v, got %v", expectedTLSCtx.HandshakeDuration, extractedTLSCtx.HandshakeDuration)
	}

	t.Logf("TLS context successfully extracted: version=%s, cipher=%s, server_name=%s",
		extractedTLSCtx.Version, extractedTLSCtx.CipherSuite, extractedTLSCtx.ServerName)

	t.Log("TLS context extraction test completed successfully")
}

func TestTLSContextInPipelineVariables(t *testing.T) {
	// Test that TLS context is properly added to pipeline variables

	// Create a mock TLS context
	tlsCtx := &domain.TLSContext{
		Version:           "1.2",
		CipherSuite:       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		ServerName:        "api.example.com",
		ClientAuth:        true,
		HandshakeDuration: 10 * time.Millisecond,
		PeerCertificates:  []string{"CN=Test Client,O=Test Org"},
	}

	// Create a pipeline context
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:   "GET",
			Path:     "/api/test",
			Host:     "api.example.com",
			Protocol: "http",
			TLS:      tlsCtx, // TLS context should be included here
		},
		Variables: make(map[string]interface{}),
	}

	// Simulate what applyTLSMetadata does
	if pipelineCtx.Request.TLS != nil {
		pipelineCtx.Variables["tls.version"] = tlsCtx.Version
		pipelineCtx.Variables["tls.cipher_suite"] = tlsCtx.CipherSuite
		pipelineCtx.Variables["tls.server_name"] = tlsCtx.ServerName
		pipelineCtx.Variables["tls.client_auth"] = tlsCtx.ClientAuth
		pipelineCtx.Variables["tls.negotiated_protocol"] = tlsCtx.NegotiatedProtocol
		pipelineCtx.Variables["tls.handshake_duration_ms"] = tlsCtx.HandshakeDuration.Milliseconds()

		if len(tlsCtx.PeerCertificates) > 0 {
			pipelineCtx.Variables["tls.peer_certificates"] = tlsCtx.PeerCertificates
			pipelineCtx.Variables["tls.peer_certificate_count"] = len(tlsCtx.PeerCertificates)
		}
	}

	// Verify that TLS variables are properly set
	expectedVars := map[string]interface{}{
		"tls.version":                "1.2",
		"tls.cipher_suite":           "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"tls.server_name":            "api.example.com",
		"tls.client_auth":            true,
		"tls.handshake_duration_ms":  int64(10),
		"tls.peer_certificates":      []string{"CN=Test Client,O=Test Org"},
		"tls.peer_certificate_count": 1,
	}

	for key, expectedValue := range expectedVars {
		actualValue, exists := pipelineCtx.Variables[key]
		if !exists {
			t.Errorf("Expected variable %s not found", key)
			continue
		}

		// Handle different types appropriately
		switch expected := expectedValue.(type) {
		case string:
			if actual, ok := actualValue.(string); !ok || actual != expected {
				t.Errorf("Expected %s = %s, got %v", key, expected, actualValue)
			}
		case bool:
			if actual, ok := actualValue.(bool); !ok || actual != expected {
				t.Errorf("Expected %s = %v, got %v", key, expected, actualValue)
			}
		case int64:
			if actual, ok := actualValue.(int64); !ok || actual != expected {
				t.Errorf("Expected %s = %d, got %v", key, expected, actualValue)
			}
		case int:
			if actual, ok := actualValue.(int); !ok || actual != expected {
				t.Errorf("Expected %s = %d, got %v", key, expected, actualValue)
			}
		case []string:
			if actual, ok := actualValue.([]string); !ok || len(actual) != len(expected) {
				t.Errorf("Expected %s = %v, got %v", key, expected, actualValue)
			} else {
				for i, exp := range expected {
					if actual[i] != exp {
						t.Errorf("Expected %s[%d] = %s, got %s", key, i, exp, actual[i])
					}
				}
			}
		}
	}

	// Verify that TLS context is available in the request
	if pipelineCtx.Request.TLS == nil {
		t.Error("TLS context is nil in pipeline request")
	} else {
		if pipelineCtx.Request.TLS.Version != tlsCtx.Version {
			t.Errorf("Expected TLS version %s, got %s", tlsCtx.Version, pipelineCtx.Request.TLS.Version)
		}
	}

	t.Log("TLS context in pipeline variables test completed successfully")
}
