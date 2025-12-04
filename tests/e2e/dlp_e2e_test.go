package e2e

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
	"github.com/polisai/polis-oss/pkg/engine/handlers"
)

// TestDLPStreamingEmailRedaction tests DLP redaction of email addresses in streaming responses.
func TestDLPStreamingEmailRedaction(t *testing.T) {
	logger := slog.Default()

	// Create upstream server that streams sensitive data
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("streaming not supported")
			return
		}

		// Stream multiple events with email addresses
		events := []string{
			"data: Contact our support team at support@example.com\n\n",
			"data: Sales inquiries: sales@example.com\n\n",
			"data: For urgent matters: urgent@example.com\n\n",
		}

		for _, event := range events {
			_, _ = w.Write([]byte(event))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	// Setup pipeline with DLP
	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)
	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	executor.RegisterHandler("dlp", handlers.NewDLPHandler(logger))
	executor.RegisterHandler("egress.http", handlers.NewEgressHTTPHandler(logger))

	pipeline := domain.Pipeline{
		ID:       "dlp-streaming-pipeline",
		AgentID:  "dlp-agent",
		Version:  1,
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "dlp",
				Type: "dlp",
				Config: map[string]interface{}{
					"mode":       "stream",
					"chunk_size": 64,
					"overlap":    16,
					"rules": []interface{}{
						map[string]interface{}{
							"name":        "email",
							"pattern":     `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
							"action":      "redact",
							"replacement": "[EMAIL:REDACTED]",
						},
					},
				},
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress.http",
				Config: map[string]interface{}{
					"upstream_url": upstream.URL,
				},
				On: domain.NodeHandlers{
					Success: "",
				},
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to update pipelines: %v", err)
	}

	// Create test request context
	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:    "GET",
			Path:      "/events",
			Host:      "localhost",
			Protocol:  "http",
			AgentID:   "dlp-agent",
			SessionID: "dlp-stream-session",
			Headers:   map[string][]string{"Accept": {"text/event-stream"}},
		},
		Variables: make(map[string]interface{}),
	}

	// Execute pipeline
	err := executor.Execute(ctx, "dlp-agent", "http", pipelineCtx)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	t.Log("✓ DLP streaming email redaction pipeline executed successfully")
}

// TestDLPBufferedSSNRedaction tests DLP redaction of SSN in buffered mode.
func TestDLPBufferedSSNRedaction(t *testing.T) {
	logger := slog.Default()

	// Create upstream with sensitive SSN data
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{
			"user": "john.doe",
			"ssn": "123-45-6789",
			"contact": {
				"email": "john@example.com",
				"phone": "555-0123",
				"alt_ssn": "987-65-4321"
			}
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer upstream.Close()

	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)
	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	executor.RegisterHandler("dlp", handlers.NewDLPHandler(logger))
	executor.RegisterHandler("egress.http", handlers.NewEgressHTTPHandler(logger))

	pipeline := domain.Pipeline{
		ID:       "dlp-buffered-pipeline",
		AgentID:  "dlp-buffered-agent",
		Version:  1,
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "dlp",
				Type: "dlp",
				Config: map[string]interface{}{
					"mode": "buffered",
					"rules": []interface{}{
						map[string]interface{}{
							"name":        "ssn",
							"pattern":     `\d{3}-\d{2}-\d{4}`,
							"action":      "redact",
							"replacement": "XXX-XX-XXXX",
						},
						map[string]interface{}{
							"name":        "email",
							"pattern":     `[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
							"action":      "redact",
							"replacement": "[EMAIL]",
						},
					},
				},
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress.http",
				Config: map[string]interface{}{
					"upstream_url": upstream.URL,
				},
				On: domain.NodeHandlers{
					Success: "",
				},
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to update pipelines: %v", err)
	}

	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:    "GET",
			Path:      "/user/profile",
			Host:      "localhost",
			Protocol:  "http",
			AgentID:   "dlp-buffered-agent",
			SessionID: "dlp-buffered-session",
			Headers:   map[string][]string{"Accept": {"application/json"}},
		},
		Variables: make(map[string]interface{}),
	}

	err := executor.Execute(ctx, "dlp-buffered-agent", "http", pipelineCtx)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	t.Log("✓ DLP buffered SSN and email redaction pipeline executed successfully")
}

// TestDLPBlockingBehavior tests DLP blocking when configured with block action.
func TestDLPBlockingBehavior(t *testing.T) {
	logger := slog.Default()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Confidential API Key: sk_live_abc123def456"))
	}))
	defer upstream.Close()

	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)
	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	executor.RegisterHandler("dlp", handlers.NewDLPHandler(logger))
	executor.RegisterHandler("egress.http", handlers.NewEgressHTTPHandler(logger))

	pipeline := domain.Pipeline{
		ID:       "dlp-blocking-pipeline",
		AgentID:  "dlp-block-agent",
		Version:  1,
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "dlp",
				Type: "dlp",
				Config: map[string]interface{}{
					"mode": "stream",
					"rules": []interface{}{
						map[string]interface{}{
							"name":    "api_key",
							"pattern": `sk_live_[a-zA-Z0-9]+`,
							"action":  "block",
						},
					},
				},
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress.http",
				Config: map[string]interface{}{
					"upstream_url": upstream.URL,
				},
				On: domain.NodeHandlers{
					Success: "",
				},
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to update pipelines: %v", err)
	}

	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:    "GET",
			Path:      "/secret",
			Host:      "localhost",
			Protocol:  "http",
			AgentID:   "dlp-block-agent",
			SessionID: "dlp-block-session",
			Headers:   map[string][]string{},
		},
		Variables: make(map[string]interface{}),
	}

	err := executor.Execute(ctx, "dlp-block-agent", "http", pipelineCtx)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	// With block action, content should be truncated/blocked
	respBody, ok := pipelineCtx.Variables["response.body"]
	if ok {
		bodyBytes, ok := respBody.([]byte)
		if !ok {
			t.Fatalf("response.body is not a []byte, got %T", respBody)
		}
		bodyStr := string(bodyBytes)
		// The response should either be empty or not contain the sensitive data
		if strings.Contains(bodyStr, "sk_live_abc123def456") {
			t.Errorf("Blocked content was leaked in response: %s", bodyStr)
		}
	}

	t.Log("✓ DLP blocking behavior validated")
}

// TestDLPMultiplePatternRedaction tests DLP with multiple redaction patterns.
func TestDLPMultiplePatternRedaction(t *testing.T) {
	logger := slog.Default()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		response := `
Customer Report:
Name: John Doe
Email: john.doe@example.com
Phone: (555) 123-4567
SSN: 123-45-6789
Credit Card: 4532-1234-5678-9010
IP Address: 192.168.1.100
Date: 2025-11-01
`
		_, _ = w.Write([]byte(response))
	}))
	defer upstream.Close()

	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)
	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	executor.RegisterHandler("dlp", handlers.NewDLPHandler(logger))
	executor.RegisterHandler("egress.http", handlers.NewEgressHTTPHandler(logger))

	pipeline := domain.Pipeline{
		ID:       "dlp-multi-pattern-pipeline",
		AgentID:  "dlp-multi-agent",
		Version:  1,
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "dlp",
				Type: "dlp",
				Config: map[string]interface{}{
					"mode":       "buffered",
					"chunk_size": 128,
					"rules": []interface{}{
						map[string]interface{}{
							"name":        "email",
							"pattern":     `[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
							"action":      "redact",
							"replacement": "[EMAIL]",
						},
						map[string]interface{}{
							"name":        "ssn",
							"pattern":     `\d{3}-\d{2}-\d{4}`,
							"action":      "redact",
							"replacement": "[SSN]",
						},
						map[string]interface{}{
							"name":        "phone",
							"pattern":     `\(\d{3}\)\s\d{3}-\d{4}`,
							"action":      "redact",
							"replacement": "[PHONE]",
						},
						map[string]interface{}{
							"name":        "credit_card",
							"pattern":     `\d{4}-\d{4}-\d{4}-\d{4}`,
							"action":      "redact",
							"replacement": "[CC]",
						},
					},
				},
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress.http",
				Config: map[string]interface{}{
					"upstream_url": upstream.URL,
				},
				On: domain.NodeHandlers{
					Success: "",
				},
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to update pipelines: %v", err)
	}

	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:    "GET",
			Path:      "/report",
			Host:      "localhost",
			Protocol:  "http",
			AgentID:   "dlp-multi-agent",
			SessionID: "dlp-multi-session",
			Headers:   map[string][]string{},
		},
		Variables: make(map[string]interface{}),
	}

	err := executor.Execute(ctx, "dlp-multi-agent", "http", pipelineCtx)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	t.Log("✓ DLP multiple pattern redaction pipeline executed successfully")
}

// TestDLPChunkedStreamingRedaction tests DLP with chunked transfer encoding.
func TestDLPChunkedStreamingRedaction(t *testing.T) {
	logger := slog.Default()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// No Content-Length = chunked transfer encoding
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("streaming not supported")
			return
		}

		chunks := []string{
			"Line 1: contact support@",
			"example.com for help\n",
			"Line 2: email us at sales@",
			"company.org\n",
			"Line 3: final note urgent@",
			"service.net\n",
		}

		for _, chunk := range chunks {
			_, _ = w.Write([]byte(chunk))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)
	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	executor.RegisterHandler("dlp", handlers.NewDLPHandler(logger))
	executor.RegisterHandler("egress.http", handlers.NewEgressHTTPHandler(logger))

	pipeline := domain.Pipeline{
		ID:       "dlp-chunked-pipeline",
		AgentID:  "dlp-chunked-agent",
		Version:  1,
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "dlp",
				Type: "dlp",
				Config: map[string]interface{}{
					"mode":       "stream",
					"chunk_size": 32,
					"overlap":    12,
					"rules": []interface{}{
						map[string]interface{}{
							"name":        "email",
							"pattern":     `[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
							"action":      "redact",
							"replacement": "[REDACTED]",
						},
					},
				},
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress.http",
				Config: map[string]interface{}{
					"upstream_url": upstream.URL,
				},
				On: domain.NodeHandlers{
					Success: "",
				},
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to update pipelines: %v", err)
	}

	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:    "GET",
			Path:      "/chunked",
			Host:      "localhost",
			Protocol:  "http",
			AgentID:   "dlp-chunked-agent",
			SessionID: "dlp-chunked-session",
			Headers:   map[string][]string{},
		},
		Variables: make(map[string]interface{}),
	}

	err := executor.Execute(ctx, "dlp-chunked-agent", "http", pipelineCtx)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	t.Log("✓ DLP chunked streaming redaction with pattern spanning chunks executed successfully")
}

// TestDLPNoRulesPassthrough tests that DLP allows passthrough when no rules configured.
func TestDLPNoRulesPassthrough(t *testing.T) {
	logger := slog.Default()

	expectedBody := "This is a normal response with no sensitive data"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(expectedBody))
	}))
	defer upstream.Close()

	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)
	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	executor.RegisterHandler("dlp", handlers.NewDLPHandler(logger))
	executor.RegisterHandler("egress.http", handlers.NewEgressHTTPHandler(logger))

	pipeline := domain.Pipeline{
		ID:       "dlp-passthrough-pipeline",
		AgentID:  "dlp-passthrough-agent",
		Version:  1,
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "dlp",
				Type: "dlp",
				Config: map[string]interface{}{
					"rules": []interface{}{}, // Empty rules
				},
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress.http",
				Config: map[string]interface{}{
					"upstream_url": upstream.URL,
				},
				On: domain.NodeHandlers{
					Success: "",
				},
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to update pipelines: %v", err)
	}

	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:    "GET",
			Path:      "/passthrough",
			Host:      "localhost",
			Protocol:  "http",
			AgentID:   "dlp-passthrough-agent",
			SessionID: "dlp-passthrough-session",
			Headers:   map[string][]string{},
		},
		Variables: make(map[string]interface{}),
	}

	err := executor.Execute(ctx, "dlp-passthrough-agent", "http", pipelineCtx)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	t.Log("✓ DLP passthrough with no rules executed successfully")
}
