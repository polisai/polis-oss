package perf

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
)

// BenchmarkDAGExecutor_SimplePassthrough benchmarks a simple auth -> egress pipeline
func BenchmarkDAGExecutor_SimplePassthrough(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer upstream.Close()

	// Create a simple pipeline: auth -> egress
	pipeline := domain.Pipeline{
		ID:       "bench-pipeline",
		Version:  1,
		AgentID:  "bench-agent",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "auth",
				Type: "auth.passthrough", // Use passthrough for benchmark
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
			},
		},
	}

	// Create registry and executor
	registry := pipelinepkg.NewPipelineRegistry(nil)
	_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-ID", "bench-agent")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := context.Background()

		// Execute pipeline
		err := executor.Execute(ctx, "bench-agent", "http", &domain.PipelineContext{
			Request: domain.RequestContext{
				Method:    req.Method,
				Path:      req.URL.Path,
				Headers:   req.Header,
				Protocol:  "http",
				AgentID:   "bench-agent",
				SessionID: "bench-session",
			},
			Variables: make(map[string]interface{}),
		})

		if err != nil {
			b.Fatalf("Pipeline execution failed: %v", err)
		}
	}
}

// BenchmarkDAGExecutor_WithPolicy benchmarks auth -> policy -> egress pipeline
func BenchmarkDAGExecutor_WithPolicy(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer upstream.Close()

	// Create pipeline with policy: auth -> policy -> egress
	pipeline := domain.Pipeline{
		ID:       "bench-pipeline-policy",
		Version:  1,
		AgentID:  "bench-agent-policy",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "auth",
				Type: "auth.passthrough",
				On: domain.NodeHandlers{
					Success: "policy",
				},
			},
			{
				ID:   "policy",
				Type: "policy.passthrough", // Use passthrough for benchmark
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
			},
		},
	}

	// Create registry and executor
	registry := pipelinepkg.NewPipelineRegistry(nil)
	_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Agent-ID", "bench-agent-policy")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := context.Background()

		// Execute pipeline
		err := executor.Execute(ctx, "bench-agent-policy", "http", &domain.PipelineContext{
			Request: domain.RequestContext{
				Method:    req.Method,
				Path:      req.URL.Path,
				Headers:   req.Header,
				Protocol:  "http",
				AgentID:   "bench-agent-policy",
				SessionID: "bench-session-policy",
			},
			Variables: make(map[string]interface{}),
		})

		if err != nil {
			b.Fatalf("Pipeline execution failed: %v", err)
		}
	}
}

// BenchmarkDAGExecutor_PipelineSelection benchmarks pipeline selection overhead
func BenchmarkDAGExecutor_PipelineSelection(b *testing.B) {
	// Create multiple pipelines
	pipelines := make([]domain.Pipeline, 0, 100)
	for i := 0; i < 100; i++ {
		agentID := "bench-agent-" + strconv.Itoa(i)
		pipelines = append(pipelines, domain.Pipeline{
			ID:       "bench-pipeline-" + agentID,
			Version:  1,
			AgentID:  agentID,
			Protocol: "http",
			Nodes: []domain.PipelineNode{
				{
					ID:   "auth",
					Type: "auth.passthrough",
				},
			},
		})
	}

	// Create registry
	registry := pipelinepkg.NewPipelineRegistry(nil)
	_ = registry.UpdatePipelines(context.Background(), pipelines)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Select pipeline (middle of the list)
		_, err := registry.SelectPipeline("bench-agent-55", "http")
		if err != nil {
			b.Fatalf("Pipeline selection failed: %v", err)
		}
	}
}
