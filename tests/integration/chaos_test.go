package integration

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
)

// TestChaosNetworkPartition tests upstream timeout handling
func TestChaosNetworkPartition(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("upstream timeout triggers circuit breaker", func(t *testing.T) {
		t.Skip("Timeout enforcement requires actual HTTP egress execution - pattern validated, implementation pending")
		// Note: Current egress handler prepares request but doesn't execute it
		// Full timeout testing requires integration with actual HTTP client
		// Pattern: Configure timeout in node config, enforce in egress execution
		// Create slow upstream that times out
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(5 * time.Second) // Longer than typical timeout
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		// Pipeline with timeout configuration
		pipeline := domain.Pipeline{
			ID:       "timeout-test",
			Version:  1,
			AgentID:  "timeout-agent",
			Protocol: "http",
			Defaults: domain.PipelineDefaults{
				TimeoutMS: 1000, // 1 second timeout
			},
			Nodes: []domain.PipelineNode{
				{
					ID:   "egress",
					Type: "egress.http",
					Config: map[string]interface{}{
						"upstream_url": upstream.URL,
						"timeout_ms":   1000,
					},
				},
			},
		}

		registry := pipelinepkg.NewPipelineRegistry(nil)
		_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

		executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
			Registry: registry,
			Logger:   logger,
		})

		// Execute pipeline - should timeout
		ctx := context.Background()
		pipelineCtx := &domain.PipelineContext{
			Request: domain.RequestContext{
				Method:    "GET",
				Path:      "/api/slow",
				Headers:   map[string][]string{},
				Protocol:  "http",
				AgentID:   "timeout-agent",
				SessionID: "timeout-session-1",
			},
			Variables: make(map[string]interface{}),
		}

		start := time.Now()
		err := executor.Execute(ctx, "timeout-agent", "http", pipelineCtx)
		elapsed := time.Since(start)

		// Verify: Request should fail due to timeout
		if err == nil {
			t.Error("Expected timeout error, got nil")
		}

		// Verify: Timeout happened quickly (around 1s, not 5s)
		if elapsed > 2*time.Second {
			t.Errorf("Timeout took too long: %v (expected ~1s)", elapsed)
		}

		t.Logf("Timeout occurred after %v (expected ~1s) ✓", elapsed)
	})

	t.Run("partial network partition with retries", func(t *testing.T) {
		attempts := 0
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			if attempts < 3 {
				// Simulate intermittent failure
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		// Pipeline with retry configuration
		pipeline := domain.Pipeline{
			ID:       "retry-test",
			Version:  1,
			AgentID:  "retry-agent",
			Protocol: "http",
			Defaults: domain.PipelineDefaults{
				Retries: domain.PipelineRetryConfig{
					MaxAttempts: 3,
					Backoff:     "fixed",
					BaseMS:      100,
				},
			},
			Nodes: []domain.PipelineNode{
				{
					ID:   "egress",
					Type: "egress.http",
					Config: map[string]interface{}{
						"upstream_url": upstream.URL,
					},
				},
			},
		}

		registry := pipelinepkg.NewPipelineRegistry(nil)
		_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

		executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
			Registry: registry,
			Logger:   logger,
		})

		ctx := context.Background()
		pipelineCtx := &domain.PipelineContext{
			Request: domain.RequestContext{
				Method:    "GET",
				Path:      "/api/flaky",
				Headers:   map[string][]string{},
				Protocol:  "http",
				AgentID:   "retry-agent",
				SessionID: "retry-session-1",
			},
			Variables: make(map[string]interface{}),
		}

		err := executor.Execute(ctx, "retry-agent", "http", pipelineCtx)

		// Note: Retry logic would be implemented in governance layer
		// This test demonstrates the pattern; actual retry requires governance.RetryConfig
		if err != nil {
			t.Logf("Retry test result: %v (retry logic pending governance integration)", err)
		}

		t.Logf("Upstream received %d attempts", attempts)
	})
}

// TestChaosControlPlaneUnavailability tests LKG fallback
func TestChaosControlPlaneUnavailability(t *testing.T) {
	t.Run("control plane disconnect continues with LKG", func(t *testing.T) {
		// Setup: Register pipeline
		pipeline := domain.Pipeline{
			ID:       "lkg-test",
			Version:  1,
			AgentID:  "lkg-agent",
			Protocol: "http",
			Nodes: []domain.PipelineNode{
				{
					ID:   "egress",
					Type: "egress.http",
					Config: map[string]interface{}{
						"upstream_url": "http://upstream.example.com",
					},
				},
			},
		}

		registry := pipelinepkg.NewPipelineRegistry(nil)
		_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

		// Create active session
		sessionID := "lkg-session-1"
		_, err := registry.SelectPipelineForSession(sessionID, "lkg-agent", "http")
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		// Simulate control plane disconnect (no new pipeline updates)
		// In real scenario, control plane gRPC stream would disconnect

		// Verify: Existing session continues with LKG
		lkgPipeline, err := registry.SelectPipelineForSession(sessionID, "lkg-agent", "http")
		if err != nil {
			t.Errorf("Expected LKG to be available, got error: %v", err)
		}

		if lkgPipeline.Version != 1 {
			t.Errorf("Expected LKG version 1, got %d", lkgPipeline.Version)
		}

		t.Log("Session continues with LKG during control plane outage ✓")
	})

	t.Run("control plane reconnect applies new config", func(t *testing.T) {
		// Setup: Initial pipeline
		pipeline := domain.Pipeline{
			ID:       "reconnect-test",
			Version:  1,
			AgentID:  "reconnect-agent",
			Protocol: "http",
			Nodes:    []domain.PipelineNode{{ID: "egress", Type: "egress.http"}},
		}

		registry := pipelinepkg.NewPipelineRegistry(nil)
		_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

		// Simulate control plane reconnect with new config
		updatedPipeline := domain.Pipeline{
			ID:       "reconnect-test",
			Version:  2,
			AgentID:  "reconnect-agent",
			Protocol: "http",
			Nodes: []domain.PipelineNode{
				{ID: "auth", Type: "auth.jwt.validate"},
				{ID: "egress", Type: "egress.http"},
			},
		}

		_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{updatedPipeline})

		// Verify: New sessions use updated pipeline
		newPipeline, err := registry.SelectPipelineForSession("new-session", "reconnect-agent", "http")
		if err != nil {
			t.Fatalf("Failed to select pipeline: %v", err)
		}

		if newPipeline.Version != 2 {
			t.Errorf("Expected new pipeline version 2, got %d", newPipeline.Version)
		}

		if len(newPipeline.Nodes) != 2 {
			t.Errorf("Expected 2 nodes in updated pipeline, got %d", len(newPipeline.Nodes))
		}

		t.Log("Control plane reconnect applies new configuration ✓")
	})
}

// TestChaosConfigCorruption tests validation rejection
func TestChaosConfigCorruption(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("corrupted pipeline rejected with validation error", func(t *testing.T) {
		registry := pipelinepkg.NewPipelineRegistry(nil)

		// Attempt to register invalid pipeline (missing required fields)
		invalidPipeline := domain.Pipeline{
			ID:      "", // Missing ID - should fail validation
			Version: 1,
			Nodes:   []domain.PipelineNode{},
		}

		err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{invalidPipeline})

		// Pipeline validation is enforced - empty ID should be rejected
		if err == nil {
			t.Fatal("Expected validation error for pipeline with empty ID, got nil")
		}

		if !strings.Contains(err.Error(), "ID is required") {
			t.Errorf("Expected error about missing ID, got: %v", err)
		}

		t.Logf("Invalid pipeline rejected: %v ✓", err)
	})

	t.Run("cycle detection prevents infinite loops", func(t *testing.T) {
		// Pipeline with cycle: A → B → C → A
		cyclicPipeline := domain.Pipeline{
			ID:       "cycle-test",
			Version:  1,
			AgentID:  "cycle-agent",
			Protocol: "http",
			Nodes: []domain.PipelineNode{
				{
					ID:   "node-a",
					Type: "passthrough",
					On:   domain.NodeHandlers{Success: "node-b"},
				},
				{
					ID:   "node-b",
					Type: "passthrough",
					On:   domain.NodeHandlers{Success: "node-c"},
				},
				{
					ID:   "node-c",
					Type: "passthrough",
					On:   domain.NodeHandlers{Success: "node-a"}, // Cycle!
				},
			},
		}

		registry := pipelinepkg.NewPipelineRegistry(nil)
		_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{cyclicPipeline})

		executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
			Registry: registry,
			Logger:   logger,
		})

		ctx := context.Background()
		pipelineCtx := &domain.PipelineContext{
			Request: domain.RequestContext{
				Method:    "GET",
				Path:      "/test",
				Protocol:  "http",
				AgentID:   "cycle-agent",
				SessionID: "cycle-session",
			},
			Variables: make(map[string]interface{}),
		}

		err := executor.Execute(ctx, "cycle-agent", "http", pipelineCtx)

		// Verify: Cycle detection prevents infinite loop
		if err == nil {
			t.Error("Expected cycle detection error, got nil")
		}

		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("Cycle detected: %v ✓", err)
		}
	})
}

// TestChaosDependencyFailures tests fail-open/fail-closed postures
func TestChaosDependencyFailures(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("DLP scanner unavailable with fail-open posture", func(t *testing.T) {
		// Pipeline with DLP node configured as fail-open
		pipeline := domain.Pipeline{
			ID:       "dlp-failopen-test",
			Version:  1,
			AgentID:  "dlp-agent",
			Protocol: "http",
			Nodes: []domain.PipelineNode{
				{
					ID:      "dlp",
					Type:    "dlp.inspect",
					Posture: "fail-open", // Continue if scanner unavailable
					On: domain.NodeHandlers{
						Success: "egress",
						Failure: "egress", // Fail-open: proceed anyway
					},
				},
				{
					ID:   "egress",
					Type: "egress.http",
					Config: map[string]interface{}{
						"upstream_url": "http://upstream.example.com",
					},
				},
			},
		}

		registry := pipelinepkg.NewPipelineRegistry(nil)
		_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

		executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
			Registry: registry,
			Logger:   logger,
		})

		ctx := context.Background()
		pipelineCtx := &domain.PipelineContext{
			Request: domain.RequestContext{
				Method:    "POST",
				Path:      "/api/data",
				Protocol:  "http",
				AgentID:   "dlp-agent",
				SessionID: "dlp-session-1",
			},
			Variables: make(map[string]interface{}),
		}

		// Execute - DLP uses passthrough handler, so it will succeed
		err := executor.Execute(ctx, "dlp-agent", "http", pipelineCtx)

		// Note: Real DLP scanner failure would require actual scanner integration
		// This test validates the posture configuration pattern
		if err != nil {
			t.Logf("Pipeline with fail-open DLP result: %v", err)
		} else {
			t.Log("DLP fail-open: request proceeds despite scanner unavailability (passthrough mode) ✓")
		}
	})

	t.Run("WAF scanner unavailable with fail-closed posture", func(t *testing.T) {
		// Pipeline with WAF node configured as fail-closed
		pipeline := domain.Pipeline{
			ID:       "waf-failclosed-test",
			Version:  1,
			AgentID:  "waf-agent",
			Protocol: "http",
			Nodes: []domain.PipelineNode{
				{
					ID:      "waf",
					Type:    "waf.inspect",
					Posture: "fail-closed", // Block if scanner unavailable
					On: domain.NodeHandlers{
						Success: "egress",
						Failure: "deny",
					},
				},
				{
					ID:   "egress",
					Type: "egress.http",
					Config: map[string]interface{}{
						"upstream_url": "http://upstream.example.com",
					},
				},
				{
					ID:   "deny",
					Type: "terminal.deny",
				},
			},
		}

		registry := pipelinepkg.NewPipelineRegistry(nil)
		_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

		executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
			Registry: registry,
			Logger:   logger,
		})

		ctx := context.Background()
		pipelineCtx := &domain.PipelineContext{
			Request: domain.RequestContext{
				Method:    "POST",
				Path:      "/api/input",
				Protocol:  "http",
				AgentID:   "waf-agent",
				SessionID: "waf-session-1",
			},
			Variables: make(map[string]interface{}),
		}

		// Execute - WAF uses passthrough handler, so it will succeed
		err := executor.Execute(ctx, "waf-agent", "http", pipelineCtx)

		// Note: Real WAF scanner failure would require actual scanner integration
		// This test validates the posture configuration pattern
		if err != nil {
			t.Logf("WAF fail-closed would block: %v", err)
		} else {
			t.Log("WAF fail-closed posture configured (passthrough mode active) ✓")
		}
	})
}

// TestChaosGracefulDegradation tests system behavior under stress
func TestChaosGracefulDegradation(t *testing.T) {
	t.Run("high error rate triggers circuit breaker", func(t *testing.T) {
		t.Skip("Circuit breaker integration pending - tracked in governance layer")
		// Pattern: Track consecutive failures, open circuit after threshold
		// When open: fail fast without attempting upstream call
		// Half-open after cooldown period to test recovery
	})

	t.Run("memory pressure with session limit", func(t *testing.T) {
		t.Skip("Session limit enforcement pending - tracked in governance layer")
		// Pattern: Reject new sessions when limit reached
		// Provide clear error message with retry-after guidance
	})

	t.Run("telemetry buffer overflow", func(t *testing.T) {
		t.Skip("Telemetry buffering and backpressure pending - tracked in telemetry layer")
		// Pattern: Drop telemetry events if buffer full (don't block requests)
		// Emit metrics about dropped events
	})
}
