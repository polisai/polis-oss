package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
)

// TestZeroDowntimeUpdate tests that pipeline updates preserve existing sessions
// while new sessions use updated pipelines (T014).
//
//nolint:gocyclo // Integration test with multiple comprehensive scenarios
func TestZeroDowntimeUpdate(t *testing.T) {
	t.Run("existing sessions continue with LKG pipeline", func(t *testing.T) {
		// Setup: Create registry and register initial pipeline
		registry := pipelinepkg.NewPipelineRegistry(nil)

		initialPipeline := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 1,
			Nodes: []domain.PipelineNode{
				{ID: "v1-auth", Type: "auth.jwt.validate"},
				{ID: "v1-egress", Type: "egress.http"},
			},
		}

		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{initialPipeline}); err != nil {
			t.Fatalf("failed to register initial pipeline: %v", err)
		}

		// Test: Create active session with initial pipeline
		session1ID := "session-001"
		pipeline1, err := registry.SelectPipelineForSession(session1ID, "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select pipeline for session1: %v", err)
		}

		if pipeline1.Version != 1 {
			t.Errorf("expected version 1 for initial session, got %d", pipeline1.Version)
		}

		// Test: Update to v2 pipeline (atomic swap)
		updatedPipeline := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 2,
			Nodes: []domain.PipelineNode{
				{ID: "v2-auth", Type: "auth.jwt.validate"},
				{ID: "v2-policy", Type: "policy.opa"},
				{ID: "v2-egress", Type: "egress.http"},
			},
		}

		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{updatedPipeline}); err != nil {
			t.Fatalf("failed to update pipeline: %v", err)
		}

		// Verify: Existing session still uses v1 pipeline (LKG)
		pipeline1After, err := registry.SelectPipelineForSession(session1ID, "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select pipeline for session1 after update: %v", err)
		}

		if pipeline1After.Version != 1 {
			t.Errorf("expected existing session to continue with version 1, got %d", pipeline1After.Version)
		}

		if len(pipeline1After.Nodes) != 2 {
			t.Errorf("expected existing session to have 2 nodes (v1), got %d", len(pipeline1After.Nodes))
		}

		// Verify: New session uses v2 pipeline
		session2ID := "session-002"
		pipeline2, err := registry.SelectPipelineForSession(session2ID, "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select pipeline for session2: %v", err)
		}

		if pipeline2.Version != 2 {
			t.Errorf("expected new session to use version 2, got %d", pipeline2.Version)
		}

		if len(pipeline2.Nodes) != 3 {
			t.Errorf("expected new session to have 3 nodes (v2), got %d", len(pipeline2.Nodes))
		}

		// Verify: Active session count reflects both sessions
		activeCount := registry.GetActiveSessionCount()
		if activeCount != 2 {
			t.Errorf("expected 2 active sessions, got %d", activeCount)
		}
	})

	t.Run("released sessions allow cleanup", func(t *testing.T) {
		registry := pipelinepkg.NewPipelineRegistry(nil)

		pipeline := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 1,
			Nodes: []domain.PipelineNode{
				{ID: "auth", Type: "auth.jwt.validate"},
			},
		}

		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
			t.Fatalf("failed to register pipeline: %v", err)
		}

		// Create session
		sessionID := "session-001"
		_, err := registry.SelectPipelineForSession(sessionID, "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select pipeline: %v", err)
		}

		// Verify session cached
		if registry.GetActiveSessionCount() != 1 {
			t.Error("expected 1 active session")
		}

		// Release session
		registry.ReleaseSession(sessionID)

		// Verify session released
		if registry.GetActiveSessionCount() != 0 {
			t.Error("expected 0 active sessions after release")
		}
	})

	t.Run("concurrent session creation during update", func(t *testing.T) {
		registry := pipelinepkg.NewPipelineRegistry(nil)

		v1Pipeline := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 1,
			Nodes: []domain.PipelineNode{
				{ID: "v1-node", Type: "egress.http"},
			},
		}

		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{v1Pipeline}); err != nil {
			t.Fatalf("failed to register v1 pipeline: %v", err)
		}

		// Test: Create multiple concurrent sessions
		const numSessions = 50
		var wg sync.WaitGroup
		sessionVersions := make([]int, numSessions)
		errors := make([]error, numSessions)

		for i := 0; i < numSessions; i++ {
			idx := i
			wg.Go(func() {
				sessionID := fmt.Sprintf("concurrent-session-%d", idx)
				pipeline, err := registry.SelectPipelineForSession(sessionID, "agent-alpha", "http")
				if err != nil {
					errors[idx] = err
					return
				}
				sessionVersions[idx] = pipeline.Version

				// Simulate some work
				time.Sleep(10 * time.Millisecond)
			})

			// Trigger update midway through
			if i == numSessions/2 {
				v2Pipeline := domain.Pipeline{
					ID:      "agent-alpha",
					AgentID: "agent-alpha",
					Version: 2,
					Nodes: []domain.PipelineNode{
						{ID: "v2-node", Type: "egress.http"},
					},
				}
				if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{v2Pipeline}); err != nil {
					t.Fatalf("failed to update pipeline: %v", err)
				}
			}
		}

		wg.Wait()

		// Verify: No errors
		for i, err := range errors {
			if err != nil {
				t.Errorf("session %d failed: %v", i, err)
			}
		}

		// Verify: All sessions got either v1 or v2 (no corrupted state)
		v1Count := 0
		v2Count := 0
		for i, version := range sessionVersions {
			switch version {
			case 1:
				v1Count++
			case 2:
				v2Count++
			default:
				t.Errorf("session %d got unexpected version %d", i, version)
			}
		}

		// In concurrent scenarios, it's possible all sessions get v2 if update happens quickly
		// The key validation is: no corrupted state - all should be valid versions (v1 or v2)
		if v1Count == 0 && v2Count == 0 {
			t.Error("no sessions were successfully created")
		}

		// At least one version should be present
		if v1Count+v2Count != numSessions {
			t.Errorf("expected %d total sessions, got %d", numSessions, v1Count+v2Count)
		}

		t.Logf("Concurrent session distribution: v1=%d, v2=%d (both versions present indicates race was captured)", v1Count, v2Count)
	})

	t.Run("multiple pipeline updates preserve session isolation", func(t *testing.T) {
		registry := pipelinepkg.NewPipelineRegistry(nil)

		// Register v1
		v1 := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 1,
			Nodes:   []domain.PipelineNode{{ID: "v1", Type: "egress.http"}},
		}
		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{v1}); err != nil {
			t.Fatalf("failed to register v1: %v", err)
		}

		// Create session 1 on v1
		session1, err := registry.SelectPipelineForSession("sess-1", "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select session 1: %v", err)
		}

		// Update to v2
		v2 := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 2,
			Nodes:   []domain.PipelineNode{{ID: "v2", Type: "egress.http"}},
		}
		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{v2}); err != nil {
			t.Fatalf("failed to register v2: %v", err)
		}

		// Create session 2 on v2
		session2, err := registry.SelectPipelineForSession("sess-2", "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select session 2: %v", err)
		}

		// Update to v3
		v3 := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 3,
			Nodes:   []domain.PipelineNode{{ID: "v3", Type: "egress.http"}},
		}
		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{v3}); err != nil {
			t.Fatalf("failed to register v3: %v", err)
		}

		// Create session 3 on v3
		session3, err := registry.SelectPipelineForSession("sess-3", "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select session 3: %v", err)
		}

		// Verify: Session 1 still on v1
		sess1Check, _ := registry.SelectPipelineForSession("sess-1", "agent-alpha", "http")
		if sess1Check.Version != session1.Version || sess1Check.Version != 1 {
			t.Errorf("session 1 should remain on v1, got v%d", sess1Check.Version)
		}

		// Verify: Session 2 still on v2
		sess2Check, _ := registry.SelectPipelineForSession("sess-2", "agent-alpha", "http")
		if sess2Check.Version != session2.Version || sess2Check.Version != 2 {
			t.Errorf("session 2 should remain on v2, got v%d", sess2Check.Version)
		}

		// Verify: Session 3 on v3
		if session3.Version != 3 {
			t.Errorf("session 3 should be on v3, got v%d", session3.Version)
		}

		// Verify: 3 active sessions
		if registry.GetActiveSessionCount() != 3 {
			t.Errorf("expected 3 active sessions, got %d", registry.GetActiveSessionCount())
		}
	})

	t.Run("session pipeline selection after release uses current", func(t *testing.T) {
		registry := pipelinepkg.NewPipelineRegistry(nil)

		v1 := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 1,
			Nodes:   []domain.PipelineNode{{ID: "v1", Type: "egress.http"}},
		}
		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{v1}); err != nil {
			t.Fatalf("failed to register v1: %v", err)
		}

		// Create and release session
		sessionID := "sess-reuse"
		pipe1, err := registry.SelectPipelineForSession(sessionID, "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select initial pipeline: %v", err)
		}
		if pipe1.Version != 1 {
			t.Error("expected v1 initially")
		}

		registry.ReleaseSession(sessionID)

		// Update to v2
		v2 := domain.Pipeline{
			ID:      "agent-alpha",
			AgentID: "agent-alpha",
			Version: 2,
			Nodes:   []domain.PipelineNode{{ID: "v2", Type: "egress.http"}},
		}
		if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{v2}); err != nil {
			t.Fatalf("failed to register v2: %v", err)
		}

		// Reuse same session ID
		pipe2, err := registry.SelectPipelineForSession(sessionID, "agent-alpha", "http")
		if err != nil {
			t.Fatalf("failed to select pipeline after release: %v", err)
		}

		// Should get current pipeline (v2), not cached LKG (v1)
		if pipe2.Version != 2 {
			t.Errorf("expected reused session ID to get v2, got v%d", pipe2.Version)
		}
	})
}
