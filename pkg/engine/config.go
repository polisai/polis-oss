package engine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/polisai/polis-oss/pkg/domain"
)

// PipelineRegistry - Per-Agent Pipeline Management
// ================================

// PipelineRegistry maintains the active set of pipelines and provides
// selection logic based on agent ID, goal ID, and protocol.
// Supports zero-downtime updates: existing sessions continue with last-known-good (LKG)
// pipelines while new sessions use the updated configuration.
//
//nolint:revive // Name PipelineRegistry is intentional for clarity
type PipelineRegistry struct {
	mu                sync.RWMutex
	pipelines         map[string]*domain.Pipeline // pipelineID → pipeline
	sessionPipelines  map[string]*domain.Pipeline // sessionID → pipeline (LKG for active sessions)
	currentGeneration int64                       // increments on each UpdatePipelines call
	engineFactory     *EngineFactory              // Factory for initializing engines
	logger            *slog.Logger
}

// NewPipelineRegistry creates a new pipeline registry.
func NewPipelineRegistry(factory *EngineFactory) *PipelineRegistry {
	return &PipelineRegistry{
		pipelines:        make(map[string]*domain.Pipeline),
		sessionPipelines: make(map[string]*domain.Pipeline),
		engineFactory:    factory,
		logger:           slog.Default(),
	}
}

// SelectPipeline returns the appropriate pipeline for the given agent and protocol.
// Selection precedence:
// 1. agentID:protocol (protocol-specific)
// 2. agentID (agent default)
// 3. * (wildcard fallback)
func (pr *PipelineRegistry) SelectPipeline(agentID, protocol string) (*domain.Pipeline, error) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	if agentID == "" {
		return nil, fmt.Errorf("agentID is required")
	}

	// Normalize protocol to lowercase
	protocol = strings.ToLower(protocol)

	// Try most specific to least specific
	lookupKeys := []string{
		fmt.Sprintf("%s:%s", agentID, protocol), // agent:protocol
		agentID,                                 // agent default
		"*",                                     // wildcard fallback (catch-all)
	}

	for _, key := range lookupKeys {
		if pipeline, ok := pr.pipelines[key]; ok {
			return pipeline, nil
		}
	}

	return nil, fmt.Errorf("no pipeline found for agent %q (protocol=%q)", agentID, protocol)
}

// SelectPipelineForSession returns the appropriate pipeline for a session.
// For existing sessions with a cached pipeline (LKG), returns that pipeline.
// For new sessions, selects the current pipeline and caches it for zero-downtime updates.
func (pr *PipelineRegistry) SelectPipelineForSession(sessionID, agentID, protocol string) (*domain.Pipeline, error) {
	pr.mu.RLock()
	// Check if this session already has an LKG pipeline
	if lkgPipeline, ok := pr.sessionPipelines[sessionID]; ok {
		pr.mu.RUnlock()
		pr.logger.Debug("using LKG pipeline for active session",
			slog.String("session_id", sessionID),
			slog.String("pipeline_id", lkgPipeline.ID))
		return lkgPipeline, nil
	}
	pr.mu.RUnlock()

	// New session - select current pipeline and cache it
	pipeline, err := pr.SelectPipeline(agentID, protocol)
	if err != nil {
		return nil, err
	}

	pr.mu.Lock()
	pr.sessionPipelines[sessionID] = pipeline
	pr.mu.Unlock()

	pr.logger.Debug("selected pipeline for new session",
		slog.String("session_id", sessionID),
		slog.String("pipeline_id", pipeline.ID),
		slog.String("agent_id", agentID))

	return pipeline, nil
}

// ReleaseSession removes the LKG pipeline cache for a completed session.
// Should be called when a session completes (stream ends, request finishes, etc.)
func (pr *PipelineRegistry) ReleaseSession(sessionID string) {
	pr.mu.Lock()
	delete(pr.sessionPipelines, sessionID)
	pr.mu.Unlock()

	pr.logger.Debug("released session pipeline",
		slog.String("session_id", sessionID))
}

// GetActiveSessionCount returns the number of sessions with cached LKG pipelines.
// Useful for monitoring zero-downtime transitions.
func (pr *PipelineRegistry) GetActiveSessionCount() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return len(pr.sessionPipelines)
}

// UpdatePipelines atomically updates the pipeline registry.
func (pr *PipelineRegistry) UpdatePipelines(ctx context.Context, pipelines []domain.Pipeline) (err error) {
	defer func() {
		if r := recover(); r != nil {
			_ = os.WriteFile("update_panic.log", []byte(fmt.Sprintf("panic: %v\nstack: %s", r, debug.Stack())), 0600)
			err = fmt.Errorf("panic in UpdatePipelines: %v", r)
		}
	}()

	if err := validatePipelines(pipelines); err != nil {
		_ = os.WriteFile("update_error.log", []byte(fmt.Sprintf("validation error: %v", err)), 0600)
		return fmt.Errorf("pipeline validation failed: %w", err)
	}

	var ids []string
	for _, p := range pipelines {
		ids = append(ids, p.ID)
	}
	_ = os.WriteFile("update_debug.log", []byte(fmt.Sprintf("received pipelines: %v", ids)), 0600)

	newRegistry := make(map[string]*domain.Pipeline)
	for i := range pipelines {
		p := &pipelines[i]

		// Initialize engines for this pipeline if factory is available
		if pr.engineFactory != nil {
			engineCtx, err := pr.engineFactory.InitializeEnginesForPipeline(ctx, p)
			if err != nil {
				pr.logger.Error("failed to initialize engines for pipeline",
					slog.String("pipeline_id", p.ID),
					slog.Any("error", err))
				_ = os.WriteFile("update_init_error.log", []byte(fmt.Sprintf("init error for %s: %v", p.ID, err)), 0600)
				return fmt.Errorf("failed to initialize engines for pipeline %s: %w", p.ID, err)
			}
			p.EngineContext = engineCtx
		}

		key := buildPipelineKey(p.AgentID, p.Protocol)
		if existing, ok := newRegistry[key]; ok {
			return fmt.Errorf("duplicate pipeline key %q (id1=%s, id2=%s)", key, existing.ID, p.ID)
		}
		newRegistry[key] = p
	}

	pr.mu.Lock()
	// Close engines from old pipelines
	for _, oldPipeline := range pr.pipelines {
		if oldPipeline.EngineContext != nil {
			_ = oldPipeline.EngineContext.Close()
		}
	}
	pr.pipelines = newRegistry
	pr.currentGeneration++
	generation := pr.currentGeneration
	activeSessionCount := len(pr.sessionPipelines)
	pr.mu.Unlock()

	pr.logger.Info("pipeline registry updated",
		slog.Int64("generation", generation),
		slog.Int("active_sessions", activeSessionCount),
		slog.Int("new_pipeline_count", len(newRegistry)))

	return nil
}

// ListPipelines returns a copy of all registered pipelines.
func (pr *PipelineRegistry) ListPipelines() []domain.Pipeline {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	result := make([]domain.Pipeline, 0, len(pr.pipelines))
	for _, p := range pr.pipelines {
		result = append(result, *p)
	}
	return result
}

// GetPipeline returns a specific pipeline by ID.
func (pr *PipelineRegistry) GetPipeline(pipelineID string) (*domain.Pipeline, bool) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	keys := make([]string, 0, len(pr.pipelines))
	for k := range pr.pipelines {
		keys = append(keys, k)
	}
	_ = os.WriteFile("get_pipeline_debug.log", []byte(fmt.Sprintf("looking for %s, have keys: %v", pipelineID, keys)), 0600)

	for _, p := range pr.pipelines {
		if p.ID == pipelineID {
			return p, true
		}
	}
	return nil, false
}

// buildPipelineKey constructs a lookup key from agent and protocol.
func buildPipelineKey(agentID, protocol string) string {
	protocol = strings.ToLower(protocol)
	if protocol != "" {
		return fmt.Sprintf("%s:%s", agentID, protocol)
	}
	return agentID
}

// validatePipelines performs basic validation on pipeline definitions.
func validatePipelines(pipelines []domain.Pipeline) error {
	seenIDs := make(map[string]bool)

	for i, p := range pipelines {
		if p.ID == "" {
			return fmt.Errorf("pipeline[%d]: ID is required", i)
		}
		if seenIDs[p.ID] {
			return fmt.Errorf("pipeline[%d]: duplicate ID %q", i, p.ID)
		}
		seenIDs[p.ID] = true

		if p.AgentID == "" {
			return fmt.Errorf("pipeline[%d] %q: AgentID is required", i, p.ID)
		}

		if len(p.Nodes) == 0 {
			return fmt.Errorf("pipeline[%d] %q: at least one node is required", i, p.ID)
		}

		// Validate node IDs are unique
		nodeIDs := make(map[string]bool)
		for j, node := range p.Nodes {
			if node.ID == "" {
				return fmt.Errorf("pipeline[%d] %q node[%d]: ID is required", i, p.ID, j)
			}
			if nodeIDs[node.ID] {
				return fmt.Errorf("pipeline[%d] %q: duplicate node ID %q", i, p.ID, node.ID)
			}
			nodeIDs[node.ID] = true
		}

		// Validate edges reference existing nodes
		for j, edge := range p.Edges {
			if !nodeIDs[edge.From] {
				return fmt.Errorf("pipeline[%d] %q edge[%d]: from node %q not found", i, p.ID, j, edge.From)
			}
			if !nodeIDs[edge.To] {
				return fmt.Errorf("pipeline[%d] %q edge[%d]: to node %q not found", i, p.ID, j, edge.To)
			}
		}

		// Validate handler references (basic check)
		for j, node := range p.Nodes {
			handlers := []string{
				node.On.Success, node.On.Failure, node.On.Timeout,
				node.On.RateLimited, node.On.CircuitOpen, node.On.Else,
			}
			for _, h := range handlers {
				if h != "" && !nodeIDs[h] {
					return fmt.Errorf("pipeline[%d] %q node[%d] %q: handler references unknown node %q", i, p.ID, j, node.ID, h)
				}
			}
		}
	}

	return nil
}
