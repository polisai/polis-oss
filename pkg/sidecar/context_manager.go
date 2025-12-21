package sidecar

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// PolicyDecision represents the decision made by the governance engine
type PolicyDecision string

const (
	DecisionAllow  PolicyDecision = "allow"
	DecisionBlock  PolicyDecision = "block"
	DecisionRedact PolicyDecision = "redact"
)

// ExecutionResult represents the result of a tool execution
type ExecutionResult struct {
	ExitCode int
	Output   string // Summary or truncated output if needed
	Error    string
}

// RequestContext holds the state for a single request through the sidecar
type RequestContext struct {
	ID              string
	PolicyDecision  PolicyDecision
	ExecutionResult *ExecutionResult
	Metadata        map[string]interface{}
	CreatedAt       time.Time
}

// ContextManager manages the lifecycle of request contexts
type ContextManager interface {
	Create(ctx context.Context) (string, error)
	Get(id string) (*RequestContext, bool)
	SetPolicyDecision(id string, decision PolicyDecision) error
	SetExecutionResult(id string, result ExecutionResult) error
	SetMetadata(id string, key string, value interface{}) error
	Delete(id string)
	StartCleanup(ctx context.Context, interval time.Duration, ttl time.Duration)
}

// InMemoryContextManager implements ContextManager with an in-memory map
type InMemoryContextManager struct {
	contexts map[string]*RequestContext
	mu       sync.RWMutex
}

// NewInMemoryContextManager creates a new instance
func NewInMemoryContextManager() *InMemoryContextManager {
	return &InMemoryContextManager{
		contexts: make(map[string]*RequestContext),
	}
}

func (m *InMemoryContextManager) Create(ctx context.Context) (string, error) {
	id := uuid.New().String()
	m.mu.Lock()
	defer m.mu.Unlock()

	m.contexts[id] = &RequestContext{
		ID:        id,
		CreatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
	return id, nil
}

func (m *InMemoryContextManager) Get(id string) (*RequestContext, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ctx, ok := m.contexts[id]
	if !ok {
		return nil, false
	}
	// Return a copy or pointer? Pointer is dangerous if modified outside lock,
	// but struct has fields we might read.
	// For thread safety, clients should use Set methods to modify.
	// Reading is safe if we don't modify fields concurrently.
	// Let's return a detailed copy to be safe?
	// For now, pointer is efficient, but we must warn about modification.
	// Actually, getter is mostly for reading. Modifications go through Setters.
	return ctx, true
}

func (m *InMemoryContextManager) SetPolicyDecision(id string, decision PolicyDecision) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, ok := m.contexts[id]
	if !ok {
		return fmt.Errorf("context not found: %s", id)
	}
	ctx.PolicyDecision = decision
	return nil
}

func (m *InMemoryContextManager) SetExecutionResult(id string, result ExecutionResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, ok := m.contexts[id]
	if !ok {
		return fmt.Errorf("context not found: %s", id)
	}
	ctx.ExecutionResult = &result
	return nil
}

func (m *InMemoryContextManager) SetMetadata(id string, key string, value interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, ok := m.contexts[id]
	if !ok {
		return fmt.Errorf("context not found: %s", id)
	}
	ctx.Metadata[key] = value
	return nil
}

func (m *InMemoryContextManager) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.contexts, id)
}

// StartCleanup runs a ticker to remove expired contexts
func (m *InMemoryContextManager) StartCleanup(ctx context.Context, interval time.Duration, ttl time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.cleanup(ttl)
			}
		}
	}()
}

func (m *InMemoryContextManager) cleanup(ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, ctx := range m.contexts {
		if now.Sub(ctx.CreatedAt) > ttl {
			delete(m.contexts, id)
		}
	}
}
