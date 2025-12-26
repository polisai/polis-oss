package sidecar

import (
	"sync"
)

// SidecarMetrics holds the unified metrics collectors
type SidecarMetrics struct {
	// Simulating Prometheus metrics with counters for now
	// In real impl these would be prometheus.Counter/Histogram
	mu sync.RWMutex

	interceptRequests map[string]int // action -> count
	toolExecutions    map[string]int // tool -> count
}

func NewSidecarMetrics() *SidecarMetrics {
	return &SidecarMetrics{
		interceptRequests: make(map[string]int),
		toolExecutions:    make(map[string]int),
	}
}

func (m *SidecarMetrics) RecordIntercept(action PolicyDecision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interceptRequests[string(action)]++
}

func (m *SidecarMetrics) RecordToolExecution(toolName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.toolExecutions[toolName]++
}

// Helpers for testing
func (m *SidecarMetrics) GetInterceptCount(action PolicyDecision) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.interceptRequests[string(action)]
}
