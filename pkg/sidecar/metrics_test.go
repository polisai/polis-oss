package sidecar

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestMetrics_RecordIntercept(t *testing.T) {
	m := NewSidecarMetrics()
	m.RecordIntercept(DecisionAllow)
	m.RecordIntercept(DecisionBlock)
	m.RecordIntercept(DecisionAllow)

	assert.Equal(t, 2, m.GetInterceptCount(DecisionAllow))
	assert.Equal(t, 1, m.GetInterceptCount(DecisionBlock))
}

// Property 10: Metrics Emission Consistency
func TestMetricsProperties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := NewSidecarMetrics()

		actions := rapid.SliceOf(rapid.SampledFrom([]PolicyDecision{DecisionAllow, DecisionBlock, DecisionRedact})).Draw(t, "actions")

		for _, a := range actions {
			m.RecordIntercept(a)
		}

		// Verify counts match
		expected := make(map[PolicyDecision]int)
		for _, a := range actions {
			expected[a]++
		}

		for k, v := range expected {
			if m.GetInterceptCount(k) != v {
				t.Fatalf("Count mismatch for %v: expected %d, got %d", k, v, m.GetInterceptCount(k))
			}
		}
	})
}

// Placeholder for Tracing test
func TestTracing_Propagation(t *testing.T) {
	// TODO: Implement real OpenTelemetry tests
	// For now just verify we can pass context
	ctx := context.Background()
	_ = ctx
}
