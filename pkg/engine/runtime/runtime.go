// Package runtime defines the core contracts shared by pipeline executors and node
// handlers, keeping business logic decoupled from execution mechanics.
package runtime

import (
	"context"

	"github.com/polisai/polis-oss/pkg/domain"
)

// NodeOutcome captures the classification of a node execution result and guides
// the next hop in the DAG.
type NodeOutcome string

const (
	// OutcomeSuccess indicates the node completed work and the happy-path edge should be taken.
	OutcomeSuccess NodeOutcome = "success"
	// OutcomeFailure indicates the node failed without a more specific classification.
	OutcomeFailure NodeOutcome = "failure"
	// OutcomeTimeout indicates the node exceeded its governance deadline.
	OutcomeTimeout NodeOutcome = "timeout"
	// OutcomeRateLimited indicates the node was throttled and should follow the rate-limited edge.
	OutcomeRateLimited NodeOutcome = "ratelimited"
	// OutcomeCircuitOpen indicates the circuit breaker blocked the call.
	OutcomeCircuitOpen NodeOutcome = "circuitopen"
	// OutcomeDeny indicates the node intentionally denied the request (fail-closed posture).
	OutcomeDeny NodeOutcome = "deny"
	// OutcomeRetryable signals the executor should follow retry logic if available.
	OutcomeRetryable NodeOutcome = "retryable"
)

// NodeResult bundles the outcome, optional next-node hint, and mutated state.
type NodeResult struct {
	Outcome  NodeOutcome
	NextHint string
	State    map[string]any
}

// WithDefaults ensures the outcome is set even when handlers omit it.
func (r NodeResult) WithDefaults() NodeResult {
	if r.Outcome == "" {
		r.Outcome = OutcomeSuccess
	}
	return r
}

// Success constructs a success result with optional state.
func Success(state map[string]any) NodeResult {
	return NodeResult{Outcome: OutcomeSuccess, State: state}
}

// Failure constructs a failure result with optional state.
func Failure(state map[string]any) NodeResult {
	return NodeResult{Outcome: OutcomeFailure, State: state}
}

// NodeHandler executes a pipeline node and returns its classified result.
type NodeHandler interface {
	Execute(ctx context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (NodeResult, error)
}
