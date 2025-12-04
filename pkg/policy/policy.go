package policy

import (
	"context"
	"errors"

	"github.com/polisai/polis-oss/pkg/domain"
)

// Action defines the outcome of a policy evaluation.
type Action string

const (
	// ActionAllow permits the request to proceed.
	ActionAllow Action = "allow"
	// ActionRedact allows the request after redaction is applied.
	ActionRedact Action = "redact"
	// ActionBlock terminates the request.
	ActionBlock Action = "block"
)

// Decision captures the result from a filter evaluation.
type Decision struct {
	Action   Action
	Reason   string
	Metadata map[string]string
	Outputs  map[string]any
}

// Input provides context for policy evaluation.
type Input struct {
	RouteID      string
	PolicyID     string
	Identity     domain.PolicyIdentity
	Attributes   map[string]any
	Findings     map[string]any
	Generation   string
	Entrypoint   string
	DisableCache bool
}

// Filter evaluates a policy decision for a given input.
type Filter interface {
	Evaluate(ctx context.Context, input Input) (Decision, error)
}

// Chain composes multiple filters, short-circuiting on terminal decisions.
type Chain struct {
	filters []Filter
}

// NewChain constructs a filter chain.
func NewChain(filters ...Filter) Chain {
	return Chain{filters: append([]Filter(nil), filters...)}
}

// Evaluate executes the chain until a terminal decision is produced.
func (c Chain) Evaluate(ctx context.Context, input Input) (Decision, error) {
	if len(c.filters) == 0 {
		return Decision{Action: ActionAllow, Metadata: map[string]string{}}, nil
	}

	for _, filter := range c.filters {
		decision, err := filter.Evaluate(ctx, input)
		if err != nil {
			return Decision{}, err
		}
		if decision.Metadata == nil {
			decision.Metadata = map[string]string{}
		}
		if decision.Outputs == nil {
			decision.Outputs = map[string]any{}
		}
		switch decision.Action {
		case ActionAllow:
			// continue evaluating subsequent filters
		case ActionRedact, ActionBlock:
			return decision, nil
		default:
			return Decision{}, errors.New("unknown policy action")
		}
	}

	return Decision{Action: ActionAllow, Metadata: map[string]string{}}, nil
}
