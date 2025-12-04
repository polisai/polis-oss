package expr

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEvaluator_Evaluate(t *testing.T) {
	lookup := mapLookup(map[string]any{
		"metadata.risk_score":  0.72,
		"header.X-Client-Tier": "premium",
		"policy.blocked":       false,
		"request.method":       "POST",
	})

	eval := NewEvaluator(Options{})

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{
			name: "boolean literal",
			expr: "true",
			want: true,
		},
		{
			name: "numeric and string comparators",
			expr: "metadata.risk_score >= 0.5 && header.X-Client-Tier == \"premium\"",
			want: true,
		},
		{
			name: "negation",
			expr: "!policy.blocked",
			want: true,
		},
		{
			name: "less than comparison",
			expr: "metadata.risk_score < 1.0 && request.method == \"POST\"",
			want: true,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.Evaluate(ctx, tt.expr, lookup)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluator_Errors(t *testing.T) {
	lookup := mapLookup(map[string]any{
		"metadata.risk_score": 0.42,
	})
	eval := NewEvaluator(Options{})

	_, err := eval.Evaluate(context.Background(), "unknown.value == true", lookup)
	if !errors.Is(err, ErrUnknownIdentifier) {
		t.Fatalf("expected ErrUnknownIdentifier, got %v", err)
	}

	_, err = eval.Evaluate(context.Background(), "metadata.risk_score == \"high\"", lookup)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("expected ErrTypeMismatch, got %v", err)
	}

	_, err = eval.Evaluate(context.Background(), "metadata.risk_score >=", lookup)
	if !errors.Is(err, ErrSyntax) {
		t.Fatalf("expected ErrSyntax, got %v", err)
	}
}

func TestEvaluator_Timeout(t *testing.T) {
	eval := NewEvaluator(Options{Timeout: time.Millisecond})

	slowLookup := func(path string) (any, bool) {
		time.Sleep(2 * time.Millisecond)
		if path == "metadata.flag" {
			return true, true
		}
		return nil, false
	}

	_, err := eval.Evaluate(context.Background(), "metadata.flag == true", slowLookup)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}
}

func TestEvaluator_ShortCircuit(t *testing.T) {
	eval := NewEvaluator(Options{})

	var calls int
	lookup := func(path string) (any, bool) {
		if path == "metadata.allow" {
			return true, true
		}
		if path == "metadata.expensive" {
			calls++
			return true, true
		}
		return nil, false
	}

	result, err := eval.Evaluate(context.Background(), "metadata.allow || metadata.expensive", lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Fatalf("expected true result")
	}
	if calls != 0 {
		t.Fatalf("expected short-circuit to skip expensive lookup, got %d calls", calls)
	}
}

func mapLookup(values map[string]any) LookupFunc {
	return func(path string) (any, bool) {
		v, ok := values[path]
		return v, ok
	}
}
