package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

type retryStubHandler struct {
	calls int
}

func (h *retryStubHandler) Execute(_ context.Context, _ *domain.PipelineNode, _ *domain.PipelineContext) (runtime.NodeResult, error) {
	h.calls++
	if h.calls == 1 {
		return runtime.NodeResult{}, fmt.Errorf("connection reset by peer")
	}
	return runtime.Success(nil), nil
}

func TestExecuteWithGovernanceExposesDeadlineAndRetries(t *testing.T) {
	executor := NewDAGExecutor(DAGExecutorConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	timeoutMS := 500
	pipeline := &domain.Pipeline{
		Defaults: domain.PipelineDefaults{
			TimeoutMS: timeoutMS,
			Retries: domain.PipelineRetryConfig{
				MaxAttempts: 2,
				BaseMS:      1,
				MaxMS:       1,
			},
		},
	}

	node := &domain.PipelineNode{
		ID:   "egress",
		Type: "egress.http",
	}

	handler := &retryStubHandler{}
	meta := handlerMetadata{Kind: "egress.http", Version: "v2", Canonical: "egress.http@v2"}

	tctx := &domain.PipelineContext{}

	result, execMeta, err := executor.executeWithGovernance(context.Background(), pipeline, node, tctx, handler, meta)
	if err != nil {
		t.Fatalf("expected retries to succeed, got error: %v", err)
	}
	if result.Outcome != runtime.OutcomeSuccess {
		t.Fatalf("expected success outcome, got %s", result.Outcome)
	}

	if execMeta.retries != 1 {
		t.Fatalf("expected 1 retry, got %d", execMeta.retries)
	}
	if execMeta.maxRetries != 1 {
		t.Fatalf("expected maxRetries to reflect configuration, got %d", execMeta.maxRetries)
	}
	if execMeta.deadline != time.Duration(timeoutMS)*time.Millisecond {
		t.Fatalf("unexpected deadline %s", execMeta.deadline)
	}
}
