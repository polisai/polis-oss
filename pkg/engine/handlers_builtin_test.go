package engine

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

func TestTerminalAllowHandler_SetsDefaultStatus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := &TerminalAllowHandler{logger: logger}

	pipelineCtx := &domain.PipelineContext{Response: domain.ResponseContext{}}

	result, err := handler.Execute(context.Background(), &domain.PipelineNode{ID: "allow"}, pipelineCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != runtime.OutcomeSuccess {
		t.Fatalf("expected success outcome, got %s", result.Outcome)
	}
	if pipelineCtx.Response.Status != http.StatusOK {
		t.Fatalf("expected response status 200, got %d", pipelineCtx.Response.Status)
	}
}

func TestTerminalAllowHandler_PreservesExistingStatus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := &TerminalAllowHandler{logger: logger}

	pipelineCtx := &domain.PipelineContext{Response: domain.ResponseContext{Status: http.StatusAccepted}}

	result, err := handler.Execute(context.Background(), &domain.PipelineNode{ID: "allow"}, pipelineCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != runtime.OutcomeSuccess {
		t.Fatalf("expected success outcome, got %s", result.Outcome)
	}
	if pipelineCtx.Response.Status != http.StatusAccepted {
		t.Fatalf("expected status to remain %d, got %d", http.StatusAccepted, pipelineCtx.Response.Status)
	}
}

func TestTerminalDenyHandler_MarksPipelineContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := &TerminalDenyHandler{logger: logger}

	pipelineCtx := &domain.PipelineContext{
		Response:  domain.ResponseContext{},
		Security:  domain.SecurityContext{},
		Variables: make(map[string]interface{}),
	}

	node := &domain.PipelineNode{
		ID: "deny",
		Config: map[string]interface{}{
			"status":  451,
			"code":    "LEGAL_BLOCK",
			"message": "Denied for compliance",
		},
	}

	result, err := handler.Execute(context.Background(), node, pipelineCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != runtime.OutcomeDeny {
		t.Fatalf("expected deny outcome, got %s", result.Outcome)
	}
	if pipelineCtx.Response.Status != 451 {
		t.Fatalf("expected response status 451, got %d", pipelineCtx.Response.Status)
	}
	if !pipelineCtx.Security.Blocked {
		t.Fatalf("expected security blocked flag to be set")
	}
	if pipelineCtx.Security.BlockReason != "LEGAL_BLOCK" {
		t.Fatalf("unexpected block reason: %s", pipelineCtx.Security.BlockReason)
	}
	if got := pipelineCtx.Variables[responseErrorCodeKey]; got != "LEGAL_BLOCK" {
		t.Fatalf("unexpected error code: %v", got)
	}
	if got := pipelineCtx.Variables[responseErrorMessageKey]; got != "Denied for compliance" {
		t.Fatalf("unexpected error message: %v", got)
	}
	if ct := pipelineCtx.Response.Headers["Content-Type"]; len(ct) == 0 || ct[0] != "application/json" {
		t.Fatalf("expected content-type to be application/json, got %v", ct)
	}
}

func TestTerminalDenyHandler_Defaults(t *testing.T) {
	handler := &TerminalDenyHandler{}
	pipelineCtx := &domain.PipelineContext{Response: domain.ResponseContext{}, Security: domain.SecurityContext{}}

	result, err := handler.Execute(context.Background(), &domain.PipelineNode{ID: "deny"}, pipelineCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != runtime.OutcomeDeny {
		t.Fatalf("expected deny outcome, got %s", result.Outcome)
	}
	if pipelineCtx.Response.Status != http.StatusForbidden {
		t.Fatalf("expected default status 403, got %d", pipelineCtx.Response.Status)
	}
	if pipelineCtx.Security.BlockReason != "ACCESS_DENIED" {
		t.Fatalf("expected default block reason ACCESS_DENIED, got %s", pipelineCtx.Security.BlockReason)
	}
}
