package handlers

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/policy/dlp"
	"github.com/polisai/polis-oss/pkg/storage"
)

func TestDLPHandler_RequestScopeRedacts(t *testing.T) {
	recordingRegistry := dlp.NewRegistry()
	if err := recordingRegistry.Register(dlp.Rule{
		Name:        "test.email",
		Pattern:     `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
		Action:      dlp.ActionRedact,
		Replacement: "[EMAIL]",
	}); err != nil {
		t.Fatalf("failed to register test rule: %v", err)
	}

	vault := storage.NewMemoryTokenVault()
	handler := NewDLPHandler(nil, vault)

	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Headers: map[string][]string{
				"Content-Length": {"22"},
			},
		},
		Variables: map[string]interface{}{
			"request.body": io.NopCloser(strings.NewReader("hello test@example.com")),
		},
		Security:  domain.SecurityContext{},
		Telemetry: domain.TelemetryContext{},
	}

	node := &domain.PipelineNode{
		ID:   "dlp",
		Type: "dlp.inspect",
		Config: map[string]interface{}{
			"rules": []interface{}{"test.email"},
			"scope": "request",
		},
	}

	tResult, err := handler.Execute(ctx, node, pipelineCtx)
	if err != nil {
		t.Fatalf("handler.Execute() error = %v", err)
	}
	if tResult.Outcome != runtime.OutcomeSuccess {
		t.Fatalf("unexpected outcome: %s", tResult.Outcome)
	}

	replay, ok := pipelineCtx.Variables["request.body"].(io.ReadCloser)
	if !ok || replay == nil {
		t.Fatalf("expected replay body to be stored")
	}

	sanitized, readErr := io.ReadAll(replay)
	if readErr != nil {
		t.Fatalf("failed to read replay body: %v", readErr)
	}

	if closeErr := replay.Close(); closeErr != nil {
		t.Fatalf("failed to close replay body: %v", closeErr)
	}

	expected := "hello [EMAIL]"
	if string(sanitized) != expected {
		t.Fatalf("unexpected sanitized payload: %q", sanitized)
	}

	lengthValues := pipelineCtx.Request.Headers["Content-Length"]
	if len(lengthValues) != 1 || lengthValues[0] != "13" {
		t.Fatalf("expected updated Content-Length header, got %v", lengthValues)
	}

	if len(pipelineCtx.Security.Findings) != 1 {
		t.Fatalf("expected one security finding, got %d", len(pipelineCtx.Security.Findings))
	}

	summary := pipelineCtx.Security.Findings[0].Summary
	if !strings.Contains(summary, "request body") {
		t.Fatalf("expected summary to reference request body, got %q", summary)
	}

	if pipelineCtx.Telemetry.Taints["http.request.body"].Attribute != "http.request.body" {
		t.Fatalf("expected telemetry taint for http.request.body")
	}
}
