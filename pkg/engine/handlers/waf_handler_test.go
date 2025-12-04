package handlers

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/policy/waf"
)

func TestWAFHandler_StreamBlocks(t *testing.T) {
	ctx := context.Background()

	registry := waf.NewRegistry()
	if err := registry.Register(waf.Rule{
		Name:     "test.union-select",
		Pattern:  `(?i)union select`,
		Severity: waf.SeverityHigh,
		Action:   waf.ActionBlock,
	}); err != nil {
		t.Fatalf("failed to register waf rule: %v", err)
	}

	handler := NewWAFHandlerWithRegistry(nil, registry)

	pipelineCtx := &domain.PipelineContext{
		Variables: map[string]interface{}{},
		Security:  domain.SecurityContext{},
		Telemetry: domain.TelemetryContext{Taints: make(map[string]domain.TelemetryTaint)},
	}

	pipelineCtx.Variables["request.body"] = io.NopCloser(strings.NewReader("select * from users UNION SELECT password"))

	node := &domain.PipelineNode{
		ID:   "waf",
		Type: "waf",
		Config: map[string]interface{}{
			"rules": []interface{}{"test.union-select"},
		},
	}

	result, err := handler.Execute(ctx, node, pipelineCtx)
	// WAF blocking returns OutcomeDeny without error to prevent retries
	if err != nil {
		t.Fatalf("unexpected error from WAF handler: %v", err)
	}
	if result.Outcome != runtime.OutcomeDeny {
		t.Fatalf("expected deny outcome, got %s", result.Outcome)
	}

	if !pipelineCtx.Security.Blocked {
		t.Fatalf("expected security context to be marked blocked")
	}

	if pipelineCtx.Security.BlockReason != "waf.blocked" {
		t.Fatalf("unexpected block reason: %s", pipelineCtx.Security.BlockReason)
	}
}
