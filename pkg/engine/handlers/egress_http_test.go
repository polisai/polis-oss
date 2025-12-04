package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

func TestEgressHTTPHandler_StripHeadersAndTimeout(t *testing.T) {
	handler := NewEgressHTTPHandler(slog.Default())

	ctx := context.Background()

	pipelineCtx := &domain.PipelineContext{
		Pipeline: &domain.Pipeline{
			Defaults: domain.PipelineDefaults{TimeoutMS: 7000},
		},
		Request: domain.RequestContext{
			Method: "GET",
			Path:   "/widgets",
			Headers: map[string][]string{
				"Authorization": {"Bearer token"},
				"Content-Type":  {"application/json"},
			},
			AgentID: "agent-1",
		},
		Variables: map[string]interface{}{},
	}

	node := &domain.PipelineNode{
		ID: "egress",
		Config: map[string]interface{}{
			"upstream_url":  "https://api.example.com",
			"timeout_ms":    float64(3000),
			"strip_headers": []interface{}{"Authorization", "X-Unused"},
		},
		Governance: domain.PipelineGovernanceConfig{TimeoutMS: 5000},
	}

	result, err := handler.Execute(ctx, node, pipelineCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != runtime.OutcomeSuccess {
		t.Fatalf("expected success outcome, got %s", result.Outcome)
	}

	headers, ok := pipelineCtx.Variables["egress.headers"].(http.Header)
	if !ok {
		t.Fatalf("egress headers not stored in context")
	}

	if _, exists := headers["Authorization"]; exists {
		t.Fatalf("authorization header was not stripped")
	}
	if _, exists := headers["Content-Type"]; !exists {
		t.Fatalf("content-type header missing after strip")
	}

	timeoutValue, ok := pipelineCtx.Variables["egress.timeout"].(time.Duration)
	if !ok {
		t.Fatalf("expected timeout to be stored as time.Duration")
	}

	if timeoutValue != 3*time.Second {
		t.Fatalf("expected timeout 3s, got %s", timeoutValue)
	}

	selectedMs, ok := pipelineCtx.Variables["egress.timeout.selected_ms"].(int)
	if !ok {
		t.Fatalf("expected selected timeout to be stored")
	}

	if selectedMs != 3000 {
		t.Fatalf("expected selected timeout 3000ms, got %d", selectedMs)
	}

	selectedSources, ok := pipelineCtx.Variables["egress.timeout.sources"].([]string)
	if !ok {
		t.Fatalf("expected timeout sources to be stored")
	}

	if len(selectedSources) != 1 || selectedSources[0] != "node.config.timeout_ms" {
		t.Fatalf("unexpected timeout sources: %v", selectedSources)
	}

	allCandidates, ok := pipelineCtx.Variables["egress.timeout.candidates"].([]string)
	if !ok {
		t.Fatalf("expected timeout candidates to be stored")
	}

	expectedCandidates := []string{
		"7000ms<- pipeline.defaults.timeoutMs",
		"5000ms<- node.egress.governance.timeoutMs",
		"3000ms<- node.config.timeout_ms",
	}

	if !reflect.DeepEqual(expectedCandidates, allCandidates) {
		t.Fatalf("unexpected candidate list: %v", allCandidates)
	}
}
