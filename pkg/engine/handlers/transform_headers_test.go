package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

func TestHeaderTransformHandler_RequestScopeOperations(t *testing.T) {
	handler := NewHeaderTransformHandler(nil)
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Headers: map[string][]string{
				"Authorization": {"Bearer inbound"},
				"X-Old":         {"legacy"},
			},
			AgentID:   "agent-123",
			Method:    http.MethodGet,
			Path:      "/widgets",
			Host:      "api.internal",
			Protocol:  "http",
			SessionID: "session-abc",
		},
		Response:  domain.ResponseContext{},
		Variables: map[string]interface{}{},
	}

	node := &domain.PipelineNode{
		ID:   "transform",
		Type: "transform.headers",
		Config: map[string]interface{}{
			"operations": []interface{}{
				map[string]interface{}{"action": "remove", "headers": []interface{}{"Authorization"}},
				map[string]interface{}{"action": "set", "header": "X-Agent-ID", "value": "${agent.id}"},
				map[string]interface{}{"action": "add", "header": "X-Trace-ID", "values": []interface{}{"trace-1", "trace-2"}},
				map[string]interface{}{"action": "rename", "from": "X-Old", "to": "X-New"},
			},
		},
	}

	result, err := handler.Execute(context.Background(), node, pipelineCtx)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if result.Outcome != runtime.OutcomeSuccess {
		t.Fatalf("expected success outcome, got %s", result.Outcome)
	}

	if _, exists := pipelineCtx.Request.Headers["Authorization"]; exists {
		t.Fatalf("authorization header should be removed")
	}

	agentValues := pipelineCtx.Request.Headers["X-Agent-Id"]
	if len(agentValues) != 1 || agentValues[0] != pipelineCtx.Request.AgentID {
		t.Fatalf("expected X-Agent-Id header to be set to agent id, got %v", agentValues)
	}

	traceValues := pipelineCtx.Request.Headers["X-Trace-Id"]
	if len(traceValues) != 2 {
		t.Fatalf("expected two X-Trace-Id values, got %v", traceValues)
	}

	if _, exists := pipelineCtx.Request.Headers["X-Old"]; exists {
		t.Fatalf("expected X-Old header to be renamed")
	}

	if renamed := pipelineCtx.Request.Headers["X-New"]; len(renamed) != 1 || renamed[0] != "legacy" {
		t.Fatalf("expected X-New to carry previous value, got %v", renamed)
	}
}

func TestHeaderTransformHandler_LegacyRemoveAlias(t *testing.T) {
	handler := NewHeaderTransformHandler(nil)
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Headers: map[string][]string{
				"Authorization": {"Bearer token"},
				"Cookie":        {"session"},
				"Content-Type":  {"application/json"},
			},
		},
		Response:  domain.ResponseContext{},
		Variables: map[string]interface{}{},
	}

	node := &domain.PipelineNode{
		ID:   "remove",
		Type: "transform.headers.remove",
		Config: map[string]interface{}{
			"headers": []interface{}{"Authorization", "Cookie"},
		},
	}

	result, err := handler.Execute(context.Background(), node, pipelineCtx)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if result.Outcome != runtime.OutcomeSuccess {
		t.Fatalf("expected success outcome, got %s", result.Outcome)
	}

	if _, exists := pipelineCtx.Request.Headers["Authorization"]; exists {
		t.Fatalf("authorization header should be removed")
	}
	if _, exists := pipelineCtx.Request.Headers["Cookie"]; exists {
		t.Fatalf("cookie header should be removed")
	}
	if _, exists := pipelineCtx.Request.Headers["Content-Type"]; !exists {
		t.Fatalf("content-type header should remain")
	}
}

func TestHeaderTransformHandler_ResponseScopeStagesOperations(t *testing.T) {
	handler := NewHeaderTransformHandler(nil)
	pipelineCtx := &domain.PipelineContext{
		Request:   domain.RequestContext{Headers: map[string][]string{}},
		Response:  domain.ResponseContext{},
		Variables: map[string]interface{}{},
	}

	node := &domain.PipelineNode{
		ID:   "response",
		Type: "transform.headers",
		Config: map[string]interface{}{
			"scope": "response",
			"operations": []interface{}{
				map[string]interface{}{"action": "remove", "headers": []interface{}{"X-Internal"}},
				map[string]interface{}{"action": "set", "header": "X-Processed", "value": "true"},
			},
		},
	}

	result, err := handler.Execute(context.Background(), node, pipelineCtx)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if result.Outcome != runtime.OutcomeSuccess {
		t.Fatalf("expected success outcome, got %s", result.Outcome)
	}

	raw, exists := pipelineCtx.Variables[ResponseTransformKey]
	if !exists {
		t.Fatalf("expected response transforms to be staged")
	}
	ops, ok := raw.([]HeaderTransformOperation)
	if !ok {
		t.Fatalf("expected staged transforms slice, got %T", raw)
	}
	if len(ops) != 2 {
		t.Fatalf("expected two staged operations, got %d", len(ops))
	}
}

func TestApplyResponseHeaderTransforms(t *testing.T) {
	pipelineCtx := &domain.PipelineContext{
		Request:   domain.RequestContext{Headers: map[string][]string{}},
		Response:  domain.ResponseContext{Status: http.StatusCreated},
		Variables: map[string]interface{}{},
	}

	headers := make(http.Header)
	headers.Set("X-Internal", "secret")
	headers.Set("Content-Type", "application/json")

	ops := []HeaderTransformOperation{
		{Action: "remove", Headers: []string{"X-Internal"}},
		{Action: "add", Header: "X-Upstream-Status", Values: []string{"${response.status}"}},
	}

	ApplyResponseHeaderTransforms(ops, headers, pipelineCtx)

	if _, exists := headers["X-Internal"]; exists {
		t.Fatalf("expected X-Internal header to be removed")
	}
	values := headers.Values("X-Upstream-Status")
	if len(values) != 1 || values[0] != "201" {
		t.Fatalf("expected X-Upstream-Status=201, got %v", values)
	}
	if headers.Get("Content-Type") != "application/json" {
		t.Fatalf("content-type header should remain unchanged")
	}
}
