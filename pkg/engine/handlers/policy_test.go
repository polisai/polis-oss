package handlers

import (
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/policy"
)

func TestPolicyHandlerPublishDecision(t *testing.T) {
	handler := NewPolicyHandler(nil)

	pipelineCtx := &domain.PipelineContext{
		Variables: make(map[string]any),
	}

	node := &domain.PipelineNode{ID: "risk_evaluation"}

	decision := policy.Decision{
		Action: policy.ActionAllow,
		Reason: "approved",
		Metadata: map[string]string{
			"risk_bucket": "medium",
			"risk_score":  "0.62",
		},
		Outputs: map[string]any{
			"risk_score": 0.62,
			"flags":      []string{"manual_review"},
		},
	}

	handler.publishPolicyDecision(pipelineCtx, node, decision)

	if got := pipelineCtx.Variables["policy.action"]; got != string(decision.Action) {
		t.Fatalf("expected policy.action %q, got %v", decision.Action, got)
	}

	baseKey := "policy.risk_evaluation"
	snapshot, ok := pipelineCtx.Variables[baseKey].(map[string]any)
	if !ok {
		t.Fatalf("expected %s snapshot", baseKey)
	}

	if snapshot["reason"] != decision.Reason {
		t.Fatalf("expected snapshot reason %q, got %v", decision.Reason, snapshot["reason"])
	}

	if _, exists := pipelineCtx.Variables[baseKey+".risk_score"]; !exists {
		t.Fatalf("expected namespaced risk_score variable")
	}

	if value, ok := pipelineCtx.Variables["risk_score"].(float64); !ok || value != 0.62 {
		t.Fatalf("expected flattened risk_score 0.62, got %T %v", pipelineCtx.Variables["risk_score"], pipelineCtx.Variables["risk_score"])
	}

	if _, promoted := pipelineCtx.Variables["flags"]; promoted {
		t.Fatalf("did not expect slice to be promoted to top-level")
	}
}
