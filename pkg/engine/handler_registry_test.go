package engine

import (
	"context"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

type stubHandler struct{}

func (s *stubHandler) Execute(context.Context, *domain.PipelineNode, *domain.PipelineContext) (runtime.NodeResult, error) {
	return runtime.Success(nil), nil
}

func TestHandlerRegistryResolvePolicyAliases(t *testing.T) {
	registry := newHandlerRegistry()
	wafHandler := &stubHandler{}
	dlpHandler := &stubHandler{}

	registry.register("waf.inspect", "v1", wafHandler, "policy.waf")
	registry.register("dlp.inspect", "v1", dlpHandler, "policy.dlp")

	handler, meta, ok := registry.resolve("policy.waf")
	if !ok {
		t.Fatalf("expected policy.waf alias to resolve")
	}
	if handler != wafHandler {
		t.Fatalf("resolved handler mismatch for policy.waf")
	}
	if meta.Canonical != "waf.inspect@v1" {
		t.Fatalf("expected canonical key waf.inspect@v1, got %s", meta.Canonical)
	}

	handler, meta, ok = registry.resolve("policy.dlp")
	if !ok {
		t.Fatalf("expected policy.dlp alias to resolve")
	}
	if handler != dlpHandler {
		t.Fatalf("resolved handler mismatch for policy.dlp")
	}
	if meta.Canonical != "dlp.inspect@v1" {
		t.Fatalf("expected canonical key dlp.inspect@v1, got %s", meta.Canonical)
	}
}
