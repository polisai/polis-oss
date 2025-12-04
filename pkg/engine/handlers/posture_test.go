package handlers

import (
	"io"
	"log/slog"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
)

func TestResolveNodePosture(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("uses node posture when present", func(t *testing.T) {
		node := &domain.PipelineNode{Posture: "Fail-Open"}
		posture := resolveNodePosture(node, "fail-closed", logger)
		if posture != "fail-open" {
			t.Fatalf("expected fail-open, got %s", posture)
		}
	})

	t.Run("falls back to config posture", func(t *testing.T) {
		node := &domain.PipelineNode{Config: map[string]interface{}{"posture": "Fail-Open"}}
		posture := resolveNodePosture(node, "fail-closed", logger)
		if posture != "fail-open" {
			t.Fatalf("expected fail-open, got %s", posture)
		}
	})

	t.Run("returns default when no posture provided", func(t *testing.T) {
		node := &domain.PipelineNode{}
		posture := resolveNodePosture(node, "fail-closed", logger)
		if posture != "fail-closed" {
			t.Fatalf("expected fail-closed, got %s", posture)
		}
	})

	t.Run("returns default when config posture isn't string", func(t *testing.T) {
		node := &domain.PipelineNode{Config: map[string]interface{}{"posture": 42}}
		posture := resolveNodePosture(node, "fail-open", logger)
		if posture != "fail-open" {
			t.Fatalf("expected fail-open, got %s", posture)
		}
	})
}
