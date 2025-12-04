package engine

import (
	"log/slog"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
)

func TestTriggerMatcher_HTTPHeaders_AcceptSSE(t *testing.T) {
	matcher := newTriggerMatcher(slog.Default())
	pipeline := &domain.Pipeline{
		ID: "test-pipeline",
		Triggers: []domain.Trigger{
			{
				Type: "http.request",
				Match: map[string]interface{}{
					"headers": map[string]interface{}{
						"Accept": "text/event-stream",
					},
				},
			},
		},
	}

	ctx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:   "GET",
			Protocol: "http",
			Headers: map[string][]string{
				"Accept": {"text/event-stream"},
			},
		},
		Variables: make(map[string]interface{}),
	}

	result := matcher.Match(pipeline, ctx)

	if !result.Matched {
		t.Fatalf("expected trigger to match")
	}
	if !result.Streaming {
		t.Fatalf("expected streaming to be true")
	}
	if result.StreamingMode != "sse" {
		t.Fatalf("expected streaming mode sse, got %q", result.StreamingMode)
	}
	if result.TriggerIndex != 0 {
		t.Fatalf("expected trigger index 0, got %d", result.TriggerIndex)
	}
}

func TestTriggerMatcher_HTTPHeaders_NoMatch(t *testing.T) {
	matcher := newTriggerMatcher(slog.Default())
	pipeline := &domain.Pipeline{
		ID: "test-pipeline",
		Triggers: []domain.Trigger{
			{
				Type: "http.request",
				Match: map[string]interface{}{
					"headers": map[string]interface{}{
						"Accept": "text/event-stream",
					},
				},
			},
		},
	}

	ctx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:   "GET",
			Protocol: "http",
			Headers: map[string][]string{
				"Accept": {"application/json"},
			},
		},
		Variables: make(map[string]interface{}),
	}

	result := matcher.Match(pipeline, ctx)

	if result.Matched {
		t.Fatalf("expected trigger not to match")
	}
}

func TestTriggerMatcher_HTTPHeaders_UpgradeWebsocket(t *testing.T) {
	matcher := newTriggerMatcher(slog.Default())
	pipeline := &domain.Pipeline{
		ID: "ws-pipeline",
		Triggers: []domain.Trigger{
			{
				Type: "http.request",
				Match: map[string]interface{}{
					"headers": map[string]interface{}{
						"Upgrade": "websocket",
					},
				},
			},
		},
	}

	ctx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:   "GET",
			Protocol: "http",
			Headers: map[string][]string{
				"Upgrade":    {"websocket"},
				"Connection": {"Upgrade"},
			},
		},
		Variables: make(map[string]interface{}),
	}

	result := matcher.Match(pipeline, ctx)

	if !result.Matched {
		t.Fatalf("expected trigger to match")
	}
	if !result.Streaming {
		t.Fatalf("expected streaming to be true")
	}
	if result.StreamingMode != "websocket" {
		t.Fatalf("expected streaming mode websocket, got %q", result.StreamingMode)
	}
}
