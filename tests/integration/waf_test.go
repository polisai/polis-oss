package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
)

func TestPipeline_WAFBlocksMaliciousBody(t *testing.T) {
	upstream := NewMockUpstream(t)
	defer upstream.Close()

	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)

	pipeline := domain.Pipeline{
		ID:       "waf-agent",
		Version:  1,
		AgentID:  "waf-agent",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "waf",
				Type: "waf",
				Config: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":     "union-select",
							"pattern":  `(?i)union select`,
							"action":   "block",
							"severity": "high",
						},
					},
					"chunk_size": 16,
					"overlap":    8,
				},
				On: domain.NodeHandlers{
					Success: "egress",
					Failure: "deny",
				},
			},
			{
				ID:   "egress",
				Type: "egress",
				Config: map[string]interface{}{
					"upstream_url": upstream.URL(),
				},
			},
			{
				ID:   "deny",
				Type: "terminal.deny",
				Config: map[string]interface{}{
					"status": 403,
					"code":   "WAF_BLOCKED",
				},
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to update pipelines: %v", err)
	}

	handler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{Registry: registry})
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/test", strings.NewReader("select * from users UNION SELECT password"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "waf-agent")
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 status for blocked request, got %d", resp.StatusCode)
	}

	if got := len(upstream.GetRequests()); got != 0 {
		t.Fatalf("expected upstream to receive 0 requests, got %d", got)
	}
}
