package integration

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
)

func TestPipeline_DLPStreamingRedaction(t *testing.T) {
	sseEvents := []string{
		"data: contact support@example.com\n\n",
		"data: or reach sales@example.com\n\n",
	}

	streamingUpstream := NewStreamingMockUpstream(t, sseEvents, 5*time.Millisecond)
	streamingUpstream.SetContentType("text/event-stream")
	defer streamingUpstream.Close()

	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)

	pipeline := domain.Pipeline{
		ID:       "dlp-agent",
		Version:  1,
		AgentID:  "dlp-agent",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "dlp",
				Type: "dlp",
				Config: map[string]interface{}{
					"chunk_size": 32,
					"overlap":    12,
					"rules": []interface{}{
						map[string]interface{}{
							"name":        "email",
							"pattern":     `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
							"action":      "redact",
							"replacement": "[REDACTED:email]",
						},
					},
				},
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress",
				Config: map[string]interface{}{
					"upstream_url": streamingUpstream.URL(),
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

	req, err := http.NewRequest(http.MethodGet, server.URL+"/stream", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "dlp-agent")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	var combined strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("failed to read response: %v", err)
		}
		combined.WriteString(line)
	}

	result := combined.String()
	if strings.Contains(result, "support@example.com") || strings.Contains(result, "sales@example.com") {
		t.Fatalf("expected emails to be redacted, got: %s", result)
	}

	if !strings.Contains(result, "[REDACTED:email]") {
		t.Fatalf("missing redacted marker in response: %s", result)
	}
}

func TestPipeline_DLPBufferedRedaction(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("contact support@example.com for help"))
	}))
	defer upstream.Close()

	factory := pipelinepkg.NewEngineFactory(nil, nil)
	registry := pipelinepkg.NewPipelineRegistry(factory)

	pipeline := domain.Pipeline{
		ID:       "dlp-buffered",
		Version:  1,
		AgentID:  "dlp-buffered",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "dlp",
				Type: "dlp",
				Config: map[string]interface{}{
					"mode": "buffered",
					"rules": []interface{}{
						map[string]interface{}{
							"name":        "email",
							"pattern":     `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
							"action":      "redact",
							"replacement": "[REDACTED:email]",
						},
					},
				},
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress",
				Config: map[string]interface{}{
					"upstream_url": upstream.URL,
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

	req, err := http.NewRequest(http.MethodGet, server.URL+"/buffered", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "dlp-buffered")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	body := string(bodyBytes)

	if strings.Contains(body, "support@example.com") {
		t.Fatalf("expected email to be redacted, got %s", body)
	}
	if !strings.Contains(body, "[REDACTED:email]") {
		t.Fatalf("missing redaction marker, body: %s", body)
	}
}
