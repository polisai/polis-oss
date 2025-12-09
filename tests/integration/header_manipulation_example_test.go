package integration

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
)

func TestHeaderManipulationExamplePipeline(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	upstream := NewMockUpstream(t)
	defer upstream.Close()

	upstream.SetResponseHeader("X-Internal-Server", "upstream-v1")
	upstream.SetResponseHeader("X-Debug-Info", "trace")
	upstream.SetResponseHeader("X-External", "safe")
	upstream.SetResponse(http.StatusOK, `{"status":"ok"}`)

	fixturePath := headerManipulationFixturePath(t)

	// #nosec G304 -- fixturePath resolved from repository-controlled fixtures
	rawPipeline, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read pipeline fixture: %v", err)
	}

	var pipeline domain.Pipeline
	if err := json.Unmarshal(rawPipeline, &pipeline); err != nil {
		t.Fatalf("failed to unmarshal pipeline fixture: %v", err)
	}

	for i := range pipeline.Nodes {
		if pipeline.Nodes[i].ID == "egress" {
			pipeline.Nodes[i].Config["upstream_url"] = upstream.URL()
		}
	}

	registry := pipelinepkg.NewPipelineRegistry(nil)
	if err := registry.UpdatePipelines(ctx, []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to register pipeline: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
		Logger:   logger,
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	const (
		inboundToken = "Bearer inbound-token"
		sessionID    = "session-123"
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/widgets", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	req.Header.Set("X-Agent-ID", pipeline.AgentID)
	req.Header.Set("Authorization", inboundToken)
	req.Header.Set("X-Internal-Token", "internal-secret")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-ID", sessionID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pipeline request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	WaitForCondition(t, time.Second, func() bool {
		return upstream.LastRequest() != nil
	})

	upstreamHeaders := upstream.LastHeaders()
	if upstreamHeaders == nil {
		t.Fatalf("expected upstream headers to be captured")
	}

	AssertNoCredentialLeak(t, upstreamHeaders, inboundToken)

	if got := upstreamHeaders.Get("X-Forwarded-By"); got != "polis" {
		t.Fatalf("expected X-Forwarded-By=polis, got %q", got)
	}
	if got := upstreamHeaders.Get("X-Proxy-Version"); got != "1.0.0" {
		t.Fatalf("expected X-Proxy-Version=1.0.0, got %q", got)
	}
	if got := upstreamHeaders.Get("X-Agent-Id"); got != pipeline.AgentID {
		t.Fatalf("expected X-Agent-Id=%s, got %q", pipeline.AgentID, got)
	}
	if got := upstreamHeaders.Get("X-Request-Id"); got != sessionID {
		t.Fatalf("expected X-Request-Id=%s, got %q", sessionID, got)
	}

	if upstreamHeaders.Get("X-Internal-Token") != "" {
		t.Fatalf("expected X-Internal-Token header to be stripped")
	}
	if upstreamHeaders.Get("Cookie") != "" {
		t.Fatalf("expected Cookie header to be stripped")
	}

	if resp.Header.Get("X-Internal-Server") != "" {
		t.Fatalf("expected X-Internal-Server header to be removed from response")
	}
	if resp.Header.Get("X-Debug-Info") != "" {
		t.Fatalf("expected X-Debug-Info header to be removed from response")
	}
	if resp.Header.Get("X-External") != "safe" {
		t.Fatalf("expected X-External header to pass through, got %q", resp.Header.Get("X-External"))
	}
}

func headerManipulationFixturePath(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to determine caller information")
	}

	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	return filepath.Join(repoRoot, "tests", "fixtures", "pipelines", "header-manipulation.json")
}
