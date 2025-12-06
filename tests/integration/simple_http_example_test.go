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

func TestSimpleHTTPExamplePipeline(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	upstream := NewMockUpstream(t)
	defer upstream.Close()

	upstream.SetResponse(http.StatusOK, `{"status":"ok"}`)

	fixturePath := simpleHTTPFixturePath(t)

	// #nosec G304 -- fixturePath is resolved from repository fixtures under tests' control
	rawPipeline, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read pipeline fixture: %v", err)
	}

	var pipeline domain.Pipeline
	if err := json.Unmarshal(rawPipeline, &pipeline); err != nil {
		t.Fatalf("failed to unmarshal pipeline fixture: %v", err)
	}

	foundEgress := false
	for i := range pipeline.Nodes {
		if pipeline.Nodes[i].ID == "egress" {
			pipeline.Nodes[i].Config["upstream_url"] = upstream.URL()
			foundEgress = true
			break
		}
	}

	if !foundEgress {
		t.Fatalf("pipeline example missing egress node")
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/widgets?trace=1", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	req.Header.Set("X-Agent-ID", pipeline.AgentID)
	req.Header.Set("Authorization", "Bearer inbound-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pipeline request failed: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Fatalf("failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	WaitForCondition(t, time.Second, func() bool {
		return upstream.LastRequest() != nil
	})

	headers := upstream.LastHeaders()
	if headers == nil {
		t.Fatalf("expected upstream headers to be captured")
	}

	if auth := headers.Get("Authorization"); auth != "" {
		t.Errorf("expected authorization header to be stripped, got %q", auth)
	}

	if ct := headers.Get("Content-Type"); ct == "" {
		t.Errorf("expected content-type header to be preserved")
	}

	lastReq := upstream.LastRequest()
	if lastReq == nil {
		t.Fatalf("expected upstream request to be captured")
		return
	}

	if lastReq.URL.Path != "/v1/widgets" {
		t.Errorf("expected upstream path /v1/widgets, got %s", lastReq.URL.Path)
	}
}

func simpleHTTPFixturePath(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to determine caller information")
	}

	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	return filepath.Join(repoRoot, "tests", "fixtures", "pipelines", "simple-http.json")
}
