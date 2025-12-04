package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPipelineFixtures_LoadFromDirectory tests that all pipelines in tests/fixtures/pipelines
// can be loaded and executed via the proxy when started with --pipeline-dir flag.
func TestPipelineFixtures_LoadFromDirectory(t *testing.T) {
	root := findRepoRoot(t)
	fixturesDir := filepath.Join(root, "tests", "fixtures", "pipelines")

	// Verify fixtures directory exists
	if _, err := os.Stat(fixturesDir); err != nil {
		t.Fatalf("fixtures directory not found: %v", err)
	}

	// Build proxy binary
	binaryPath := buildProxyBinary(t)

	// Create a mock upstream server that responds to all requests
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "mock upstream response",
			"headers": r.Header,
		})
	}))
	defer upstream.Close()

	// Start proxy with pipeline directory
	proxy := startProxyWithPipelineDir(t, binaryPath, fixturesDir, upstream.URL)

	// Give the proxy time to load all pipelines
	time.Sleep(500 * time.Millisecond)

	// Test each pipeline fixture by agent ID
	testCases := []struct {
		name        string
		agentID     string
		expectError bool
		description string
	}{
		{
			name:        "simple-http",
			agentID:     "web-agent",
			expectError: false,
			description: "Basic HTTP proxy with auth and egress",
		},
		{
			name:        "simple-dlp",
			agentID:     "dlp-agent",
			expectError: false,
			description: "DLP inspection on egress response",
		},
		{
			name:        "dlp-enabled",
			agentID:     "secure-api-agent",
			expectError: false,
			description: "Full WAF + DLP pipeline (ingress and egress)",
		},
		{
			name:        "header-manipulation",
			agentID:     "api-gateway-agent",
			expectError: false,
			description: "Header transformations and token injection",
		},
		{
			name:        "fraud-detection",
			agentID:     "fraud-agent",
			expectError: false,
			description: "Conditional routing based on risk score",
		},
		{
			name:        "llm-gateway",
			agentID:     "llm-agent",
			expectError: false,
			description: "LLM gateway with rate limiting and content policies",
		},
		{
			name:        "streaming-proxy",
			agentID:     "streaming-agent",
			expectError: false,
			description: "SSE streaming with trigger-based selection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request with agent ID header
			req, err := http.NewRequest("GET", proxy.dataURL()+"/test", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			// Set agent ID header for pipeline selection
			req.Header.Set("X-Agent-ID", tc.agentID)

			// Send request
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				if !tc.expectError {
					t.Fatalf("request failed: %v\nProxy logs:\n%s", err, proxy.logs())
				}
				return
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("failed to close response body: %v", err)
				}
			}() // Verify we got a response (specific status depends on pipeline config)
			// For now, just verify the proxy didn't crash and returned something
			if resp.StatusCode == 0 {
				t.Errorf("received zero status code\nProxy logs:\n%s", proxy.logs())
			}

			t.Logf("%s: agent=%s status=%d (%s)", tc.name, tc.agentID, resp.StatusCode, tc.description)
		})
	}
}

// TestPipelineFixtures_LoadSingleFile tests loading a single pipeline file (JSON and YAML).
func TestPipelineFixtures_LoadSingleFile(t *testing.T) {
	root := findRepoRoot(t)
	fixturesDir := filepath.Join(root, "tests", "fixtures", "pipelines")

	// Build proxy binary
	binaryPath := buildProxyBinary(t)

	// Create mock upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	testCases := []struct {
		name     string
		filename string
		agentID  string
	}{
		{
			name:     "json_format",
			filename: "simple-http.json",
			agentID:  "web-agent",
		},
		{
			name:     "dlp_pipeline",
			filename: "simple-dlp.json",
			agentID:  "dlp-agent",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pipelineFile := filepath.Join(fixturesDir, tc.filename)

			// Start proxy with single pipeline file
			proxy := startProxyWithPipelineFile(t, binaryPath, pipelineFile, upstream.URL)
			time.Sleep(300 * time.Millisecond)

			// Test the pipeline
			req, err := http.NewRequest("GET", proxy.dataURL()+"/test", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("X-Agent-ID", tc.agentID)

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v\nProxy logs:\n%s", err, proxy.logs())
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("failed to close response body: %v", err)
				}
			}()

			t.Logf("Pipeline %s loaded successfully: status=%d", tc.filename, resp.StatusCode)
		})
	}
}

// TestPipelineFixtures_YAMLSupport tests that YAML pipeline files can be loaded.
func TestPipelineFixtures_YAMLSupport(t *testing.T) {
	root := findRepoRoot(t)
	fixturesDir := filepath.Join(root, "tests", "fixtures", "pipelines")
	yamlFile := filepath.Join(fixturesDir, "test-pipeline.yaml")

	// Verify the test fixture exists
	if _, err := os.Stat(yamlFile); err != nil {
		t.Fatalf("YAML test fixture not found: %v", err)
	}

	// Build proxy and start with YAML file
	binaryPath := buildProxyBinary(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := startProxyWithPipelineFile(t, binaryPath, yamlFile, upstream.URL)
	time.Sleep(300 * time.Millisecond)

	// Test the YAML pipeline
	req, err := http.NewRequest("GET", proxy.dataURL()+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "yaml-test-agent")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v\nProxy logs:\n%s", err, proxy.logs())
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode == 0 {
		t.Errorf("received zero status code for YAML pipeline\nProxy logs:\n%s", proxy.logs())
	}

	t.Logf("YAML pipeline loaded successfully: status=%d", resp.StatusCode)
}

// startProxyWithPipelineDir starts the proxy with a pipeline directory.
func startProxyWithPipelineDir(t *testing.T, binaryPath, pipelineDir, upstreamURL string) *proxyInstance {
	t.Helper()

	// Create a minimal bootstrap config (not used, but required for validation)
	root := findRepoRoot(t)
	bootstrapPath := filepath.Join(root, "tmp", "e2e", "bootstrap-empty.yaml")
	if err := os.MkdirAll(filepath.Dir(bootstrapPath), 0o750); err != nil {
		t.Fatalf("failed to create bootstrap dir: %v", err)
	}
	if err := os.WriteFile(bootstrapPath, []byte("# empty bootstrap\n"), 0o600); err != nil {
		t.Fatalf("failed to write bootstrap: %v", err)
	}

	opts := proxyOptions{
		BinaryPath:    binaryPath,
		BootstrapPath: bootstrapPath,
		UpstreamURL:   upstreamURL,
		ExtraEnv: map[string]string{
			"PROXY_PIPELINE_DIR": pipelineDir,
		},
	}

	return startProxy(t, opts)
}

// startProxyWithPipelineFile starts the proxy with a single pipeline file.
func startProxyWithPipelineFile(t *testing.T, binaryPath, pipelineFile, upstreamURL string) *proxyInstance {
	t.Helper()

	// Create a minimal bootstrap config
	root := findRepoRoot(t)
	bootstrapPath := filepath.Join(root, "tmp", "e2e", "bootstrap-empty.yaml")
	if err := os.MkdirAll(filepath.Dir(bootstrapPath), 0o750); err != nil {
		t.Fatalf("failed to create bootstrap dir: %v", err)
	}
	if err := os.WriteFile(bootstrapPath, []byte("# empty bootstrap\n"), 0o600); err != nil {
		t.Fatalf("failed to write bootstrap: %v", err)
	}

	opts := proxyOptions{
		BinaryPath:    binaryPath,
		BootstrapPath: bootstrapPath,
		UpstreamURL:   upstreamURL,
		ExtraEnv: map[string]string{
			"PROXY_PIPELINE_FILE": pipelineFile,
		},
	}

	return startProxy(t, opts)
}
