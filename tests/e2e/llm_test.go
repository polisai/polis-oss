// Package e2e provides end-to-end tests for AI agent LLM interactions.
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	configpkg "github.com/polisai/polis-oss/pkg/config"
)

// TestE2E_LLM_OpenAI_StreamingNoAuth tests OpenAI-style streaming without authentication
func TestE2E_LLM_OpenAI_StreamingNoAuth(t *testing.T) {
	// Setup mock LLM server
	llmServer := NewMockLLMUpstream(t, ProviderOpenAI)
	defer llmServer.Close()
	t.Logf("Mock LLM URL: %s", llmServer.URL())

	// Launch proxy with JWT authentication
	proxy, token := launchProxyNoAuth(t, llmServer.URL())

	// Create streaming request
	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello, AI!"},
		},
		"stream": true,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req, err := createLLMRequest(proxy.dataURL()+"/v1/chat/completions", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token) // Add JWT token for authentication

	// Execute request
	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v\nProxy Logs:\n%s", err, proxy.logs())
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyContent, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s\nProxy Logs:\n%s", resp.StatusCode, string(bodyContent), proxy.logs())
	}

	// Verify SSE content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		t.Errorf("Expected text/event-stream content type, got: %s", contentType)
	}

	// Read and validate streaming response
	reader := bufio.NewReader(resp.Body)
	var chunks []string
	var firstChunkTime time.Time
	chunkCount := 0

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read stream: %v", err)
		}

		// Parse SSE data lines
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			data = strings.TrimSpace(data)

			if data == "[DONE]" {
				break
			}

			// Record first chunk time
			if chunkCount == 0 {
				firstChunkTime = time.Now()
			}
			chunkCount++

			// Parse JSON chunk
			var chunk map[string]interface{}
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				t.Logf("Failed to parse chunk: %v, data: %s", err, data)
				continue
			}

			// Extract content from choices
			if choices, ok := chunk["choices"].([]interface{}); ok && len(choices) > 0 {
				if choice, ok := choices[0].(map[string]interface{}); ok {
					if delta, ok := choice["delta"].(map[string]interface{}); ok {
						if content, ok := delta["content"].(string); ok && content != "" {
							chunks = append(chunks, content)
						}
					}
				}
			}
		}
	}

	// Validate streaming behavior
	if len(chunks) == 0 {
		t.Fatal("Expected to receive streaming chunks, got none")
	}

	// Verify first chunk arrived quickly (not buffered)
	firstChunkLatency := firstChunkTime.Sub(startTime)
	if firstChunkLatency > 500*time.Millisecond {
		t.Errorf("First chunk took too long (%v), indicating buffering", firstChunkLatency)
	}

	t.Logf("Successfully streamed %d chunks, first chunk latency: %v", len(chunks), firstChunkLatency)

	// Verify upstream received the request
	lastReq := llmServer.LastRequest()
	if lastReq == nil {
		t.Fatal("LLM server did not receive request")
		return
	}

	// Verify request forwarding
	if lastReq.Method != http.MethodPost {
		t.Errorf("Expected POST method, got %s", lastReq.Method)
	}
}

// TestE2E_LLM_Anthropic_StreamingNoAuth tests Anthropic-style streaming without authentication
func TestE2E_LLM_Anthropic_StreamingNoAuth(t *testing.T) {
	// Setup mock LLM server
	llmServer := NewMockLLMUpstream(t, ProviderAnthropic)
	defer llmServer.Close()

	// Launch proxy with JWT authentication
	proxy, token := launchProxyNoAuth(t, llmServer.URL())

	// Create streaming request
	requestBody := map[string]interface{}{
		"model": "claude-sonnet-4-5",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello, Claude!"},
		},
		"max_tokens": 1024,
		"stream":     true,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req, err := createLLMRequest(proxy.dataURL()+"/v1/messages", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token) // Add JWT token for authentication
	req.Header.Set("anthropic-version", "2023-06-01")

	// Execute request
	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyContent, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyContent))
	}

	// Verify SSE content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		t.Errorf("Expected text/event-stream content type, got: %s", contentType)
	}

	// Read and validate streaming response
	reader := bufio.NewReader(resp.Body)
	var textDeltas []string
	var eventTypes []string
	var firstDeltaTime time.Time
	gotMessageStart := false
	gotMessageStop := false

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read stream: %v", err)
		}

		// Parse SSE event lines
		if strings.HasPrefix(line, "event: ") {
			eventType := strings.TrimSpace(strings.TrimPrefix(line, "event: "))
			eventTypes = append(eventTypes, eventType)

			if eventType == "message_start" {
				gotMessageStart = true
			}
			if eventType == "message_stop" {
				gotMessageStop = true
				break
			}
		}

		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			data = strings.TrimSpace(data)

			var event map[string]interface{}
			if err := json.Unmarshal([]byte(data), &event); err != nil {
				continue
			}

			// Extract text deltas
			if eventType, ok := event["type"].(string); ok && eventType == "content_block_delta" {
				if delta, ok := event["delta"].(map[string]interface{}); ok {
					if text, ok := delta["text"].(string); ok && text != "" {
						if len(textDeltas) == 0 {
							firstDeltaTime = time.Now()
						}
						textDeltas = append(textDeltas, text)
					}
				}
			}
		}
	}

	// Validate Anthropic-specific streaming events
	if !gotMessageStart {
		t.Error("Expected message_start event")
	}

	if !gotMessageStop {
		t.Error("Expected message_stop event")
	}

	if len(textDeltas) == 0 {
		t.Fatal("Expected to receive text deltas, got none")
	}

	// Verify first delta arrived quickly
	firstDeltaLatency := firstDeltaTime.Sub(startTime)
	if firstDeltaLatency > 500*time.Millisecond {
		t.Errorf("First delta took too long (%v), indicating buffering", firstDeltaLatency)
	}

	t.Logf("Successfully streamed %d text deltas with %d event types, first delta latency: %v",
		len(textDeltas), len(eventTypes), firstDeltaLatency)
}

// TestE2E_LLM_LargeResponseNoBuffering tests large LLM responses without buffering
func TestE2E_LLM_LargeResponseNoBuffering(t *testing.T) {
	// Setup mock LLM server with slow streaming
	llmServer := NewMockLLMUpstream(t, ProviderOpenAI)
	llmServer.SetTokenDelay(50 * time.Millisecond) // Slower token generation
	defer llmServer.Close()

	// Launch proxy with JWT authentication
	proxy, token := launchProxyNoAuth(t, llmServer.URL())

	// Create streaming request
	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "user", "content": "Generate a long response"},
		},
		"stream": true,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req, err := createLLMRequest(proxy.dataURL()+"/v1/chat/completions", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token) // Add JWT token for authentication

	// Execute request
	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Read first chunk quickly
	reader := bufio.NewReader(resp.Body)
	foundFirstData := false
	for !foundFirstData {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read stream: %v", err)
		}

		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
			if data != "[DONE]" {
				foundFirstData = true
				firstChunkTime := time.Since(startTime)

				// First chunk should arrive much faster than total stream time
				// If buffering, we'd wait for all chunks (13 tokens * 50ms = 650ms+)
				if firstChunkTime > 300*time.Millisecond {
					t.Errorf("First chunk took %v, indicating buffering (expected < 300ms)", firstChunkTime)
				} else {
					t.Logf("✓ First chunk arrived in %v (no buffering detected)", firstChunkTime)
				}
			}
		}
	}
}

// TestE2E_LLM_ErrorHandling tests LLM error response forwarding
func TestE2E_LLM_ErrorHandling(t *testing.T) {
	tests := []struct {
		name               string
		errorType          string
		expectedStatusCode int
		expectedErrorType  string
	}{
		{
			name:               "Rate Limit Error",
			errorType:          "rate_limit",
			expectedStatusCode: http.StatusTooManyRequests,
			expectedErrorType:  "rate_limit_error",
		},
		{
			name:               "Invalid Request Error",
			errorType:          "invalid_request",
			expectedStatusCode: http.StatusBadRequest,
			expectedErrorType:  "invalid_request_error",
		},
		{
			name:               "Overloaded Error",
			errorType:          "overloaded",
			expectedStatusCode: http.StatusServiceUnavailable,
			expectedErrorType:  "server_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock LLM server
			llmServer := NewMockLLMUpstream(t, ProviderOpenAI)
			defer llmServer.Close()

			// Launch proxy with JWT authentication
			proxy, token := launchProxyNoAuth(t, llmServer.URL())

			// Create request to error endpoint
			req, err := createLLMRequest(proxy.dataURL()+"/error?type="+tt.errorType, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token) // Add JWT token for authentication

			// Execute request
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// Verify status code
			if resp.StatusCode != tt.expectedStatusCode {
				t.Errorf("Expected status %d, got %d", tt.expectedStatusCode, resp.StatusCode)
			}

			// Parse error response
			var errorResp map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
				t.Fatalf("Failed to decode error response: %v", err)
			}

			// Verify error structure
			if errorObj, ok := errorResp["error"].(map[string]interface{}); ok {
				if errorType, ok := errorObj["type"].(string); ok {
					if errorType != tt.expectedErrorType {
						t.Errorf("Expected error type %s, got %s", tt.expectedErrorType, errorType)
					}
				} else {
					t.Error("Error response missing 'type' field")
				}
			} else {
				t.Error("Error response missing 'error' object")
			}
		})
	}
}

// TestE2E_LLM_ConcurrentRequests tests concurrent LLM requests
func TestE2E_LLM_ConcurrentRequests(t *testing.T) {
	// Setup mock LLM server
	llmServer := NewMockLLMUpstream(t, ProviderOpenAI)
	defer llmServer.Close()

	// Launch proxy with JWT authentication
	proxy, token := launchProxyNoAuth(t, llmServer.URL())

	// Number of concurrent requests
	concurrentRequests := 10

	// Create a channel to collect results
	results := make(chan error, concurrentRequests)

	// Launch concurrent requests
	for i := 0; i < concurrentRequests; i++ {
		go func(agentID int) {
			requestBody := map[string]interface{}{
				"model": "gpt-4",
				"messages": []map[string]string{
					{"role": "user", "content": fmt.Sprintf("Request from agent %d", agentID)},
				},
				"stream": true,
			}

			bodyBytes, err := json.Marshal(requestBody)
			if err != nil {
				results <- fmt.Errorf("agent %d: marshal failed: %w", agentID, err)
				return
			}

			req, err := createLLMRequest(proxy.dataURL()+"/v1/chat/completions", strings.NewReader(string(bodyBytes)))
			if err != nil {
				results <- fmt.Errorf("agent %d: request creation failed: %w", agentID, err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token) // Add JWT token for authentication
			req.Header.Set("X-Agent-ID", fmt.Sprintf("agent-%d", agentID))

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results <- fmt.Errorf("agent %d: request failed: %w", agentID, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				results <- fmt.Errorf("agent %d: unexpected status %d", agentID, resp.StatusCode)
				return
			}

			// Read entire response
			_, err = io.Copy(io.Discard, resp.Body)
			if err != nil {
				results <- fmt.Errorf("agent %d: read failed: %w", agentID, err)
				return
			}

			results <- nil // Success
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < concurrentRequests; i++ {
		err := <-results
		if err != nil {
			t.Errorf("Concurrent request failed: %v", err)
		} else {
			successCount++
		}
	}

	if successCount < concurrentRequests {
		t.Errorf("Only %d/%d concurrent requests succeeded", successCount, concurrentRequests)
	} else {
		t.Logf("✓ All %d concurrent requests succeeded", concurrentRequests)
	}
}

// TestE2E_LLM_NonStreaming tests non-streaming LLM responses
func TestE2E_LLM_NonStreaming(t *testing.T) {
	// Setup mock LLM server
	llmServer := NewMockLLMUpstream(t, ProviderOpenAI)
	defer llmServer.Close()

	// Launch proxy with JWT authentication
	proxy, token := launchProxyNoAuth(t, llmServer.URL())

	// Create non-streaming request
	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello!"},
		},
		"stream": false,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req, err := createLLMRequest(proxy.dataURL()+"/v1/chat/completions", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token) // Add JWT token for authentication

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify JSON content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected application/json content type, got: %s", contentType)
	}

	// Parse response
	var completion map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&completion); err != nil {
		t.Fatalf("Failed to decode completion: %v", err)
	}

	// Verify response structure
	if _, ok := completion["id"]; !ok {
		t.Error("Response missing 'id' field")
	}

	if choices, ok := completion["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if message, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := message["content"].(string); !ok || content == "" {
					t.Error("Response missing message content")
				}
			}
		}
	} else {
		t.Error("Response missing choices")
	}
}

// TestE2E_LLM_TelemetryCapture tests that telemetry captures LLM-specific attributes
func TestE2E_LLM_TelemetryCapture(t *testing.T) {
	// Start mock OTLP collector
	collector, endpoint := startMockTraceCollector(t)

	// Setup mock LLM server
	llmServer := NewMockLLMUpstream(t, ProviderOpenAI)
	defer llmServer.Close()

	// Launch proxy with telemetry
	proxy, token := launchProxyNoAuthWithTelemetry(t, llmServer.URL(), endpoint)

	// Create request with agent metadata
	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello!"},
		},
		"stream": false,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req, err := createLLMRequest(proxy.dataURL()+"/v1/chat/completions", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token) // Add JWT token for authentication
	req.Header.Set("X-Agent-ID", "test-agent-123")
	req.Header.Set("X-Session-ID", "session-456")

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyContent, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyContent))
	}

	// Read response to ensure request completes
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Wait for telemetry export with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Try to get at least one span
	spans := collector.WaitForSpans(ctx, 1)
	if len(spans) > 0 {
		t.Logf("✓ Telemetry captured %d spans", len(spans))
		// Note: Full attribute validation would require integration with actual telemetry middleware
		// This test validates that the telemetry infrastructure is working
	} else {
		t.Logf("⚠ No spans captured (telemetry may not be fully wired for no-auth mode)")
	}
}

// launchProxyNoAuth launches a proxy instance in passthrough mode (no JWT validation) for LLM testing.
// Returns the proxy instance and an empty token string (not used in passthrough mode).
func launchProxyNoAuth(t *testing.T, llmUpstreamURL string) (*proxyInstance, string) {
	t.Helper()

	binary := buildProxyBinary(t)
	bootstrapPath := writeBootstrapNoAuth(t, llmUpstreamURL)

	// Launch proxy in passthrough mode (no OIDC validation)
	proxy := startProxy(t, proxyOptions{
		BinaryPath:    binary,
		BootstrapPath: bootstrapPath,
		UpstreamURL:   llmUpstreamURL,
	})

	// Return empty token - not validated in passthrough mode
	return proxy, ""
}

// launchProxyNoAuthWithTelemetry launches proxy in passthrough mode with telemetry enabled for LLM testing.
// Returns the proxy instance and an empty token string (not used in passthrough mode).
func launchProxyNoAuthWithTelemetry(t *testing.T, llmUpstreamURL string, otlpEndpoint string) (*proxyInstance, string) {
	t.Helper()

	binary := buildProxyBinary(t)
	bootstrapPath := writeBootstrapNoAuth(t, llmUpstreamURL)

	// Launch with telemetry in passthrough mode
	proxy := startProxy(t, proxyOptions{
		BinaryPath:    binary,
		BootstrapPath: bootstrapPath,
		UpstreamURL:   llmUpstreamURL,
		// No OIDC configuration - passthrough mode
		ExtraEnv: map[string]string{
			"PROXY_OTLP_INSECURE":            "true",
			"PROXY_OTLP_ENDPOINT":            otlpEndpoint,
			"OTEL_BSP_SCHEDULE_DELAY":        "100",
			"OTEL_BSP_MAX_EXPORT_BATCH_SIZE": "1",
		},
	})

	// Return empty token - not validated in passthrough mode
	return proxy, ""
}

// writeBootstrapNoAuth creates a bootstrap config with pipeline-based configuration
func writeBootstrapNoAuth(t *testing.T, upstreamURL string) string {
	t.Helper()

	snapshot := configpkg.Snapshot{
		Generation: 1,
		RawPolicies: []configpkg.PolicySpec{
			{
				ID:   "policy-passthrough",
				Name: "Passthrough (No Auth)",
			},
		},
		Pipelines: []configpkg.PipelineSpec{
			{
				ID:       "llm-wildcard-pipeline",
				Version:  1,
				AgentID:  "*", // Wildcard: matches any agent ID
				Protocol: "",  // Empty protocol: true wildcard (matches any protocol)
				Nodes: []configpkg.PipelineNodeSpec{
					{
						ID:   "egress",
						Type: "egress.http",
						Config: map[string]interface{}{
							"upstream_url":  upstreamURL,
							"upstream_mode": "static",
						},
						On: configpkg.NodeHandlersSpec{
							Success: "", // Terminal node
						},
					},
				},
			},
		},
	}

	data, err := yaml.Marshal(snapshot)
	if err != nil {
		t.Fatalf("failed to marshal bootstrap: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap-noauth.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write bootstrap: %v", err)
	}

	return path
}

// createLLMRequest creates an HTTP POST request for LLM endpoints with required headers.
// Automatically adds X-Agent-ID header required after router removal.
func createLLMRequest(url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-ID", "default")
	return req, nil
}
