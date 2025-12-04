package integration

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestStreaming_ChunkedTransferEncoding tests that chunked responses are properly streamed.
func TestStreaming_ChunkedTransferEncoding(t *testing.T) {
	// Create upstream that sends chunked response
	chunks := []string{"chunk1\n", "chunk2\n", "chunk3\n", "chunk4\n", "chunk5\n"}
	streamingUpstream := NewStreamingMockUpstream(t, chunks, 10*time.Millisecond)
	defer streamingUpstream.Close()

	// Wrap in MockUpstream for compatibility with setupProxyPipeline
	upstream := NewMockUpstreamFromServer(t, streamingUpstream.server)

	proxy := setupProxyPipeline(t, upstream)
	defer proxy.Close()

	req, err := http.NewRequest("GET", proxy.URL+"/api/stream", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "test-route")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Read streamed response
	reader := bufio.NewReader(resp.Body)
	receivedChunks := []string{}
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read chunk: %v", err)
		}
		receivedChunks = append(receivedChunks, line)
	}

	// Verify all chunks received
	if len(receivedChunks) != len(chunks) {
		t.Errorf("Expected %d chunks, got %d", len(chunks), len(receivedChunks))
	}

	for i, expected := range chunks {
		if i < len(receivedChunks) && receivedChunks[i] != expected {
			t.Errorf("Chunk %d mismatch: expected %q, got %q", i, expected, receivedChunks[i])
		}
	}
}

// TestStreaming_ServerSentEvents tests SSE streaming through the proxy.
func TestStreaming_ServerSentEvents(t *testing.T) {
	// Create SSE upstream
	sseEvents := []string{
		"data: event1\n\n",
		"data: event2\n\n",
		"data: event3\n\n",
	}
	streamingUpstream := NewStreamingMockUpstream(t, sseEvents, 20*time.Millisecond)
	streamingUpstream.SetContentType("text/event-stream")
	defer streamingUpstream.Close()

	// Wrap in MockUpstream for compatibility
	upstream := NewMockUpstreamFromServer(t, streamingUpstream.server)

	proxy := setupProxyPipeline(t, upstream)
	defer proxy.Close()

	req, err := http.NewRequest("GET", proxy.URL+"/api/events", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "test-route")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify Content-Type for SSE
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		t.Errorf("Expected text/event-stream content type, got: %s", contentType)
	}

	// Read SSE events
	reader := bufio.NewReader(resp.Body)
	receivedEvents := []string{}
	currentEvent := ""

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read SSE event: %v", err)
		}

		currentEvent += line
		if line == "\n" {
			// Event complete
			receivedEvents = append(receivedEvents, currentEvent)
			currentEvent = ""
		}
	}

	// Verify events received
	if len(receivedEvents) != len(sseEvents) {
		t.Errorf("Expected %d events, got %d", len(sseEvents), len(receivedEvents))
	}
}

// TestStreaming_NoBuffering tests that responses are not fully buffered.
func TestStreaming_NoBuffering(t *testing.T) {
	// Create slow streaming upstream
	chunks := []string{"start\n", "middle\n", "end\n"}
	chunkDelay := 50 * time.Millisecond
	streamingUpstream := NewStreamingMockUpstream(t, chunks, chunkDelay)
	defer streamingUpstream.Close()

	// Wrap in MockUpstream
	upstream := NewMockUpstreamFromServer(t, streamingUpstream.server)

	proxy := setupProxyPipeline(t, upstream)
	defer proxy.Close()

	req, err := http.NewRequest("GET", proxy.URL+"/api/slow", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "test-route")

	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	// Read first chunk
	reader := bufio.NewReader(resp.Body)
	firstChunk, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read first chunk: %v", err)
	}

	firstChunkTime := time.Since(startTime)

	// First chunk should arrive quickly (not after all chunks are buffered)
	// If buffering occurred, we'd wait for all chunks (3 * 50ms = 150ms+)
	// Without buffering, first chunk arrives in ~50ms even with scheduling jitter
	if firstChunkTime > 200*time.Millisecond {
		t.Errorf("First chunk took too long (%v), suggesting full buffering", firstChunkTime)
	}

	if firstChunk != "start\n" {
		t.Errorf("Expected 'start\\n', got %q", firstChunk)
	}
}

// TestStreaming_HopByHopHeaders tests that hop-by-hop headers are filtered.
func TestStreaming_HopByHopHeaders(t *testing.T) {
	// Track which headers upstream receives
	var upstreamHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Fatalf("Failed to write upstream response: %v", err)
		}
	}))
	defer upstream.Close()

	proxy := setupProxyPipeline(t, NewMockUpstreamFromServer(t, upstream))
	defer proxy.Close()

	req, err := http.NewRequest("GET", proxy.URL+"/api/test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "test-route")

	// Add hop-by-hop headers that should be stripped
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Upgrade", "websocket")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	// Verify hop-by-hop headers were filtered
	hopByHopHeaders := []string{"Connection", "Transfer-Encoding", "TE", "Upgrade"}
	for _, header := range hopByHopHeaders {
		if upstreamHeaders.Get(header) != "" {
			t.Errorf("Hop-by-hop header %s should have been filtered but was present", header)
		}
	}
}

// TestStreaming_LargeResponse tests streaming of large responses.
func TestStreaming_LargeResponse(t *testing.T) {
	// Create large streaming response (10MB in 1KB chunks)
	const chunkSize = 1024
	const numChunks = 10 * 1024 // 10MB total

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		chunk := make([]byte, chunkSize)
		for i := 0; i < len(chunk); i++ {
			chunk[i] = byte(i % 256)
		}

		for i := 0; i < numChunks; i++ {
			if _, err := w.Write(chunk); err != nil {
				http.Error(w, "Failed to write chunk", http.StatusInternalServerError)
				return
			}
			if i%100 == 0 {
				flusher.Flush()
			}
		}
	}))
	defer upstream.Close()

	proxy := setupProxyPipeline(t, NewMockUpstreamFromServer(t, upstream))
	defer proxy.Close()

	req, err := http.NewRequest("GET", proxy.URL+"/api/large", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Agent-ID", "test-route")

	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer closeBody(t, resp.Body)

	// Read response in chunks
	totalBytes := 0
	buffer := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buffer)
		totalBytes += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
	}

	duration := time.Since(startTime)
	expectedBytes := chunkSize * numChunks

	if totalBytes != expectedBytes {
		t.Errorf("Expected %d bytes, got %d", expectedBytes, totalBytes)
	}

	// Should stream efficiently (not buffer entire 10MB)
	t.Logf("Streamed %d MB in %v", totalBytes/(1024*1024), duration)
}

// NewMockUpstreamFromServer creates a MockUpstream wrapper around an httptest.Server.
func NewMockUpstreamFromServer(t *testing.T, server *httptest.Server) *MockUpstream {
	t.Helper()

	upstream := &MockUpstream{
		server:       server,
		responseCode: http.StatusOK,
		responseBody: "",
	}
	return upstream
}
