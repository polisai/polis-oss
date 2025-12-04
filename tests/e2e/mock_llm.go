package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// LLMProvider represents different LLM API styles
type LLMProvider string

// Supported LLM provider types for testing
const (
	ProviderOpenAI    LLMProvider = "openai"
	ProviderAnthropic LLMProvider = "anthropic"
)

// MockLLMUpstream simulates an LLM API server with streaming responses
type MockLLMUpstream struct {
	t          *testing.T
	server     *httptest.Server
	provider   LLMProvider
	mu         sync.RWMutex
	lastReq    *http.Request
	lastBody   map[string]interface{}
	tokenDelay time.Duration
}

// NewMockLLMUpstream creates a new mock LLM server
func NewMockLLMUpstream(t *testing.T, provider LLMProvider) *MockLLMUpstream {
	t.Helper()

	mock := &MockLLMUpstream{
		t:          t,
		provider:   provider,
		tokenDelay: 10 * time.Millisecond, // Simulate realistic token generation delay
	}

	mock.server = httptest.NewServer(http.HandlerFunc(mock.handleRequest))
	return mock
}

// SetTokenDelay configures the delay between streaming tokens
func (m *MockLLMUpstream) SetTokenDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokenDelay = delay
}

// URL returns the server URL
func (m *MockLLMUpstream) URL() string {
	return m.server.URL
}

// Close shuts down the server
func (m *MockLLMUpstream) Close() {
	m.server.Close()
}

// LastRequest returns the last received request
func (m *MockLLMUpstream) LastRequest() *http.Request {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastReq
}

// LastBody returns the last received request body
func (m *MockLLMUpstream) LastBody() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastBody
}

// handleRequest routes requests based on path
func (m *MockLLMUpstream) handleRequest(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.lastReq = r.Clone(r.Context())
	m.mu.Unlock()

	// Parse request body
	var body map[string]interface{}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			if err != io.EOF {
				m.t.Logf("Failed to decode request body: %v", err)
			}
		} else {
			m.mu.Lock()
			m.lastBody = body
			m.mu.Unlock()
		}
	}

	// Route based on path
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/chat/completions"):
		m.handleChatCompletions(w, r, body)
	case strings.HasPrefix(r.URL.Path, "/v1/messages"):
		m.handleMessages(w, r, body)
	case strings.HasPrefix(r.URL.Path, "/error"):
		m.handleError(w, r, body)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

// handleChatCompletions handles OpenAI-style chat completions
func (m *MockLLMUpstream) handleChatCompletions(w http.ResponseWriter, r *http.Request, body map[string]interface{}) {
	isStream := false
	if stream, ok := body["stream"].(bool); ok {
		isStream = stream
	}

	if isStream {
		m.streamOpenAIResponse(w, r, body)
	} else {
		m.nonStreamOpenAIResponse(w, r, body)
	}
}

// streamOpenAIResponse sends an OpenAI-style SSE streaming response
//
//nolint:revive,unparam // body parameter kept for consistency with other handlers
func (m *MockLLMUpstream) streamOpenAIResponse(w http.ResponseWriter, _ *http.Request, body map[string]interface{}) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Get tokens to stream
	tokens := []string{"Hello", " from", " the", " AI", " assistant", "!", " How", " can", " I", " help", " you", " today", "?"}

	// Get token delay
	m.mu.RLock()
	delay := m.tokenDelay
	m.mu.RUnlock()

	// Stream tokens
	for i, token := range tokens {
		chunk := map[string]interface{}{
			"id":      "chatcmpl-123",
			"object":  "chat.completion.chunk",
			"created": time.Now().Unix(),
			"model":   "gpt-4",
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"delta": map[string]interface{}{
						"content": token,
					},
					"finish_reason": nil,
				},
			},
		}

		// Last chunk has finish_reason
		if i == len(tokens)-1 {
			chunk["choices"].([]map[string]interface{})[0]["finish_reason"] = "stop"
		}

		data, _ := json.Marshal(chunk)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()

		if i < len(tokens)-1 {
			time.Sleep(delay)
		}
	}

	// Send done message
	_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// nonStreamOpenAIResponse sends a non-streaming OpenAI response
//
//nolint:revive,unparam // body parameter kept for consistency with other handlers
func (m *MockLLMUpstream) nonStreamOpenAIResponse(w http.ResponseWriter, _ *http.Request, body map[string]interface{}) {
	response := map[string]interface{}{
		"id":      "chatcmpl-123",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "gpt-4",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": "Hello from the AI assistant! How can I help you today?",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]interface{}{
			"prompt_tokens":     10,
			"completion_tokens": 12,
			"total_tokens":      22,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleMessages handles Anthropic-style messages
func (m *MockLLMUpstream) handleMessages(w http.ResponseWriter, r *http.Request, body map[string]interface{}) {
	isStream := false
	if stream, ok := body["stream"].(bool); ok {
		isStream = stream
	}

	if isStream {
		m.streamAnthropicResponse(w, r, body)
	} else {
		m.nonStreamAnthropicResponse(w, r, body)
	}
}

// streamAnthropicResponse sends an Anthropic-style SSE streaming response
//
//nolint:revive,unparam // body parameter kept for consistency with other handlers
func (m *MockLLMUpstream) streamAnthropicResponse(w http.ResponseWriter, _ *http.Request, body map[string]interface{}) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Get token delay
	m.mu.RLock()
	delay := m.tokenDelay
	m.mu.RUnlock()

	// Send message_start event
	messageStart := map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id":            "msg_01abc",
			"type":          "message",
			"role":          "assistant",
			"content":       []interface{}{},
			"model":         "claude-sonnet-4-5",
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]interface{}{
				"input_tokens":  10,
				"output_tokens": 1,
			},
		},
	}
	data, _ := json.Marshal(messageStart)
	_, _ = fmt.Fprintf(w, "event: message_start\ndata: %s\n\n", data)
	flusher.Flush()

	// Send content_block_start event
	blockStart := map[string]interface{}{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]interface{}{
			"type": "text",
			"text": "",
		},
	}
	data, _ = json.Marshal(blockStart)
	_, _ = fmt.Fprintf(w, "event: content_block_start\ndata: %s\n\n", data)
	flusher.Flush()

	// Send ping event
	ping := map[string]interface{}{
		"type": "ping",
	}
	data, _ = json.Marshal(ping)
	_, _ = fmt.Fprintf(w, "event: ping\ndata: %s\n\n", data)
	flusher.Flush()

	// Stream text deltas
	tokens := []string{"Hello", "!", " How", " can", " I", " assist", " you", " today", "?"}
	for _, token := range tokens {
		delta := map[string]interface{}{
			"type":  "content_block_delta",
			"index": 0,
			"delta": map[string]interface{}{
				"type": "text_delta",
				"text": token,
			},
		}
		data, _ = json.Marshal(delta)
		_, _ = fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", data)
		flusher.Flush()
		time.Sleep(delay)
	}

	// Send content_block_stop event
	blockStop := map[string]interface{}{
		"type":  "content_block_stop",
		"index": 0,
	}
	data, _ = json.Marshal(blockStop)
	_, _ = fmt.Fprintf(w, "event: content_block_stop\ndata: %s\n\n", data)
	flusher.Flush()

	// Send message_delta event
	messageDelta := map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
		},
		"usage": map[string]interface{}{
			"output_tokens": 15,
		},
	}
	data, _ = json.Marshal(messageDelta)
	_, _ = fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", data)
	flusher.Flush()

	// Send message_stop event
	messageStop := map[string]interface{}{
		"type": "message_stop",
	}
	data, _ = json.Marshal(messageStop)
	_, _ = fmt.Fprintf(w, "event: message_stop\ndata: %s\n\n", data)
	flusher.Flush()
}

// nonStreamAnthropicResponse sends a non-streaming Anthropic response
//
//nolint:revive,unparam // body parameter kept for consistency with other handlers
func (m *MockLLMUpstream) nonStreamAnthropicResponse(w http.ResponseWriter, _ *http.Request, body map[string]interface{}) {
	response := map[string]interface{}{
		"id":   "msg_01abc",
		"type": "message",
		"role": "assistant",
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": "Hello! How can I assist you today?",
			},
		},
		"model":         "claude-sonnet-4-5",
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage": map[string]interface{}{
			"input_tokens":  10,
			"output_tokens": 15,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleError simulates various error conditions
func (m *MockLLMUpstream) handleError(w http.ResponseWriter, r *http.Request, _ map[string]interface{}) {
	errorType := r.URL.Query().Get("type")

	switch errorType {
	case "rate_limit":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": "Rate limit exceeded",
				"type":    "rate_limit_error",
				"code":    "rate_limit_exceeded",
			},
		})
	case "invalid_request":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": "Invalid request parameters",
				"type":    "invalid_request_error",
			},
		})
	case "overloaded":
		if m.provider == ProviderAnthropic {
			// Anthropic-style overload error in streaming
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher := w.(http.Flusher)

			errorEvent := map[string]interface{}{
				"type": "error",
				"error": map[string]interface{}{
					"type":    "overloaded_error",
					"message": "Overloaded",
				},
			}
			data, _ := json.Marshal(errorEvent)
			_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
			flusher.Flush()
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message": "The server is currently overloaded",
					"type":    "server_error",
					"code":    "overloaded",
				},
			})
		}
	default:
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// NewMockLLMUpstreamFromServer wraps an httptest.Server for compatibility
func NewMockLLMUpstreamFromServer(t *testing.T, server *httptest.Server) *MockLLMUpstream {
	return &MockLLMUpstream{
		t:      t,
		server: server,
	}
}
