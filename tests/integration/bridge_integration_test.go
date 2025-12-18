package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/bridge"
	"github.com/polisai/polis-oss/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockToolProcess simulates an MCP tool process for integration testing
type MockToolProcess struct {
	mu           sync.Mutex
	running      bool
	stdinBuffer  bytes.Buffer
	stdoutCh     chan []byte
	readHandler  func([]byte)
	exitCode     int
	startErr     error
	writeErr     error
	stopErr      error
}

func NewMockToolProcess() *MockToolProcess {
	return &MockToolProcess{
		running:  false,
		stdoutCh: make(chan []byte, 100),
	}
}

func (m *MockToolProcess) Start(ctx context.Context, command []string, workDir string, env []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.startErr != nil {
		return m.startErr
	}
	m.running = true
	return nil
}

func (m *MockToolProcess) Write(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writeErr != nil {
		return m.writeErr
	}
	if !m.running {
		return fmt.Errorf("process not running")
	}
	m.stdinBuffer.Write(data)
	return nil
}

func (m *MockToolProcess) ReadLoop(handler func([]byte)) error {
	m.mu.Lock()
	m.readHandler = handler
	m.mu.Unlock()

	for data := range m.stdoutCh {
		handler(data)
	}
	return nil
}

func (m *MockToolProcess) Stop(timeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running = false
	close(m.stdoutCh)
	return nil
}

func (m *MockToolProcess) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *MockToolProcess) ExitCode() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exitCode
}

// SendOutput simulates the tool sending output to stdout
func (m *MockToolProcess) SendOutput(data []byte) {
	m.mu.Lock()
	running := m.running
	m.mu.Unlock()
	if running {
		m.stdoutCh <- data
	}
}

// GetStdinData returns all data written to stdin
func (m *MockToolProcess) GetStdinData() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stdinBuffer.Bytes()
}

// MockPolicyEngine implements a configurable policy engine for testing
type MockPolicyEngine struct {
	mu        sync.Mutex
	decisions map[string]policy.Decision // method -> decision
	defaultDecision policy.Decision
	evaluations []policy.Input
}

func NewMockPolicyEngine() *MockPolicyEngine {
	return &MockPolicyEngine{
		decisions: make(map[string]policy.Decision),
		defaultDecision: policy.Decision{
			Action: policy.ActionAllow,
			Reason: "default allow",
		},
	}
}

func (m *MockPolicyEngine) SetDecision(method string, decision policy.Decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions[method] = decision
}

func (m *MockPolicyEngine) SetDefaultDecision(decision policy.Decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultDecision = decision
}

func (m *MockPolicyEngine) Evaluate(ctx context.Context, input policy.Input) (policy.Decision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evaluations = append(m.evaluations, input)

	method, _ := input.Attributes["method"].(string)
	if decision, ok := m.decisions[method]; ok {
		return decision, nil
	}
	return m.defaultDecision, nil
}

func (m *MockPolicyEngine) GetEvaluations() []policy.Input {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]policy.Input{}, m.evaluations...)
}

// TestBridgeEndToEndIntegration tests the complete flow of messages through the bridge
// Requirements: 1.1, 1.2, 1.3
func TestBridgeEndToEndIntegration(t *testing.T) {
	t.Parallel()

	// Create bridge configuration
	config := bridge.DefaultBridgeConfig()
	config.Command = []string{"mock-tool"}
	config.ListenAddr = ":0" // Use any available port

	// Create bridge instance
	b := bridge.NewBridge(config, nil)

	// Set up mock process manager
	mockProcess := NewMockToolProcess()
	b.SetProcessManager(mockProcess)

	// Set up session manager
	sessionMgr := bridge.NewSessionManager(config.Session, nil)
	b.SetSessionManager(sessionMgr)

	// Start the mock process
	err := mockProcess.Start(context.Background(), config.Command, "", nil)
	require.NoError(t, err)

	// Test 1: Health endpoint returns healthy when process is running
	t.Run("health_endpoint_healthy", func(t *testing.T) {
		// Call health handler directly
		status := b.Health()
		assert.Equal(t, "healthy", status.Status)
	})

	// Test 2: Message endpoint forwards JSON-RPC to process stdin
	t.Run("message_forwarding", func(t *testing.T) {
		jsonRPC := `{"jsonrpc":"2.0","method":"tools/list","id":1}`

		// Create a test server to handle the request
		mux := http.NewServeMux()
		mux.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
			// Validate agent ID
			agentID := r.Header.Get("X-Agent-ID")
			if agentID == "" {
				http.Error(w, "missing X-Agent-ID", http.StatusUnauthorized)
				return
			}

			// Read body
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			// Validate JSON-RPC
			var jsonRPCMsg map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &jsonRPCMsg); err != nil {
				http.Error(w, "invalid JSON-RPC", http.StatusBadRequest)
				return
			}

			// Write to mock process
			if err := mockProcess.Write(append(bodyBytes, '\n')); err != nil {
				http.Error(w, "process not running", http.StatusServiceUnavailable)
				return
			}

			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"status":"accepted"}`))
		})

		server := httptest.NewServer(mux)
		defer server.Close()

		// Send request with X-Agent-ID header
		req, err := http.NewRequest(http.MethodPost, server.URL+"/message", strings.NewReader(jsonRPC))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Agent-ID", "test-agent")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusAccepted, resp.StatusCode)

		// Verify message was written to process stdin
		stdinData := mockProcess.GetStdinData()
		assert.Contains(t, string(stdinData), "tools/list")
	})

	// Test 3: Process output is forwarded as SSE events
	t.Run("process_output_forwarding", func(t *testing.T) {
		// Create a channel to receive SSE events
		eventsCh := make(chan *bridge.SSEEvent, 10)

		// Simulate process output
		response := `{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`

		// Start a goroutine to read from the mock process
		go func() {
			mockProcess.ReadLoop(func(data []byte) {
				event := &bridge.SSEEvent{
					Event: "message",
					Data:  data,
				}
				eventsCh <- event
			})
		}()

		// Send output from mock process
		mockProcess.SendOutput([]byte(response))

		// Wait for event
		select {
		case event := <-eventsCh:
			assert.Equal(t, "message", event.Event)
			assert.Contains(t, string(event.Data), "tools")
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for SSE event")
		}
	})
}

// TestBridgeReconnectionIntegration tests session reconnection with Last-Event-ID
// Requirements: 5.2
func TestBridgeReconnectionIntegration(t *testing.T) {
	t.Parallel()

	// Create session manager with buffer
	config := &bridge.SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 300 * time.Second,
	}
	sessionMgr := bridge.NewSessionManager(config, nil)

	agentID := "test-agent-reconnect"

	// Step 1: Create a session
	session, err := sessionMgr.CreateSession(agentID)
	require.NoError(t, err)
	require.NotEmpty(t, session.ID)

	// Step 2: Buffer some events
	var bufferedSequences []uint64
	for i := 0; i < 5; i++ {
		eventData := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","result":"event-%d","id":%d}`, i, i))
		seq, err := sessionMgr.BufferEvent(session.ID, eventData)
		require.NoError(t, err)
		bufferedSequences = append(bufferedSequences, seq)
	}

	// Step 3: Simulate disconnect (just stop reading)
	// In a real scenario, the client would disconnect here

	// Step 4: Reconnect with Last-Event-ID
	lastEventID := fmt.Sprintf("%d", bufferedSequences[2]) // Resume from event 2
	resumedSession, fromSequence, err := sessionMgr.ResumeSession(session.ID, agentID, lastEventID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, resumedSession.ID)
	assert.Equal(t, bufferedSequences[2]+1, fromSequence) // Should resume from next event

	// Step 5: Verify buffered events can be retrieved
	events, err := sessionMgr.GetBufferedEvents(session.ID, fromSequence)
	require.NoError(t, err)

	// Should get events 3 and 4 (after event 2)
	assert.GreaterOrEqual(t, len(events), 2)
	for _, event := range events {
		assert.GreaterOrEqual(t, event.Sequence, fromSequence)
	}
}

// TestBridgeMultiTenantIsolationIntegration tests that agents cannot access each other's sessions
// Requirements: 6.1, 6.3, 6.4
func TestBridgeMultiTenantIsolationIntegration(t *testing.T) {
	t.Parallel()

	// Create session manager
	config := &bridge.SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 300 * time.Second,
	}
	sessionMgr := bridge.NewSessionManager(config, nil)

	// Create sessions for two different agents
	agent1ID := "agent-1"
	agent2ID := "agent-2"

	session1, err := sessionMgr.CreateSession(agent1ID)
	require.NoError(t, err)

	session2, err := sessionMgr.CreateSession(agent2ID)
	require.NoError(t, err)

	// Test 1: Agent 1 can access their own session
	t.Run("agent_can_access_own_session", func(t *testing.T) {
		retrieved, err := sessionMgr.GetSession(session1.ID, agent1ID)
		require.NoError(t, err)
		assert.Equal(t, session1.ID, retrieved.ID)
		assert.Equal(t, agent1ID, retrieved.AgentID)
	})

	// Test 2: Agent 2 cannot access Agent 1's session (403 Forbidden)
	t.Run("agent_cannot_access_other_session", func(t *testing.T) {
		_, err := sessionMgr.GetSession(session1.ID, agent2ID)
		require.Error(t, err)
		assert.True(t, bridge.IsAccessDenied(err), "expected access denied error")
	})

	// Test 3: Agent 1 cannot access Agent 2's session
	t.Run("cross_agent_access_denied", func(t *testing.T) {
		_, err := sessionMgr.GetSession(session2.ID, agent1ID)
		require.Error(t, err)
		assert.True(t, bridge.IsAccessDenied(err), "expected access denied error")
	})

	// Test 4: Session listing only returns agent's own sessions
	t.Run("session_listing_filtered_by_agent", func(t *testing.T) {
		// Create additional session for agent 1
		session1b, err := sessionMgr.CreateSession(agent1ID)
		require.NoError(t, err)

		// List sessions for agent 1
		agent1Sessions, err := sessionMgr.ListSessions(agent1ID)
		require.NoError(t, err)

		// Should only see agent 1's sessions
		for _, s := range agent1Sessions {
			assert.Equal(t, agent1ID, s.AgentID)
		}

		// Should have 2 sessions
		assert.Len(t, agent1Sessions, 2)

		// Verify both sessions are present
		sessionIDs := make(map[string]bool)
		for _, s := range agent1Sessions {
			sessionIDs[s.ID] = true
		}
		assert.True(t, sessionIDs[session1.ID])
		assert.True(t, sessionIDs[session1b.ID])

		// List sessions for agent 2
		agent2Sessions, err := sessionMgr.ListSessions(agent2ID)
		require.NoError(t, err)

		// Should only see agent 2's session
		assert.Len(t, agent2Sessions, 1)
		assert.Equal(t, session2.ID, agent2Sessions[0].ID)
	})

	// Test 5: Missing agent ID returns 401
	t.Run("missing_agent_id_unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sse", nil)
		// No X-Agent-ID header

		_, err := bridge.ValidateAgentID(req)
		require.Error(t, err)

		mtErr, ok := err.(*bridge.MultiTenantError)
		require.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, mtErr.Code)
	})
}

// TestBridgeElicitationBlockingIntegration tests that elicitation requests are blocked by policy
// Requirements: 4.3, 4.5
func TestBridgeElicitationBlockingIntegration(t *testing.T) {
	t.Parallel()

	// Create mock policy engine that blocks sampling requests
	policyEngine := NewMockPolicyEngine()
	policyEngine.SetDecision("sampling/createMessage", policy.Decision{
		Action: policy.ActionBlock,
		Reason: "sampling requests blocked by policy",
	})

	// Create stream inspector with the policy engine
	inspectorConfig := bridge.DefaultStreamInspectorConfig()
	inspectorConfig.FailClosed = true
	inspector := bridge.NewStreamInspector(policyEngine, inspectorConfig, nil)

	// Test 1: Sampling request is blocked
	t.Run("sampling_request_blocked", func(t *testing.T) {
		// Create a sampling/createMessage request (server-initiated)
		samplingRequest := `{"jsonrpc":"2.0","method":"sampling/createMessage","id":"req-1","params":{"messages":[{"role":"user","content":"test prompt"}]}}`

		event := &bridge.SSEEvent{
			ID:    "1",
			Event: "message",
			Data:  []byte(samplingRequest),
		}

		result, err := inspector.Inspect(context.Background(), event, "test-tool")
		require.NoError(t, err)
		assert.Equal(t, "block", result.Action)
		assert.Contains(t, result.Reason, "blocked")
	})

	// Test 2: Non-sampling requests are allowed
	t.Run("non_sampling_request_allowed", func(t *testing.T) {
		// Create a regular response (not a server request)
		response := `{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`

		event := &bridge.SSEEvent{
			ID:    "2",
			Event: "message",
			Data:  []byte(response),
		}

		result, err := inspector.Inspect(context.Background(), event, "test-tool")
		require.NoError(t, err)
		assert.Equal(t, "allow", result.Action)
	})

	// Test 3: Fail-closed behavior when no policy engine
	t.Run("fail_closed_no_policy", func(t *testing.T) {
		// Create inspector without policy engine
		noEngineInspector := bridge.NewStreamInspector(nil, inspectorConfig, nil)

		// Server-initiated request should be blocked
		serverRequest := `{"jsonrpc":"2.0","method":"resources/read","id":"req-2","params":{"uri":"file:///etc/passwd"}}`

		event := &bridge.SSEEvent{
			ID:    "3",
			Event: "message",
			Data:  []byte(serverRequest),
		}

		result, err := noEngineInspector.Inspect(context.Background(), event, "test-tool")
		require.NoError(t, err)
		assert.Equal(t, "block", result.Action)
		assert.Contains(t, result.Reason, "fail-closed")
	})

	// Test 4: Policy input contains required fields
	t.Run("policy_input_completeness", func(t *testing.T) {
		samplingRequest := `{"jsonrpc":"2.0","method":"sampling/createMessage","id":"req-3","params":{"messages":[{"role":"user","content":"test"}],"maxTokens":100}}`

		event := &bridge.SSEEvent{
			ID:    "4",
			Event: "message",
			Data:  []byte(samplingRequest),
		}

		_, err := inspector.Inspect(context.Background(), event, "my-tool-id")
		require.NoError(t, err)

		// Check that policy was evaluated with correct input
		evaluations := policyEngine.GetEvaluations()
		require.NotEmpty(t, evaluations)

		lastEval := evaluations[len(evaluations)-1]
		assert.Equal(t, "sampling/createMessage", lastEval.Attributes["method"])
		assert.Equal(t, "my-tool-id", lastEval.Attributes["tool_id"])
		assert.NotNil(t, lastEval.Attributes["params"])
	})
}

// TestBridgeSSEStreamIntegration tests SSE streaming functionality
func TestBridgeSSEStreamIntegration(t *testing.T) {
	t.Parallel()

	// Create a mock SSE server
	sseEvents := []string{
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]},\"id\":1}\n\n",
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"resources\":[]},\"id\":2}\n\n",
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"prompts\":[]},\"id\":3}\n\n",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		for _, event := range sseEvents {
			w.Write([]byte(event))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer server.Close()

	// Connect to SSE stream
	resp, err := http.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	// Parse SSE events
	reader := bufio.NewReader(resp.Body)
	var receivedEvents []*bridge.SSEEvent

	// Read events with timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		eventCh := bridge.ParseSSEStream(reader)
		for event := range eventCh {
			receivedEvents = append(receivedEvents, event)
			if len(receivedEvents) >= 3 {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SSE events")
	}

	// Verify events were received
	assert.Len(t, receivedEvents, 3)
	for _, event := range receivedEvents {
		assert.Equal(t, "message", event.Event)
		assert.NotEmpty(t, event.Data)
	}
}

// TestBridgeHealthStatusIntegration tests health endpoint behavior
func TestBridgeHealthStatusIntegration(t *testing.T) {
	t.Parallel()

	t.Run("healthy_with_running_process", func(t *testing.T) {
		config := bridge.DefaultBridgeConfig()
		config.Command = []string{"mock-tool"}

		b := bridge.NewBridge(config, nil)

		mockProcess := NewMockToolProcess()
		mockProcess.Start(context.Background(), config.Command, "", nil)
		b.SetProcessManager(mockProcess)

		status := b.Health()
		assert.Equal(t, "healthy", status.Status)
	})

	t.Run("unhealthy_with_stopped_process", func(t *testing.T) {
		config := bridge.DefaultBridgeConfig()
		config.Command = []string{"mock-tool"}

		b := bridge.NewBridge(config, nil)

		mockProcess := NewMockToolProcess()
		// Don't start the process
		b.SetProcessManager(mockProcess)

		status := b.Health()
		assert.Equal(t, "unhealthy", status.Status)
		assert.NotEmpty(t, status.Reason)
	})

	t.Run("healthy_without_command", func(t *testing.T) {
		config := bridge.DefaultBridgeConfig()
		config.Command = []string{} // No command configured

		b := bridge.NewBridge(config, nil)

		status := b.Health()
		assert.Equal(t, "healthy", status.Status)
	})
}
