package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// MockProcessManager is a mock implementation of ProcessManager for testing
type MockProcessManager struct {
	running     bool
	exitCode    int
	writeErr    error
	startErr    error
	stopErr     error
	writtenData [][]byte
}

func NewMockProcessManager(running bool) *MockProcessManager {
	return &MockProcessManager{
		running:  running,
		exitCode: 0,
	}
}

func (m *MockProcessManager) Start(ctx context.Context, command []string, workDir string, env []string) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.running = true
	return nil
}

func (m *MockProcessManager) Write(data []byte) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writtenData = append(m.writtenData, data)
	return nil
}

func (m *MockProcessManager) ReadLoop(handler func([]byte)) error {
	// Mock implementation - does nothing
	return nil
}

func (m *MockProcessManager) Stop(timeout time.Duration) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running = false
	return nil
}

func (m *MockProcessManager) IsRunning() bool {
	return m.running
}

func (m *MockProcessManager) ExitCode() int {
	return m.exitCode
}

// **Feature: mcp-expansion, Property 12: Health Status Accuracy**
// **Validates: Requirements 8.1, 8.3**
// For any Bridge instance, the /health endpoint SHALL return healthy status
// if and only if the child process is running and responsive.
func TestHealthStatusAccuracyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random process state
		processRunning := rapid.Bool().Draw(t, "process_running")
		hasCommand := rapid.Bool().Draw(t, "has_command")

		// Create bridge with configuration
		config := DefaultBridgeConfig()
		if hasCommand {
			config.Command = []string{"echo", "test"}
		} else {
			config.Command = []string{}
		}

		bridge := NewBridge(config, nil)

		// Set up mock process manager if command is configured
		if hasCommand {
			mockPM := NewMockProcessManager(processRunning)
			bridge.SetProcessManager(mockPM)
		}

		// Get health status
		status := bridge.Health()

		// Verify property: health status accurately reflects process state
		if hasCommand {
			if processRunning {
				// Process is running -> should be healthy
				assert.Equal(t, "healthy", status.Status,
					"Bridge with running process should report healthy")
			} else {
				// Process not running -> should be unhealthy
				assert.Equal(t, "unhealthy", status.Status,
					"Bridge with stopped process should report unhealthy")
				assert.NotEmpty(t, status.Reason,
					"Unhealthy status should include a reason")
			}
		} else {
			// No command configured -> should be healthy (no process to check)
			assert.Equal(t, "healthy", status.Status,
				"Bridge without command should report healthy")
		}
	})
}

// Test health endpoint HTTP handler
func TestHealthEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		processRunning bool
		hasCommand     bool
		expectedStatus int
		expectedHealth string
	}{
		{
			name:           "healthy with running process",
			processRunning: true,
			hasCommand:     true,
			expectedStatus: http.StatusOK,
			expectedHealth: "healthy",
		},
		{
			name:           "unhealthy with stopped process",
			processRunning: false,
			hasCommand:     true,
			expectedStatus: http.StatusServiceUnavailable,
			expectedHealth: "unhealthy",
		},
		{
			name:           "healthy without command",
			processRunning: false,
			hasCommand:     false,
			expectedStatus: http.StatusOK,
			expectedHealth: "healthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultBridgeConfig()
			if tt.hasCommand {
				config.Command = []string{"echo", "test"}
			}

			bridge := NewBridge(config, nil)

			if tt.hasCommand {
				mockPM := NewMockProcessManager(tt.processRunning)
				bridge.SetProcessManager(mockPM)
			}

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			rec := httptest.NewRecorder()

			// Call handler
			bridge.handleHealth(rec, req)

			// Verify response
			assert.Equal(t, tt.expectedStatus, rec.Code)

			var status HealthStatus
			err := json.Unmarshal(rec.Body.Bytes(), &status)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedHealth, status.Status)
		})
	}
}

// Test health endpoint method validation
func TestHealthEndpointMethodNotAllowed(t *testing.T) {
	bridge := NewBridge(nil, nil)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/health", nil)
			rec := httptest.NewRecorder()

			bridge.handleHealth(rec, req)

			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}

// Test SSE endpoint requires agent ID
func TestSSEEndpointRequiresAgentID(t *testing.T) {
	config := DefaultBridgeConfig()
	bridge := NewBridge(config, nil)
	bridge.sessions = NewSessionManager(config.Session, nil)

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	rec := httptest.NewRecorder()

	bridge.HandleSSE(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "agent ID")
}

// Test message endpoint requires agent ID
func TestMessageEndpointRequiresAgentID(t *testing.T) {
	config := DefaultBridgeConfig()
	bridge := NewBridge(config, nil)
	bridge.sessions = NewSessionManager(config.Session, nil)

	body := strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":1}`)
	req := httptest.NewRequest(http.MethodPost, "/message", body)
	rec := httptest.NewRecorder()

	bridge.HandleMessage(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// Test message endpoint method validation
func TestMessageEndpointMethodNotAllowed(t *testing.T) {
	bridge := NewBridge(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/message", nil)
	rec := httptest.NewRecorder()

	bridge.HandleMessage(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// Test message endpoint validates JSON-RPC format
func TestMessageEndpointValidatesJSONRPC(t *testing.T) {
	config := DefaultBridgeConfig()
	bridge := NewBridge(config, nil)
	bridge.sessions = NewSessionManager(config.Session, nil)

	// Invalid JSON
	body := strings.NewReader(`not valid json`)
	req := httptest.NewRequest(http.MethodPost, "/message", body)
	req.Header.Set("X-Agent-ID", "test-agent")
	rec := httptest.NewRecorder()

	// Add agent ID to context (simulating middleware)
	ctx := context.WithValue(req.Context(), AgentIDContextKey, "test-agent")
	bridge.HandleMessage(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// Test message endpoint requires running process
func TestMessageEndpointRequiresRunningProcess(t *testing.T) {
	config := DefaultBridgeConfig()
	config.Command = []string{"echo", "test"}
	bridge := NewBridge(config, nil)
	bridge.sessions = NewSessionManager(config.Session, nil)

	// Set up stopped process
	mockPM := NewMockProcessManager(false)
	bridge.SetProcessManager(mockPM)

	body := strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":1}`)
	req := httptest.NewRequest(http.MethodPost, "/message", body)
	req.Header.Set("X-Agent-ID", "test-agent")
	rec := httptest.NewRecorder()

	// Add agent ID to context
	ctx := context.WithValue(req.Context(), AgentIDContextKey, "test-agent")
	bridge.HandleMessage(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// Test message forwarding to process
func TestMessageForwardingToProcess(t *testing.T) {
	config := DefaultBridgeConfig()
	config.Command = []string{"echo", "test"}
	bridge := NewBridge(config, nil)
	bridge.sessions = NewSessionManager(config.Session, nil)

	// Set up running process
	mockPM := NewMockProcessManager(true)
	bridge.SetProcessManager(mockPM)

	jsonRPC := `{"jsonrpc":"2.0","method":"test","id":1}`
	body := strings.NewReader(jsonRPC)
	req := httptest.NewRequest(http.MethodPost, "/message", body)
	req.Header.Set("X-Agent-ID", "test-agent")
	rec := httptest.NewRecorder()

	// Add agent ID to context
	ctx := context.WithValue(req.Context(), AgentIDContextKey, "test-agent")
	bridge.HandleMessage(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusAccepted, rec.Code)

	// Verify message was written to process
	require.Len(t, mockPM.writtenData, 1)
	// Message should have newline appended
	assert.Equal(t, jsonRPC+"\n", string(mockPM.writtenData[0]))
}

// Test bridge initialization
func TestBridgeInitialization(t *testing.T) {
	config := DefaultBridgeConfig()
	bridge := NewBridge(config, nil)

	assert.NotNil(t, bridge)
	assert.NotNil(t, bridge.config)
	assert.NotNil(t, bridge.sseClients)
	assert.NotNil(t, bridge.stopCh)
	assert.False(t, bridge.IsInitialized())
}

// Test bridge with nil config uses defaults
func TestBridgeWithNilConfig(t *testing.T) {
	bridge := NewBridge(nil, nil)

	assert.NotNil(t, bridge)
	assert.NotNil(t, bridge.config)
	assert.Equal(t, ":8090", bridge.config.ListenAddr)
}
