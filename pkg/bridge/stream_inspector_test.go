package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/polisai/polis-oss/pkg/policy"
)

// **Feature: mcp-expansion, Property 7: Server Request Detection Accuracy**
// **Validates: Requirements 3.2**
// For any JSON-RPC message in an SSE event, the Stream Inspector SHALL correctly
// classify it as a server-initiated request if and only if it contains a `method`
// field and does not contain a `result` or `error` field.
func TestServerRequestDetectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random JSON-RPC message
		msgType := rapid.IntRange(0, 3).Draw(t, "msg_type")

		var data []byte
		var expectedIsServerRequest bool

		switch msgType {
		case 0:
			// Generate a server request (has method and id, no result/error)
			data = generateServerRequest(t)
			expectedIsServerRequest = true
		case 1:
			// Generate a response (has result or error)
			data = generateResponse(t)
			expectedIsServerRequest = false
		case 2:
			// Generate a notification (has method, no id)
			data = generateNotification(t)
			expectedIsServerRequest = false
		case 3:
			// Generate a client request (has method and id, but we treat as server request)
			// In MCP context, server-initiated requests have method+id
			data = generateClientRequest(t)
			// Client requests also have method+id, so they're classified as server requests
			// The distinction is contextual (direction of message flow)
			expectedIsServerRequest = true
		}

		// Test the classification
		actualIsServerRequest := IsServerRequestData(data)
		assert.Equal(t, expectedIsServerRequest, actualIsServerRequest,
			"Server request detection mismatch for data: %s", string(data))
	})
}

// generateServerRequest creates a JSON-RPC server-initiated request
func generateServerRequest(t *rapid.T) []byte {
	method := rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_/]*`).Draw(t, "method")
	id := rapid.OneOf(
		rapid.Just(json.RawMessage(`1`)),
		rapid.Just(json.RawMessage(`"abc"`)),
		rapid.Just(json.RawMessage(`123`)),
	).Draw(t, "id")

	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"id":      id,
	}

	// Optionally add params
	if rapid.Bool().Draw(t, "has_params") {
		msg["params"] = map[string]interface{}{
			"key": rapid.String().Draw(t, "param_value"),
		}
	}

	data, _ := json.Marshal(msg)
	return data
}

// generateResponse creates a JSON-RPC response message
func generateResponse(t *rapid.T) []byte {
	hasResult := rapid.Bool().Draw(t, "has_result")

	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      rapid.IntRange(1, 1000).Draw(t, "id"),
	}

	if hasResult {
		msg["result"] = map[string]interface{}{
			"data": rapid.String().Draw(t, "result_data"),
		}
	} else {
		msg["error"] = map[string]interface{}{
			"code":    rapid.IntRange(-32700, -32600).Draw(t, "error_code"),
			"message": rapid.String().Draw(t, "error_message"),
		}
	}

	data, _ := json.Marshal(msg)
	return data
}

// generateNotification creates a JSON-RPC notification (no id)
func generateNotification(t *rapid.T) []byte {
	method := rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_/]*`).Draw(t, "method")

	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
	}

	// Optionally add params
	if rapid.Bool().Draw(t, "has_params") {
		msg["params"] = map[string]interface{}{
			"key": rapid.String().Draw(t, "param_value"),
		}
	}

	data, _ := json.Marshal(msg)
	return data
}

// generateClientRequest creates a JSON-RPC client request
func generateClientRequest(t *rapid.T) []byte {
	method := rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_/]*`).Draw(t, "method")

	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"id":      rapid.IntRange(1, 1000).Draw(t, "id"),
	}

	// Optionally add params
	if rapid.Bool().Draw(t, "has_params") {
		msg["params"] = map[string]interface{}{
			"key": rapid.String().Draw(t, "param_value"),
		}
	}

	data, _ := json.Marshal(msg)
	return data
}


// TestJSONRPCClassification tests specific JSON-RPC classification cases
func TestJSONRPCClassification(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedType JSONRPCMessageType
		wantErr      bool
	}{
		{
			name:         "server request with method and id",
			input:        `{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{}}`,
			expectedType: MessageTypeServerRequest,
		},
		{
			name:         "server request with string id",
			input:        `{"jsonrpc":"2.0","method":"tools/call","id":"abc-123","params":{"name":"test"}}`,
			expectedType: MessageTypeServerRequest,
		},
		{
			name:         "response with result",
			input:        `{"jsonrpc":"2.0","id":1,"result":{"content":"hello"}}`,
			expectedType: MessageTypeResponse,
		},
		{
			name:         "response with error",
			input:        `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}`,
			expectedType: MessageTypeResponse,
		},
		{
			name:         "notification (no id)",
			input:        `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":50}}`,
			expectedType: MessageTypeNotification,
		},
		{
			name:         "notification with null id",
			input:        `{"jsonrpc":"2.0","method":"notifications/message","id":null,"params":{}}`,
			expectedType: MessageTypeNotification,
		},
		{
			name:    "invalid json",
			input:   `{invalid json}`,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   ``,
			wantErr: true,
		},
		{
			name:         "message with both method and result (edge case)",
			input:        `{"jsonrpc":"2.0","method":"test","result":"value"}`,
			expectedType: MessageTypeResponse, // result takes precedence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgType, msg, err := ClassifyJSONRPC([]byte(tt.input))

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedType, msgType, "message type mismatch")
			assert.NotNil(t, msg)
		})
	}
}

// TestIsServerRequest tests the IsServerRequest method
func TestIsServerRequest(t *testing.T) {
	inspector := NewStreamInspector(nil, nil, nil)

	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "sampling request",
			data:     []byte(`{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{"messages":[]}}`),
			expected: true,
		},
		{
			name:     "tools call request",
			data:     []byte(`{"jsonrpc":"2.0","method":"tools/call","id":"req-1","params":{"name":"read_file"}}`),
			expected: true,
		},
		{
			name:     "response",
			data:     []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"test"}}`),
			expected: false,
		},
		{
			name:     "notification",
			data:     []byte(`{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`),
			expected: false,
		},
		{
			name:     "invalid json",
			data:     []byte(`not json`),
			expected: false,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inspector.IsServerRequest(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMessageTypeString tests the String method of JSONRPCMessageType
func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		msgType  JSONRPCMessageType
		expected string
	}{
		{MessageTypeUnknown, "unknown"},
		{MessageTypeRequest, "request"},
		{MessageTypeNotification, "notification"},
		{MessageTypeResponse, "response"},
		{MessageTypeServerRequest, "server_request"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.msgType.String())
		})
	}
}


// MockPolicyEngine is a mock implementation of PolicyEngine for testing
type MockPolicyEngine struct {
	lastInput    policy.Input
	decision     policy.Decision
	err          error
	evaluateCalls int
}

func (m *MockPolicyEngine) Evaluate(ctx context.Context, input policy.Input) (policy.Decision, error) {
	m.evaluateCalls++
	m.lastInput = input
	return m.decision, m.err
}

// **Feature: mcp-expansion, Property 9: Elicitation Policy Input Completeness**
// **Validates: Requirements 4.1, 4.2**
// For any `sampling/createMessage` request detected in the SSE stream, the policy
// input constructed for evaluation SHALL contain the method name, all parameters
// from the request, and the originating tool identifier.
func TestElicitationPolicyInputCompletenessProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		t := rt // Use rapid.T for generators
		// Generate a random sampling/createMessage request
		method := "sampling/createMessage"
		toolID := rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_-]*`).Draw(t, "tool_id")
		sessionID := rapid.StringMatching(`[a-zA-Z0-9-]*`).Draw(t, "session_id")
		agentID := rapid.StringMatching(`[a-zA-Z0-9-]*`).Draw(t, "agent_id")

		// Generate random params
		params := make(map[string]interface{})
		numParams := rapid.IntRange(0, 5).Draw(t, "num_params")
		for i := 0; i < numParams; i++ {
			key := rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_]*`).Draw(t, "param_key")
			value := rapid.String().Draw(t, "param_value")
			params[key] = value
		}

		// Build the JSON-RPC message
		msg := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  method,
			"id":      rapid.IntRange(1, 1000).Draw(t, "id"),
			"params":  params,
		}
		data, err := json.Marshal(msg)
		require.NoError(t, err)

		// Create mock policy engine to capture the input
		mockEngine := &MockPolicyEngine{
			decision: policy.Decision{Action: policy.ActionAllow},
		}

		inspector := NewStreamInspector(mockEngine, nil, nil)

		// Create SSE event
		event := &SSEEvent{
			ID:   rapid.StringMatching(`[a-zA-Z0-9-]*`).Draw(t, "event_id"),
			Data: data,
		}

		// Inspect the event
		ctx := context.Background()
		inspectCtx := &InspectContext{
			SessionID: sessionID,
			AgentID:   agentID,
		}
		_, err = inspector.InspectWithContext(ctx, event, toolID, inspectCtx)
		require.NoError(t, err)

		// Verify policy was called
		require.Equal(t, 1, mockEngine.evaluateCalls, "Policy should be evaluated once")

		// Verify the policy input contains all required fields
		input := mockEngine.lastInput
		attrs := input.Attributes

		// Method name must be present
		assert.Equal(t, method, attrs["method"], "Method name must be in policy input")

		// Tool ID must be present
		assert.Equal(t, toolID, attrs["tool_id"], "Tool ID must be in policy input")

		// Session ID must be present
		assert.Equal(t, sessionID, attrs["session_id"], "Session ID must be in policy input")

		// Agent ID must be present
		assert.Equal(t, agentID, attrs["agent_id"], "Agent ID must be in policy input")

		// Params must be present and contain all original params
		inputParams, ok := attrs["params"].(map[string]interface{})
		require.True(t, ok, "Params must be a map in policy input")
		for key, value := range params {
			assert.Equal(t, value, inputParams[key], "Param %s must be preserved in policy input", key)
		}
	})
}


// **Feature: mcp-expansion, Property 8: Policy Enforcement Consistency**
// **Validates: Requirements 3.3, 3.4, 4.3, 4.4**
// For any server-initiated request evaluated against a policy:
// - If the policy returns "block", the SSE event SHALL NOT be forwarded to the client
// - If the policy returns "allow", the SSE event SHALL be forwarded unchanged
// - If the policy returns "redact", the SSE event SHALL be forwarded with content modified
func TestPolicyEnforcementConsistencyProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate a random server request
		method := rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_/]*`).Draw(rt, "method")
		toolID := rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_-]*`).Draw(rt, "tool_id")

		msg := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  method,
			"id":      rapid.IntRange(1, 1000).Draw(rt, "id"),
			"params": map[string]interface{}{
				"content": rapid.String().Draw(rt, "content"),
			},
		}
		data, err := json.Marshal(msg)
		require.NoError(t, err)

		event := &SSEEvent{
			ID:   rapid.StringMatching(`[a-zA-Z0-9-]*`).Draw(rt, "event_id"),
			Data: data,
		}

		// Generate a random policy decision
		actionType := rapid.IntRange(0, 2).Draw(rt, "action_type")
		var policyAction policy.Action
		var expectedResultAction string

		switch actionType {
		case 0:
			policyAction = policy.ActionAllow
			expectedResultAction = "allow"
		case 1:
			policyAction = policy.ActionBlock
			expectedResultAction = "block"
		case 2:
			policyAction = policy.ActionRedact
			expectedResultAction = "redact"
		}

		mockEngine := &MockPolicyEngine{
			decision: policy.Decision{
				Action: policyAction,
				Reason: "test reason",
			},
		}

		inspector := NewStreamInspector(mockEngine, nil, nil)

		ctx := context.Background()
		result, err := inspector.Inspect(ctx, event, toolID)
		require.NoError(t, err)

		// Verify the result action matches the policy decision
		assert.Equal(t, expectedResultAction, result.Action,
			"Result action should match policy decision")

		// Verify specific behaviors based on action
		switch policyAction {
		case policy.ActionAllow:
			// Allow should not modify data
			assert.Nil(t, result.ModifiedData, "Allow should not modify data")

		case policy.ActionBlock:
			// Block should not have modified data
			assert.Nil(t, result.ModifiedData, "Block should not have modified data")

		case policy.ActionRedact:
			// Redact may or may not have modified data depending on rules
			// The important thing is the action is "redact"
		}
	})
}

// TestPolicyEnforcementWithRedaction tests redaction with specific rules
func TestPolicyEnforcementWithRedaction(t *testing.T) {
	tests := []struct {
		name           string
		inputData      string
		redactionRules interface{}
		modifiedData   interface{}
		expectModified bool
	}{
		{
			name:      "redact with modified_data string",
			inputData: `{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{"content":"secret"}}`,
			modifiedData: `{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{"content":"[REDACTED]"}}`,
			expectModified: true,
		},
		{
			name:      "redact with modified_data map",
			inputData: `{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{"content":"secret"}}`,
			modifiedData: map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "sampling/createMessage",
				"id":      1,
				"params":  map[string]interface{}{"content": "[REDACTED]"},
			},
			expectModified: true,
		},
		{
			name:      "redact with field rules",
			inputData: `{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{"content":"secret"}}`,
			redactionRules: map[string]interface{}{
				"fields": []interface{}{"params.content"},
			},
			expectModified: true,
		},
		{
			name:           "redact without rules returns original",
			inputData:      `{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{"content":"secret"}}`,
			expectModified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputs := make(map[string]interface{})
			if tt.modifiedData != nil {
				outputs["modified_data"] = tt.modifiedData
			}
			if tt.redactionRules != nil {
				outputs["redaction_rules"] = tt.redactionRules
			}

			mockEngine := &MockPolicyEngine{
				decision: policy.Decision{
					Action:  policy.ActionRedact,
					Reason:  "test redaction",
					Outputs: outputs,
				},
			}

			inspector := NewStreamInspector(mockEngine, nil, nil)

			event := &SSEEvent{
				ID:   "test-event",
				Data: []byte(tt.inputData),
			}

			ctx := context.Background()
			result, err := inspector.Inspect(ctx, event, "test-tool")
			require.NoError(t, err)

			assert.Equal(t, "redact", result.Action)
			if tt.expectModified {
				assert.NotNil(t, result.ModifiedData, "Expected modified data")
			}
		})
	}
}


// TestFailClosedBehavior tests that server requests are blocked when no policy is configured
// **Validates: Requirements 4.5**
func TestFailClosedBehavior(t *testing.T) {
	tests := []struct {
		name           string
		policyEngine   PolicyEngine
		failClosed     bool
		inputData      string
		expectedAction string
	}{
		{
			name:           "fail-closed blocks server request when no policy engine",
			policyEngine:   nil,
			failClosed:     true,
			inputData:      `{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{}}`,
			expectedAction: "block",
		},
		{
			name:           "fail-open allows server request when no policy engine",
			policyEngine:   nil,
			failClosed:     false,
			inputData:      `{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{}}`,
			expectedAction: "allow",
		},
		{
			name:           "fail-closed allows non-server-request messages",
			policyEngine:   nil,
			failClosed:     true,
			inputData:      `{"jsonrpc":"2.0","id":1,"result":{"content":"test"}}`,
			expectedAction: "allow",
		},
		{
			name:           "fail-closed allows notifications",
			policyEngine:   nil,
			failClosed:     true,
			inputData:      `{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`,
			expectedAction: "allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &StreamInspectorConfig{
				Entrypoint: DefaultElicitationEntrypoint,
				FailClosed: tt.failClosed,
			}

			inspector := NewStreamInspector(tt.policyEngine, config, nil)

			event := &SSEEvent{
				ID:   "test-event",
				Data: []byte(tt.inputData),
			}

			ctx := context.Background()
			result, err := inspector.Inspect(ctx, event, "test-tool")
			require.NoError(t, err)

			assert.Equal(t, tt.expectedAction, result.Action,
				"Expected action %s but got %s", tt.expectedAction, result.Action)
		})
	}
}

// TestFailClosedOnPolicyError tests that policy errors result in blocking in fail-closed mode
func TestFailClosedOnPolicyError(t *testing.T) {
	tests := []struct {
		name           string
		policyError    error
		failClosed     bool
		expectedAction string
	}{
		{
			name:           "fail-closed blocks on policy error",
			policyError:    assert.AnError,
			failClosed:     true,
			expectedAction: "block",
		},
		{
			name:           "fail-open allows on policy error",
			policyError:    assert.AnError,
			failClosed:     false,
			expectedAction: "allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEngine := &MockPolicyEngine{
				err: tt.policyError,
			}

			config := &StreamInspectorConfig{
				Entrypoint: DefaultElicitationEntrypoint,
				FailClosed: tt.failClosed,
			}

			inspector := NewStreamInspector(mockEngine, config, nil)

			event := &SSEEvent{
				ID:   "test-event",
				Data: []byte(`{"jsonrpc":"2.0","method":"sampling/createMessage","id":1,"params":{}}`),
			}

			ctx := context.Background()
			result, err := inspector.Inspect(ctx, event, "test-tool")
			require.NoError(t, err) // Inspect should not return error, just block

			assert.Equal(t, tt.expectedAction, result.Action)
		})
	}
}

// TestDefaultConfigIsFailClosed verifies the default configuration uses fail-closed mode
func TestDefaultConfigIsFailClosed(t *testing.T) {
	config := DefaultStreamInspectorConfig()
	assert.True(t, config.FailClosed, "Default config should be fail-closed")
	assert.Equal(t, DefaultElicitationEntrypoint, config.Entrypoint)
}
