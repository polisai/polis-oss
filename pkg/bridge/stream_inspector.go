package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/polisai/polis-oss/pkg/policy"
)

// DefaultElicitationEntrypoint is the default policy entrypoint for elicitation evaluation
const DefaultElicitationEntrypoint = "mcp/elicitation"

// StreamInspectorConfig holds configuration for the stream inspector
type StreamInspectorConfig struct {
	// Entrypoint is the policy entrypoint for elicitation evaluation
	Entrypoint string `yaml:"entrypoint"`
	// FailClosed determines behavior when no policy is configured
	// If true, all server requests are blocked when no policy exists
	FailClosed bool `yaml:"fail_closed"`
}

// DefaultStreamInspectorConfig returns the default configuration
func DefaultStreamInspectorConfig() *StreamInspectorConfig {
	return &StreamInspectorConfig{
		Entrypoint: DefaultElicitationEntrypoint,
		FailClosed: true, // Fail-closed by default for security
	}
}

// PolicyEngine defines the interface for policy evaluation
// This allows for dependency injection and testing
type PolicyEngine interface {
	Evaluate(ctx context.Context, input policy.Input) (policy.Decision, error)
}

// StreamInspectorImpl implements the StreamInspector interface
// It parses SSE events and evaluates them against configured policies
type StreamInspectorImpl struct {
	policyEngine PolicyEngine
	config       *StreamInspectorConfig
	logger       *slog.Logger
	metrics      *Metrics
}

// NewStreamInspector creates a new StreamInspector with the given policy engine
func NewStreamInspector(engine PolicyEngine, config *StreamInspectorConfig, logger *slog.Logger) *StreamInspectorImpl {
	if config == nil {
		config = DefaultStreamInspectorConfig()
	}
	if config.Entrypoint == "" {
		config.Entrypoint = DefaultElicitationEntrypoint
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &StreamInspectorImpl{
		policyEngine: engine,
		config:       config,
		logger:       logger,
	}
}

// SetMetrics sets the metrics instance for recording stream inspector metrics
func (si *StreamInspectorImpl) SetMetrics(metrics *Metrics) {
	si.metrics = metrics
}

// ParseSSEEvent parses a single SSE event from raw bytes
// Delegates to the package-level ParseSSEEvent function
func (si *StreamInspectorImpl) ParseSSEEvent(data []byte) (*SSEEvent, error) {
	return ParseSSEEvent(data)
}

// ParseSSEStream reads SSE events from a reader and returns a channel
// Delegates to the package-level ParseSSEStream function
func (si *StreamInspectorImpl) ParseSSEStream(r io.Reader) <-chan *SSEEvent {
	return ParseSSEStream(r)
}


// JSONRPCMessage represents a parsed JSON-RPC 2.0 message
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// JSONRPCMessageType represents the type of JSON-RPC message
type JSONRPCMessageType int

const (
	// MessageTypeUnknown indicates the message type could not be determined
	MessageTypeUnknown JSONRPCMessageType = iota
	// MessageTypeRequest indicates a client-to-server request (has method and id)
	MessageTypeRequest
	// MessageTypeNotification indicates a notification (has method, no id)
	MessageTypeNotification
	// MessageTypeResponse indicates a response (has result or error)
	MessageTypeResponse
	// MessageTypeServerRequest indicates a server-initiated request (has method, no result/error)
	MessageTypeServerRequest
)

// String returns a string representation of the message type
func (t JSONRPCMessageType) String() string {
	switch t {
	case MessageTypeRequest:
		return "request"
	case MessageTypeNotification:
		return "notification"
	case MessageTypeResponse:
		return "response"
	case MessageTypeServerRequest:
		return "server_request"
	default:
		return "unknown"
	}
}

// ClassifyJSONRPC classifies a JSON-RPC message based on its structure
// Returns the message type and the parsed message
func ClassifyJSONRPC(data []byte) (JSONRPCMessageType, *JSONRPCMessage, error) {
	if len(data) == 0 {
		return MessageTypeUnknown, nil, fmt.Errorf("empty data")
	}

	var msg JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return MessageTypeUnknown, nil, fmt.Errorf("invalid JSON-RPC: %w", err)
	}

	return classifyMessage(&msg), &msg, nil
}

// classifyMessage determines the type of a parsed JSON-RPC message
func classifyMessage(msg *JSONRPCMessage) JSONRPCMessageType {
	hasMethod := msg.Method != ""
	hasID := len(msg.ID) > 0 && string(msg.ID) != "null"
	hasResult := len(msg.Result) > 0 && string(msg.Result) != "null"
	hasError := len(msg.Error) > 0 && string(msg.Error) != "null"

	// Response: has result or error field
	if hasResult || hasError {
		return MessageTypeResponse
	}

	// Has method field - could be request, notification, or server request
	if hasMethod {
		// If it has an ID, it's a request expecting a response
		if hasID {
			// Server-initiated request (server sends request to client)
			// In MCP context, these are elicitation requests like sampling/createMessage
			return MessageTypeServerRequest
		}
		// No ID means it's a notification
		return MessageTypeNotification
	}

	return MessageTypeUnknown
}

// IsServerRequest determines if the event data contains a server-initiated JSON-RPC request
// A server request has a method field but no result or error field
func (si *StreamInspectorImpl) IsServerRequest(data []byte) bool {
	msgType, _, err := ClassifyJSONRPC(data)
	if err != nil {
		return false
	}
	return msgType == MessageTypeServerRequest
}

// IsServerRequestData is a standalone function to check if data is a server request
// This is useful for testing without needing a full StreamInspector instance
func IsServerRequestData(data []byte) bool {
	msgType, _, err := ClassifyJSONRPC(data)
	if err != nil {
		return false
	}
	return msgType == MessageTypeServerRequest
}


// ElicitationInput is the policy input for server-initiated requests
type ElicitationInput struct {
	Method    string                 `json:"method"`
	Params    map[string]interface{} `json:"params"`
	ToolID    string                 `json:"tool_id"`
	SessionID string                 `json:"session_id"`
	AgentID   string                 `json:"agent_id"`
}

// InspectContext provides additional context for inspection
type InspectContext struct {
	SessionID string
	AgentID   string
}

// Inspect evaluates an SSE event against configured policies
// Returns an InspectionResult indicating whether to allow, block, or redact the event
func (si *StreamInspectorImpl) Inspect(ctx context.Context, event *SSEEvent, toolID string) (*InspectionResult, error) {
	return si.InspectWithContext(ctx, event, toolID, nil)
}

// InspectWithContext evaluates an SSE event with additional context
func (si *StreamInspectorImpl) InspectWithContext(ctx context.Context, event *SSEEvent, toolID string, inspectCtx *InspectContext) (*InspectionResult, error) {
	if event == nil {
		return &InspectionResult{
			Action: "allow",
			Reason: "nil event",
		}, nil
	}

	// Parse the event data as JSON-RPC
	msgType, msg, err := ClassifyJSONRPC(event.Data)
	if err != nil {
		// If we can't parse as JSON-RPC, forward unchanged and log warning
		si.logger.Warn("Failed to parse SSE event as JSON-RPC",
			"error", err,
			"event_id", event.ID,
			"event_type", event.Event,
		)
		return &InspectionResult{
			Action: "allow",
			Reason: "unparseable as JSON-RPC, forwarding unchanged",
		}, nil
	}

	// Only inspect server-initiated requests
	if msgType != MessageTypeServerRequest {
		result := &InspectionResult{
			Action: "allow",
			Reason: fmt.Sprintf("message type %s does not require inspection", msgType),
		}
		// Record metrics for non-server requests
		if si.metrics != nil {
			si.metrics.RecordStreamInspectorEvent(result.Action, msg.Method)
		}
		return result, nil
	}

	// Check if policy engine is configured
	if si.policyEngine == nil {
		var result *InspectionResult
		if si.config.FailClosed {
			si.logger.Warn("Blocking server request due to fail-closed mode (no policy engine)",
				"method", msg.Method,
				"tool_id", toolID,
			)
			result = &InspectionResult{
				Action: "block",
				Reason: "no policy engine configured, fail-closed mode active",
			}
		} else {
			result = &InspectionResult{
				Action: "allow",
				Reason: "no policy engine configured",
			}
		}
		// Record metrics for no policy engine case
		if si.metrics != nil {
			si.metrics.RecordStreamInspectorEvent(result.Action, msg.Method)
		}
		return result, nil
	}

	// Build policy input
	policyInput, err := si.buildPolicyInput(msg, toolID, inspectCtx)
	if err != nil {
		si.logger.Error("Failed to build policy input",
			"error", err,
			"method", msg.Method,
		)
		var result *InspectionResult
		if si.config.FailClosed {
			result = &InspectionResult{
				Action: "block",
				Reason: fmt.Sprintf("failed to build policy input: %v", err),
			}
		} else {
			result = &InspectionResult{
				Action: "allow",
				Reason: "failed to build policy input, allowing due to fail-open mode",
			}
		}
		// Record metrics for policy input build failure
		if si.metrics != nil {
			si.metrics.RecordStreamInspectorEvent(result.Action, msg.Method)
		}
		return result, nil
	}

	// Evaluate policy
	decision, err := si.policyEngine.Evaluate(ctx, policyInput)
	if err != nil {
		si.logger.Error("Policy evaluation failed",
			"error", err,
			"method", msg.Method,
			"tool_id", toolID,
		)
		var result *InspectionResult
		if si.config.FailClosed {
			result = &InspectionResult{
				Action: "block",
				Reason: fmt.Sprintf("policy evaluation failed: %v", err),
			}
		} else {
			result = &InspectionResult{
				Action: "allow",
				Reason: "policy evaluation failed, allowing due to fail-open mode",
			}
		}
		// Record metrics for policy evaluation failure
		if si.metrics != nil {
			si.metrics.RecordStreamInspectorEvent(result.Action, msg.Method)
		}
		return result, nil
	}

	// Convert policy decision to inspection result
	result, err := si.decisionToResult(decision, msg, event)
	if err != nil {
		return result, err
	}

	// Record metrics for the inspection result
	if si.metrics != nil {
		si.metrics.RecordStreamInspectorEvent(result.Action, msg.Method)
	}

	return result, nil
}

// buildPolicyInput constructs the policy input from the JSON-RPC message
func (si *StreamInspectorImpl) buildPolicyInput(msg *JSONRPCMessage, toolID string, inspectCtx *InspectContext) (policy.Input, error) {
	// Parse params if present
	var params map[string]interface{}
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			// Params might be an array, try that
			var paramsArray []interface{}
			if err2 := json.Unmarshal(msg.Params, &paramsArray); err2 != nil {
				return policy.Input{}, fmt.Errorf("failed to parse params: %w", err)
			}
			params = map[string]interface{}{"_array": paramsArray}
		}
	}

	// Build elicitation input
	elicitationInput := ElicitationInput{
		Method: msg.Method,
		Params: params,
		ToolID: toolID,
	}

	if inspectCtx != nil {
		elicitationInput.SessionID = inspectCtx.SessionID
		elicitationInput.AgentID = inspectCtx.AgentID
	}

	// Convert to attributes map for policy engine
	attributes := map[string]interface{}{
		"method":     elicitationInput.Method,
		"params":     elicitationInput.Params,
		"tool_id":    elicitationInput.ToolID,
		"session_id": elicitationInput.SessionID,
		"agent_id":   elicitationInput.AgentID,
	}

	return policy.Input{
		Entrypoint: si.config.Entrypoint,
		Attributes: attributes,
	}, nil
}

// decisionToResult converts a policy decision to an inspection result
func (si *StreamInspectorImpl) decisionToResult(decision policy.Decision, msg *JSONRPCMessage, event *SSEEvent) (*InspectionResult, error) {
	result := &InspectionResult{
		Reason: decision.Reason,
	}

	switch decision.Action {
	case policy.ActionAllow:
		result.Action = "allow"
		si.logger.Debug("Policy allowed server request",
			"method", msg.Method,
			"reason", decision.Reason,
		)

	case policy.ActionBlock:
		result.Action = "block"
		si.logger.Warn("Policy blocked server request",
			"method", msg.Method,
			"reason", decision.Reason,
		)

	case policy.ActionRedact:
		result.Action = "redact"
		// Apply redaction if specified in decision outputs
		modifiedData, err := si.applyRedaction(event.Data, decision)
		if err != nil {
			si.logger.Error("Failed to apply redaction",
				"error", err,
				"method", msg.Method,
			)
			// Fall back to blocking if redaction fails
			result.Action = "block"
			result.Reason = fmt.Sprintf("redaction failed: %v", err)
		} else {
			result.ModifiedData = modifiedData
			si.logger.Info("Policy redacted server request",
				"method", msg.Method,
				"reason", decision.Reason,
			)
		}

	default:
		// Unknown action, treat as block in fail-closed mode
		if si.config.FailClosed {
			result.Action = "block"
			result.Reason = fmt.Sprintf("unknown policy action: %s", decision.Action)
		} else {
			result.Action = "allow"
			result.Reason = fmt.Sprintf("unknown policy action: %s, allowing due to fail-open mode", decision.Action)
		}
	}

	return result, nil
}

// applyRedaction modifies the event data according to redaction rules
func (si *StreamInspectorImpl) applyRedaction(data []byte, decision policy.Decision) ([]byte, error) {
	// Check if decision outputs contain modified data
	if modifiedData, ok := decision.Outputs["modified_data"]; ok {
		switch v := modifiedData.(type) {
		case string:
			return []byte(v), nil
		case []byte:
			return v, nil
		case map[string]interface{}:
			return json.Marshal(v)
		}
	}

	// Check for redaction rules in outputs
	if rules, ok := decision.Outputs["redaction_rules"]; ok {
		return si.applyRedactionRules(data, rules)
	}

	// No specific redaction rules, return original data
	// This allows the policy to mark as "redact" without specifying how
	return data, nil
}

// applyRedactionRules applies specific redaction rules to the data
func (si *StreamInspectorImpl) applyRedactionRules(data []byte, rules interface{}) ([]byte, error) {
	// Parse the original data
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse data for redaction: %w", err)
	}

	// Apply rules based on type
	switch r := rules.(type) {
	case map[string]interface{}:
		// Rules specify fields to redact
		if fields, ok := r["fields"].([]interface{}); ok {
			for _, field := range fields {
				if fieldName, ok := field.(string); ok {
					si.redactField(msg, fieldName)
				}
			}
		}
		// Rules specify replacement values
		if replacements, ok := r["replacements"].(map[string]interface{}); ok {
			for path, value := range replacements {
				si.setFieldValue(msg, path, value)
			}
		}
	case []interface{}:
		// Rules is a list of field paths to redact
		for _, field := range r {
			if fieldName, ok := field.(string); ok {
				si.redactField(msg, fieldName)
			}
		}
	}

	return json.Marshal(msg)
}

// redactField redacts a field in the message by replacing its value with "[REDACTED]"
func (si *StreamInspectorImpl) redactField(msg map[string]interface{}, fieldPath string) {
	si.setFieldValue(msg, fieldPath, "[REDACTED]")
}

// setFieldValue sets a field value in a nested map using dot notation
func (si *StreamInspectorImpl) setFieldValue(msg map[string]interface{}, fieldPath string, value interface{}) {
	// Simple implementation for now - just handles top-level and params.* paths
	if fieldPath == "" {
		return
	}

	// Handle params.* paths
	if len(fieldPath) > 7 && fieldPath[:7] == "params." {
		if params, ok := msg["params"].(map[string]interface{}); ok {
			params[fieldPath[7:]] = value
		}
		return
	}

	// Handle top-level fields
	msg[fieldPath] = value
}
