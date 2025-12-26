// Package handlers provides node handler implementations for the DAG pipeline executor.
package handlers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/polisai/polis-oss/pkg/bridge"
	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/policy"
)

// SSEInspectorConfig holds configuration for SSE stream inspection
type SSEInspectorConfig struct {
	// Enabled determines if SSE inspection is active
	Enabled bool `yaml:"enabled"`
	// Entrypoint is the policy entrypoint for elicitation evaluation
	Entrypoint string `yaml:"entrypoint"`
	// FailClosed determines behavior when no policy is configured
	FailClosed bool `yaml:"fail_closed"`
	// ToolID identifies the upstream tool for policy evaluation
	ToolID string `yaml:"tool_id"`
}

// DefaultSSEInspectorConfig returns the default configuration
func DefaultSSEInspectorConfig() *SSEInspectorConfig {
	return &SSEInspectorConfig{
		Enabled:    false,
		Entrypoint: bridge.DefaultElicitationEntrypoint,
		FailClosed: true,
	}
}

// SSEStreamInspector wraps the bridge StreamInspector for use in the egress handler
type SSEStreamInspector struct {
	inspector *bridge.StreamInspectorImpl
	config    *SSEInspectorConfig
	logger    *slog.Logger
}

// NewSSEStreamInspector creates a new SSE stream inspector
func NewSSEStreamInspector(policyEngine bridge.PolicyEngine, config *SSEInspectorConfig, logger *slog.Logger) *SSEStreamInspector {
	if config == nil {
		config = DefaultSSEInspectorConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Create bridge stream inspector config
	bridgeConfig := &bridge.StreamInspectorConfig{
		Entrypoint: config.Entrypoint,
		FailClosed: config.FailClosed,
	}

	return &SSEStreamInspector{
		inspector: bridge.NewStreamInspector(policyEngine, bridgeConfig, logger),
		config:    config,
		logger:    logger,
	}
}


// InspectSSEStream reads SSE events from a reader, inspects each event against
// configured policies, and writes allowed/redacted events to the writer.
// Blocked events are dropped and logged.
// Returns a report of the inspection results.
func (s *SSEStreamInspector) InspectSSEStream(
	ctx context.Context,
	reader io.Reader,
	writer io.Writer,
	pipelineCtx *domain.PipelineContext,
) (*SSEInspectionReport, error) {
	report := &SSEInspectionReport{
		TotalEvents:   0,
		AllowedEvents: 0,
		BlockedEvents: 0,
		RedactedEvents: 0,
		ParseErrors:   0,
	}

	// Extract context for inspection
	inspectCtx := s.buildInspectContext(pipelineCtx)

	// Use buffered reader for line-by-line processing
	scanner := bufio.NewScanner(reader)
	var eventBuffer bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()

		// Add line to buffer
		eventBuffer.WriteString(line)
		eventBuffer.WriteString("\n")

		// Check if this is an empty line (end of event)
		if strings.TrimSpace(line) == "" {
			// Parse and inspect the complete event
			if eventBuffer.Len() > 1 { // More than just the empty line
				eventData := eventBuffer.Bytes()
				if err := s.processEvent(ctx, eventData, writer, inspectCtx, report); err != nil {
					s.logger.Error("Failed to process SSE event",
						"error", err,
					)
					// Continue processing other events
				}
				eventBuffer.Reset()
			}
		}
	}

	// Handle any remaining data in buffer (stream ended without empty line)
	if eventBuffer.Len() > 0 {
		eventData := eventBuffer.Bytes()
		if err := s.processEvent(ctx, eventData, writer, inspectCtx, report); err != nil {
			s.logger.Error("Failed to process final SSE event",
				"error", err,
			)
		}
	}

	if err := scanner.Err(); err != nil {
		return report, fmt.Errorf("error reading SSE stream: %w", err)
	}

	return report, nil
}

// processEvent parses, inspects, and forwards a single SSE event
func (s *SSEStreamInspector) processEvent(
	ctx context.Context,
	eventData []byte,
	writer io.Writer,
	inspectCtx *bridge.InspectContext,
	report *SSEInspectionReport,
) error {
	report.TotalEvents++

	// Parse the SSE event
	event, err := bridge.ParseSSEEvent(eventData)
	if err != nil {
		// Forward unparseable events unchanged and log warning (Requirement 3.5)
		s.logger.Warn("Failed to parse SSE event, forwarding unchanged",
			"error", err,
		)
		report.ParseErrors++
		if _, writeErr := writer.Write(eventData); writeErr != nil {
			return fmt.Errorf("failed to write unparseable event: %w", writeErr)
		}
		return nil
	}

	// If event has no data, forward unchanged
	if len(event.Data) == 0 {
		report.AllowedEvents++
		serialized := bridge.SerializeSSEEvent(event)
		if _, err := writer.Write(serialized); err != nil {
			return fmt.Errorf("failed to write empty event: %w", err)
		}
		return nil
	}

	// Inspect the event
	result, err := s.inspector.InspectWithContext(ctx, event, s.config.ToolID, inspectCtx)
	if err != nil {
		s.logger.Error("SSE event inspection failed",
			"error", err,
			"event_id", event.ID,
		)
		// On inspection error, apply fail-closed/fail-open behavior
		if s.config.FailClosed {
			report.BlockedEvents++
			s.logger.Warn("Blocking SSE event due to inspection error (fail-closed)",
				"event_id", event.ID,
				"error", err,
			)
			return nil // Don't forward the event
		}
		// Fail-open: forward unchanged
		report.AllowedEvents++
		serialized := bridge.SerializeSSEEvent(event)
		if _, writeErr := writer.Write(serialized); writeErr != nil {
			return fmt.Errorf("failed to write event after inspection error: %w", writeErr)
		}
		return nil
	}

	// Handle inspection result
	switch result.Action {
	case "allow":
		report.AllowedEvents++
		serialized := bridge.SerializeSSEEvent(event)
		if _, err := writer.Write(serialized); err != nil {
			return fmt.Errorf("failed to write allowed event: %w", err)
		}

	case "block":
		report.BlockedEvents++
		report.BlockedMethods = append(report.BlockedMethods, s.extractMethod(event.Data))
		s.logger.Warn("Blocked SSE event by policy",
			"event_id", event.ID,
			"reason", result.Reason,
		)
		// Don't forward blocked events

	case "redact":
		report.RedactedEvents++
		// Use modified data if provided
		if len(result.ModifiedData) > 0 {
			event.Data = result.ModifiedData
		}
		serialized := bridge.SerializeSSEEvent(event)
		if _, err := writer.Write(serialized); err != nil {
			return fmt.Errorf("failed to write redacted event: %w", err)
		}
		s.logger.Info("Redacted SSE event by policy",
			"event_id", event.ID,
			"reason", result.Reason,
		)

	default:
		// Unknown action, treat based on fail-closed setting
		if s.config.FailClosed {
			report.BlockedEvents++
			s.logger.Warn("Blocking SSE event due to unknown action (fail-closed)",
				"event_id", event.ID,
				"action", result.Action,
			)
			return nil
		}
		report.AllowedEvents++
		serialized := bridge.SerializeSSEEvent(event)
		if _, err := writer.Write(serialized); err != nil {
			return fmt.Errorf("failed to write event with unknown action: %w", err)
		}
	}

	return nil
}

// buildInspectContext creates inspection context from pipeline context
func (s *SSEStreamInspector) buildInspectContext(pipelineCtx *domain.PipelineContext) *bridge.InspectContext {
	if pipelineCtx == nil {
		return nil
	}

	return &bridge.InspectContext{
		SessionID: pipelineCtx.Request.SessionID,
		AgentID:   pipelineCtx.Request.AgentID,
	}
}

// extractMethod extracts the JSON-RPC method from event data for logging
func (s *SSEStreamInspector) extractMethod(data []byte) string {
	_, msg, err := bridge.ClassifyJSONRPC(data)
	if err != nil || msg == nil {
		return "unknown"
	}
	return msg.Method
}

// InspectEvent inspects a single SSE event and returns the inspection result
// This is a convenience method for use in the egress handler
func (s *SSEStreamInspector) InspectEvent(ctx context.Context, event *bridge.SSEEvent) (*bridge.InspectionResult, error) {
	inspectCtx := &bridge.InspectContext{}
	return s.inspector.InspectWithContext(ctx, event, s.config.ToolID, inspectCtx)
}

// SSEInspectionReport contains statistics about SSE stream inspection
type SSEInspectionReport struct {
	TotalEvents    int      `json:"total_events"`
	AllowedEvents  int      `json:"allowed_events"`
	BlockedEvents  int      `json:"blocked_events"`
	RedactedEvents int      `json:"redacted_events"`
	ParseErrors    int      `json:"parse_errors"`
	BlockedMethods []string `json:"blocked_methods,omitempty"`
}

// PolicyEngineAdapter adapts the policy.Engine to the bridge.PolicyEngine interface
type PolicyEngineAdapter struct {
	engine policy.Filter
}

// NewPolicyEngineAdapter creates a new adapter for the policy engine
func NewPolicyEngineAdapter(engine policy.Filter) *PolicyEngineAdapter {
	return &PolicyEngineAdapter{engine: engine}
}

// Evaluate implements bridge.PolicyEngine
func (a *PolicyEngineAdapter) Evaluate(ctx context.Context, input policy.Input) (policy.Decision, error) {
	return a.engine.Evaluate(ctx, input)
}

// ExtractSSEInspectorConfig extracts SSE inspector configuration from node config
func ExtractSSEInspectorConfig(nodeConfig map[string]interface{}) *SSEInspectorConfig {
	config := DefaultSSEInspectorConfig()

	if nodeConfig == nil {
		return config
	}

	// Check for sse_inspection configuration
	sseConfig, ok := nodeConfig["sse_inspection"].(map[string]interface{})
	if !ok {
		return config
	}

	if enabled, ok := sseConfig["enabled"].(bool); ok {
		config.Enabled = enabled
	}

	if entrypoint, ok := sseConfig["entrypoint"].(string); ok && entrypoint != "" {
		config.Entrypoint = entrypoint
	}

	if failClosed, ok := sseConfig["fail_closed"].(bool); ok {
		config.FailClosed = failClosed
	}

	if toolID, ok := sseConfig["tool_id"].(string); ok {
		config.ToolID = toolID
	}

	return config
}
