package engine

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/polisai/polis-oss/pkg/bridge"
	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/handlers"
	"github.com/polisai/polis-oss/pkg/policy/dlp"
)

// getDLPPosture retrieves the DLP failure posture from the pipeline context.
// Returns "fail-open" by default if not specified.
func getDLPPosture(pipelineCtx *domain.PipelineContext) string {
	if posture, ok := pipelineCtx.Variables["dlp.posture"].(string); ok && posture != "" {
		return posture
	}
	return "fail-open"
}

// redactSSEStream reads from src, parses SSE data fields, applies DLP/redaction, and writes to dst.
// It maintains the SSE framing (data: prefix) to ensure protocol compliance.
func redactSSEStream(ctx context.Context, src io.Reader, dst *flushCountingWriter, cfg dlp.Config) (dlp.Report, error) {
	scanner, err := dlp.NewScanner(cfg)
	if err != nil {
		return dlp.Report{}, err
	}

	sseScanner := bufio.NewScanner(src)
	// Support large SSE events (up to 10MB)
	buf := make([]byte, 64*1024)
	sseScanner.Buffer(buf, 10*1024*1024)

	var combinedReport dlp.Report

	for sseScanner.Scan() {
		line := sseScanner.Text()

		// Only inspect "data:" fields, ignore "id:", "event:", "retry:" etc. to avoid breaking protocol
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimPrefix(line, "data:")

			// SSE spec: remove single leading space if present
			content := payload
			hasLeadingSpace := false
			if strings.HasPrefix(payload, " ") {
				content = strings.TrimPrefix(payload, " ")
				hasLeadingSpace = true
			}

			// Scan the content
			report, err := scanner.Scan(ctx, content)
			if err != nil {
				// In stream mode, regex errors usually mean we can't redact.
				// We return the error so the caller can decide based on posture.
				return combinedReport, err
			}

			if report.Blocked {
				combinedReport.Blocked = true
				return combinedReport, nil // Block immediately
			}

			// Aggregate findings
			combinedReport.Findings = append(combinedReport.Findings, report.Findings...)
			combinedReport.RedactionsApplied = combinedReport.RedactionsApplied || report.RedactionsApplied

			if report.RedactionsApplied {
				// Reconstruct line
				prefix := "data:"
				if hasLeadingSpace {
					prefix += " "
				}
				line = prefix + report.Redacted
			}
		}

		if _, err := dst.Write([]byte(line + "\n")); err != nil {
			return combinedReport, err
		}
	}

	return combinedReport, sseScanner.Err()
}


// SSEInspectionConfig holds configuration for SSE stream inspection in egress
type SSEInspectionConfig struct {
	Enabled      bool
	PolicyEngine bridge.PolicyEngine
	ToolID       string
	Entrypoint   string
	FailClosed   bool
}

// inspectAndRedactSSEStream combines SSE inspection (for server-initiated requests)
// with DLP redaction. It processes SSE events, inspects them against policies,
// and applies DLP redaction to allowed events.
//
// This implements Requirements 3.1, 3.2, 3.3, 3.4, 3.5:
// - 3.1: Parse SSE events from upstream response
// - 3.2: Evaluate server-initiated requests against policy
// - 3.3: Drop blocked events and log violations
// - 3.4: Forward allowed events unchanged
// - 3.5: Forward unparseable events unchanged with warning
func inspectAndRedactSSEStream(
	ctx context.Context,
	src io.Reader,
	dst *flushCountingWriter,
	dlpCfg *dlp.Config,
	inspectCfg *SSEInspectionConfig,
	pipelineCtx *domain.PipelineContext,
	logger *slog.Logger,
) (dlp.Report, *handlers.SSEInspectionReport, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var dlpScanner *dlp.Scanner
	var dlpErr error
	dlpEnabled := dlpCfg != nil && len(dlpCfg.Rules) > 0

	if dlpEnabled {
		dlpScanner, dlpErr = dlp.NewScanner(*dlpCfg)
		if dlpErr != nil {
			return dlp.Report{}, nil, dlpErr
		}
	}

	inspectionEnabled := inspectCfg != nil && inspectCfg.Enabled

	// If neither inspection nor DLP is enabled, just copy the stream
	if !inspectionEnabled && !dlpEnabled {
		_, err := io.Copy(dst, src)
		return dlp.Report{}, nil, err
	}

	// Create stream inspector if enabled
	var inspector *handlers.SSEStreamInspector
	if inspectionEnabled {
		sseInspectorConfig := &handlers.SSEInspectorConfig{
			Enabled:    true,
			Entrypoint: inspectCfg.Entrypoint,
			FailClosed: inspectCfg.FailClosed,
			ToolID:     inspectCfg.ToolID,
		}
		if sseInspectorConfig.Entrypoint == "" {
			sseInspectorConfig.Entrypoint = bridge.DefaultElicitationEntrypoint
		}
		inspector = handlers.NewSSEStreamInspector(inspectCfg.PolicyEngine, sseInspectorConfig, logger)
	}

	sseScanner := bufio.NewScanner(src)
	// Support large SSE events (up to 10MB)
	buf := make([]byte, 64*1024)
	sseScanner.Buffer(buf, 10*1024*1024)

	var combinedDLPReport dlp.Report
	inspectionReport := &handlers.SSEInspectionReport{}

	var eventBuffer bytes.Buffer

	for sseScanner.Scan() {
		line := sseScanner.Text()

		// Add line to buffer
		eventBuffer.WriteString(line)
		eventBuffer.WriteString("\n")

		// Check if this is an empty line (end of event)
		if strings.TrimSpace(line) == "" {
			// Process the complete event
			if eventBuffer.Len() > 1 {
				eventData := eventBuffer.Bytes()
				processedData, shouldForward, err := processSSEEventWithInspection(
					ctx, eventData, inspector, dlpScanner, inspectionReport, &combinedDLPReport, inspectCfg, logger,
				)
				if err != nil {
					logger.Warn("Error processing SSE event",
						"error", err,
					)
					// Forward original event on error (fail-open for processing errors)
					if _, writeErr := dst.Write(eventData); writeErr != nil {
						return combinedDLPReport, inspectionReport, writeErr
					}
				} else if shouldForward {
					if _, writeErr := dst.Write(processedData); writeErr != nil {
						return combinedDLPReport, inspectionReport, writeErr
					}
				}
				eventBuffer.Reset()
			}
		}
	}

	// Handle any remaining data in buffer
	if eventBuffer.Len() > 0 {
		eventData := eventBuffer.Bytes()
		processedData, shouldForward, err := processSSEEventWithInspection(
			ctx, eventData, inspector, dlpScanner, inspectionReport, &combinedDLPReport, inspectCfg, logger,
		)
		if err != nil {
			logger.Warn("Error processing final SSE event",
				"error", err,
			)
			if _, writeErr := dst.Write(eventData); writeErr != nil {
				return combinedDLPReport, inspectionReport, writeErr
			}
		} else if shouldForward {
			if _, writeErr := dst.Write(processedData); writeErr != nil {
				return combinedDLPReport, inspectionReport, writeErr
			}
		}
	}

	return combinedDLPReport, inspectionReport, sseScanner.Err()
}

// processSSEEventWithInspection processes a single SSE event through inspection and DLP
func processSSEEventWithInspection(
	ctx context.Context,
	eventData []byte,
	inspector *handlers.SSEStreamInspector,
	dlpScanner *dlp.Scanner,
	inspectionReport *handlers.SSEInspectionReport,
	dlpReport *dlp.Report,
	inspectCfg *SSEInspectionConfig,
	logger *slog.Logger,
) ([]byte, bool, error) {
	inspectionReport.TotalEvents++

	// Parse the SSE event
	event, parseErr := bridge.ParseSSEEvent(eventData)
	if parseErr != nil {
		// Forward unparseable events unchanged (Requirement 3.5)
		logger.Warn("Failed to parse SSE event, forwarding unchanged",
			"error", parseErr,
		)
		inspectionReport.ParseErrors++
		return eventData, true, nil
	}

	// If inspection is enabled, check if this is a server-initiated request
	if inspector != nil && len(event.Data) > 0 {
		result, err := inspector.InspectEvent(ctx, event)
		if err != nil {
			logger.Error("SSE event inspection failed",
				"error", err,
				"event_id", event.ID,
			)
			// Apply fail-closed/fail-open behavior
			if inspectCfg != nil && inspectCfg.FailClosed {
				inspectionReport.BlockedEvents++
				return nil, false, nil
			}
			// Fail-open: continue processing
		} else {
			switch result.Action {
			case "block":
				inspectionReport.BlockedEvents++
				logger.Warn("Blocked SSE event by policy",
					"event_id", event.ID,
					"reason", result.Reason,
				)
				return nil, false, nil

			case "redact":
				inspectionReport.RedactedEvents++
				if len(result.ModifiedData) > 0 {
					event.Data = result.ModifiedData
				}
				logger.Info("Redacted SSE event by policy",
					"event_id", event.ID,
					"reason", result.Reason,
				)

			case "allow":
				inspectionReport.AllowedEvents++
				// Continue to DLP processing
			}
		}
	} else {
		inspectionReport.AllowedEvents++
	}

	// Apply DLP redaction if enabled
	if dlpScanner != nil && len(event.Data) > 0 {
		content := string(event.Data)
		report, err := dlpScanner.Scan(ctx, content)
		if err != nil {
			return nil, false, err
		}

		if report.Blocked {
			dlpReport.Blocked = true
			return nil, false, nil
		}

		dlpReport.Findings = append(dlpReport.Findings, report.Findings...)
		dlpReport.RedactionsApplied = dlpReport.RedactionsApplied || report.RedactionsApplied

		if report.RedactionsApplied {
			event.Data = []byte(report.Redacted)
		}
	}

	// Serialize the event back
	serialized := bridge.SerializeSSEEvent(event)
	return serialized, true, nil
}


// extractSSEInspectionConfig extracts SSE inspection configuration from pipeline context
func extractSSEInspectionConfig(pipelineCtx *domain.PipelineContext) *SSEInspectionConfig {
	if pipelineCtx == nil || pipelineCtx.Variables == nil {
		return nil
	}

	// Check if SSE inspection is enabled in pipeline context
	enabled, _ := pipelineCtx.Variables["sse_inspection.enabled"].(bool)
	if !enabled {
		return nil
	}

	config := &SSEInspectionConfig{
		Enabled:    true,
		FailClosed: true, // Default to fail-closed for security
	}

	// Extract policy engine if available
	if engine, ok := pipelineCtx.Variables["sse_inspection.policy_engine"].(bridge.PolicyEngine); ok {
		config.PolicyEngine = engine
	}

	// Extract tool ID
	if toolID, ok := pipelineCtx.Variables["sse_inspection.tool_id"].(string); ok {
		config.ToolID = toolID
	}

	// Extract entrypoint
	if entrypoint, ok := pipelineCtx.Variables["sse_inspection.entrypoint"].(string); ok {
		config.Entrypoint = entrypoint
	}

	// Extract fail-closed setting
	if failClosed, ok := pipelineCtx.Variables["sse_inspection.fail_closed"].(bool); ok {
		config.FailClosed = failClosed
	}

	return config
}

// recordSSEInspectionResults records SSE inspection results in the pipeline context
func recordSSEInspectionResults(pipelineCtx *domain.PipelineContext, report *handlers.SSEInspectionReport) {
	if pipelineCtx == nil || report == nil {
		return
	}

	if pipelineCtx.Variables == nil {
		pipelineCtx.Variables = make(map[string]interface{})
	}

	pipelineCtx.Variables["sse_inspection.total_events"] = report.TotalEvents
	pipelineCtx.Variables["sse_inspection.allowed_events"] = report.AllowedEvents
	pipelineCtx.Variables["sse_inspection.blocked_events"] = report.BlockedEvents
	pipelineCtx.Variables["sse_inspection.redacted_events"] = report.RedactedEvents
	pipelineCtx.Variables["sse_inspection.parse_errors"] = report.ParseErrors

	if len(report.BlockedMethods) > 0 {
		pipelineCtx.Variables["sse_inspection.blocked_methods"] = report.BlockedMethods
	}

	// Add security findings for blocked events
	if report.BlockedEvents > 0 {
		for _, method := range report.BlockedMethods {
			pipelineCtx.Security.Findings = append(pipelineCtx.Security.Findings, domain.SecurityFinding{
				Source:   "sse_inspection",
				RuleID:   "server_request_blocked",
				Severity: "high",
				Action:   "block",
				Summary:  "Server-initiated request blocked by policy: " + method,
				Metadata: map[string]interface{}{
					"method": method,
				},
			})
		}
	}
}
