package bridge

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// StructuredLogger provides enhanced logging capabilities for the bridge
type StructuredLogger struct {
	logger *slog.Logger
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(logger *slog.Logger) *StructuredLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &StructuredLogger{logger: logger}
}

// LogMessage logs a message processing event with structured fields
func (sl *StructuredLogger) LogMessage(ctx context.Context, direction, method string, duration time.Duration, success bool, errorType string) {
	attrs := []slog.Attr{
		slog.String("direction", direction),
		slog.String("method", method),
		slog.Duration("duration", duration),
		slog.Bool("success", success),
	}

	if !success && errorType != "" {
		attrs = append(attrs, slog.String("error_type", errorType))
	}

	// Extract trace information from context if available
	if traceID := getTraceID(ctx); traceID != "" {
		attrs = append(attrs, slog.String("trace_id", traceID))
	}
	if spanID := getSpanID(ctx); spanID != "" {
		attrs = append(attrs, slog.String("span_id", spanID))
	}

	if success {
		sl.logger.LogAttrs(ctx, slog.LevelInfo, "Message processed", attrs...)
	} else {
		sl.logger.LogAttrs(ctx, slog.LevelError, "Message processing failed", attrs...)
	}
}

// LogSecurityEvent logs a security-related event (policy violations, etc.)
func (sl *StructuredLogger) LogSecurityEvent(ctx context.Context, eventType, method, action, reason string, toolID string) {
	attrs := []slog.Attr{
		slog.String("event_type", eventType),
		slog.String("method", method),
		slog.String("action", action),
		slog.String("reason", reason),
	}

	if toolID != "" {
		attrs = append(attrs, slog.String("tool_id", toolID))
	}

	// Extract trace information from context if available
	if traceID := getTraceID(ctx); traceID != "" {
		attrs = append(attrs, slog.String("trace_id", traceID))
	}
	if spanID := getSpanID(ctx); spanID != "" {
		attrs = append(attrs, slog.String("span_id", spanID))
	}

	level := slog.LevelInfo
	if action == "block" {
		level = slog.LevelWarn
	}

	sl.logger.LogAttrs(ctx, level, "Security event", attrs...)
}

// LogSessionEvent logs session-related events
func (sl *StructuredLogger) LogSessionEvent(ctx context.Context, eventType, sessionID, agentID string, duration *time.Duration) {
	attrs := []slog.Attr{
		slog.String("event_type", eventType),
		slog.String("session_id", sessionID),
		slog.String("agent_id", agentID),
	}

	if duration != nil {
		attrs = append(attrs, slog.Duration("duration", *duration))
	}

	// Extract trace information from context if available
	if traceID := getTraceID(ctx); traceID != "" {
		attrs = append(attrs, slog.String("trace_id", traceID))
	}

	sl.logger.LogAttrs(ctx, slog.LevelInfo, "Session event", attrs...)
}

// LogProcessEvent logs process-related events
func (sl *StructuredLogger) LogProcessEvent(ctx context.Context, eventType, command string, pid int, exitCode *int) {
	attrs := []slog.Attr{
		slog.String("event_type", eventType),
		slog.String("command", command),
	}

	if pid > 0 {
		attrs = append(attrs, slog.Int("pid", pid))
	}
	if exitCode != nil {
		attrs = append(attrs, slog.Int("exit_code", *exitCode))
	}

	// Extract trace information from context if available
	if traceID := getTraceID(ctx); traceID != "" {
		attrs = append(attrs, slog.String("trace_id", traceID))
	}

	level := slog.LevelInfo
	if eventType == "process_failed" || (exitCode != nil && *exitCode != 0) {
		level = slog.LevelError
	}

	sl.logger.LogAttrs(ctx, level, "Process event", attrs...)
}

// LogHTTPRequest logs HTTP request details
func (sl *StructuredLogger) LogHTTPRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration, agentID string) {
	attrs := []slog.Attr{
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status_code", statusCode),
		slog.Duration("duration", duration),
	}

	if agentID != "" {
		attrs = append(attrs, slog.String("agent_id", agentID))
	}

	// Extract trace information from context if available
	if traceID := getTraceID(ctx); traceID != "" {
		attrs = append(attrs, slog.String("trace_id", traceID))
	}
	if spanID := getSpanID(ctx); spanID != "" {
		attrs = append(attrs, slog.String("span_id", spanID))
	}

	level := slog.LevelInfo
	if statusCode >= 400 {
		level = slog.LevelWarn
	}
	if statusCode >= 500 {
		level = slog.LevelError
	}

	sl.logger.LogAttrs(ctx, level, "HTTP request", attrs...)
}

// Helper functions to extract trace information from context

func getTraceID(ctx context.Context) string {
	// Extract trace ID from OpenTelemetry span context
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	return span.SpanContext().TraceID().String()
}

func getSpanID(ctx context.Context) string {
	// Extract span ID from OpenTelemetry span context
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	return span.SpanContext().SpanID().String()
}