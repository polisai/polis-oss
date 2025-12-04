package domain

import (
	"context"
	"time"
)

// TelemetryEvent represents an enriched observability event.
type TelemetryEvent struct {
	TraceID       string
	SpanID        string
	Protocol      string
	SessionID     string
	UserIdentity  string
	AgentID       string
	PolicyID      string
	RouteID       string
	ViolationCode string
	ResourceCost  float64
	Timestamp     time.Time
	Attributes    map[string]any
}

// TelemetryService defines the interface for telemetry operations.
type TelemetryService interface {
	// Emit sends a telemetry event.
	Emit(ctx context.Context, event TelemetryEvent) error

	// EnrichContext adds telemetry attributes to context.
	EnrichContext(ctx context.Context, attrs map[string]any) context.Context
}
