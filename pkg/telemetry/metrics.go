package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	metricsOnce            sync.Once
	metricsInitErr         error
	nodeExecutionCounter   metric.Int64Counter
	nodeRetryCounter       metric.Int64Counter
	nodeCircuitOpenCounter metric.Int64Counter
	nodeRateLimitedCounter metric.Int64Counter
	nodeTimeoutCounter     metric.Int64Counter
	nodeLatencyHistogram   metric.Float64Histogram
)

// NodeMetrics captures the fields needed to record pipeline node telemetry metrics.
type NodeMetrics struct {
	PipelineID      string
	PipelineVersion int
	AgentID         string
	Protocol        string
	NodeID          string
	NodeKind        string
	NodeVersion     string
	Outcome         runtime.NodeOutcome
	Duration        time.Duration
	Retries         int
}

// RecordNodeMetrics emits counters and histograms that describe node execution behaviour.
func RecordNodeMetrics(ctx context.Context, metrics NodeMetrics) {
	if err := ensureMetrics(); err != nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("pipeline.id", metrics.PipelineID),
		attribute.Int("pipeline.version", metrics.PipelineVersion),
		attribute.String("agent.id", metrics.AgentID),
		attribute.String("protocol.name", metrics.Protocol),
		attribute.String("node.id", metrics.NodeID),
		attribute.String("node.kind", metrics.NodeKind),
		attribute.String("node.version", metrics.NodeVersion),
		attribute.String("node.outcome", string(metrics.Outcome)),
	}

	nodeExecutionCounter.Add(ctx, 1, metric.WithAttributes(attrs...))

	if metrics.Duration > 0 {
		nodeLatencyHistogram.Record(ctx, float64(metrics.Duration)/float64(time.Millisecond), metric.WithAttributes(attrs...))
	}

	if metrics.Retries > 0 {
		nodeRetryCounter.Add(ctx, int64(metrics.Retries), metric.WithAttributes(attrs...))
	}

	switch metrics.Outcome {
	case runtime.OutcomeCircuitOpen:
		nodeCircuitOpenCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	case runtime.OutcomeRateLimited:
		nodeRateLimitedCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	case runtime.OutcomeTimeout:
		nodeTimeoutCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

func ensureMetrics() error {
	metricsOnce.Do(func() {
		meter := otel.GetMeterProvider().Meter("proxy.pipeline")

		nodeExecutionCounter, metricsInitErr = meter.Int64Counter(
			"proxy.node.executions_total",
			metric.WithDescription("Pipeline node executions partitioned by outcome"),
			metric.WithUnit("{count}"),
		)
		if metricsInitErr != nil {
			return
		}

		nodeRetryCounter, metricsInitErr = meter.Int64Counter(
			"proxy.node.retries_total",
			metric.WithDescription("Retry attempts performed by pipeline nodes"),
			metric.WithUnit("{count}"),
		)
		if metricsInitErr != nil {
			return
		}

		nodeCircuitOpenCounter, metricsInitErr = meter.Int64Counter(
			"proxy.node.circuit_open_total",
			metric.WithDescription("Circuit breaker opens encountered during node execution"),
			metric.WithUnit("{count}"),
		)
		if metricsInitErr != nil {
			return
		}

		nodeRateLimitedCounter, metricsInitErr = meter.Int64Counter(
			"proxy.node.rate_limited_total",
			metric.WithDescription("Rate limited outcomes emitted by nodes"),
			metric.WithUnit("{count}"),
		)
		if metricsInitErr != nil {
			return
		}

		nodeTimeoutCounter, metricsInitErr = meter.Int64Counter(
			"proxy.node.timeout_total",
			metric.WithDescription("Timeout outcomes emitted by nodes"),
			metric.WithUnit("{count}"),
		)
		if metricsInitErr != nil {
			return
		}

		nodeLatencyHistogram, metricsInitErr = meter.Float64Histogram(
			"proxy.node.duration_ms",
			metric.WithDescription("Observed node execution latency"),
			metric.WithUnit("ms"),
		)
	})

	return metricsInitErr
}

// RecordSecurityEvent attaches a coarse-grained security event to the provided span without leaking sensitive data.
func RecordSecurityEvent(span trace.Span, blocked bool, reason string, findings int, violations int) {
	if span == nil || !span.IsRecording() {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.Bool("security.blocked", blocked),
		attribute.Int("security.findings.count", findings),
		attribute.Int("security.violations.count", violations),
	}

	if reason != "" {
		attrs = append(attrs, attribute.String("security.block_reason", reason))
	}

	span.AddEvent("security.event", trace.WithAttributes(attrs...))
}
