package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestRecordNodeMetrics(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(prev)
	})

	ResetMetricsForTest()

	RecordNodeMetrics(ctx, NodeMetrics{
		PipelineID:      "pipeline-123",
		PipelineVersion: 2,
		AgentID:         "agent-abc",
		Protocol:        "http",
		NodeID:          "node-1",
		NodeKind:        "egress.http",
		NodeVersion:     "v2",
		Outcome:         runtime.OutcomeTimeout,
		Duration:        150 * time.Millisecond,
		Retries:         1,
	})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

	metrics := map[string]metricdata.Metrics{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			metrics[m.Name] = m
		}
	}

	sumExec, ok := metrics["proxy.node.executions_total"]
	if !ok {
		t.Fatalf("missing proxy.node.executions metric")
	}
	execData, ok := sumExec.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("unexpected data type for executions metric")
	}
	if len(execData.DataPoints) != 1 {
		t.Fatalf("expected 1 datapoint, got %d", len(execData.DataPoints))
	}
	if execData.DataPoints[0].Value != 1 {
		t.Fatalf("expected executions count 1, got %d", execData.DataPoints[0].Value)
	}
	if value, ok := execData.DataPoints[0].Attributes.Value(attribute.Key("node.kind")); !ok || value.AsString() != "egress.http" {
		t.Fatalf("expected node.kind attribute to be egress.http, got %v", value)
	}

	sumRetry, ok := metrics["proxy.node.retries_total"]
	if !ok {
		t.Fatalf("missing proxy.node.retries metric")
	}
	retryData := sumRetry.Data.(metricdata.Sum[int64])
	if retryData.DataPoints[0].Value != 1 {
		t.Fatalf("expected retry count 1, got %d", retryData.DataPoints[0].Value)
	}

	sumTimeout, ok := metrics["proxy.node.timeout_total"]
	if !ok {
		t.Fatalf("missing proxy.node.timeouts metric")
	}
	timeoutData := sumTimeout.Data.(metricdata.Sum[int64])
	if timeoutData.DataPoints[0].Value != 1 {
		t.Fatalf("expected timeout count 1, got %d", timeoutData.DataPoints[0].Value)
	}

	hist, ok := metrics["proxy.node.duration_ms"]
	if !ok {
		t.Fatalf("missing proxy.node.duration_ms metric")
	}
	histData := hist.Data.(metricdata.Histogram[float64])
	if histData.DataPoints[0].Count != 1 {
		t.Fatalf("expected histogram count 1, got %d", histData.DataPoints[0].Count)
	}
	if histData.DataPoints[0].Sum != 150 {
		t.Fatalf("expected histogram sum 150, got %v", histData.DataPoints[0].Sum)
	}
}

func TestRecordSecurityEvent(t *testing.T) {
	t.Helper()

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider()
	tp.RegisterSpanProcessor(recorder)
	tracer := tp.Tracer("test")

	_, span := tracer.Start(context.Background(), "node")
	RecordSecurityEvent(span, true, "blocked", 2, 1)
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	events := spans[0].Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 security event, got %d", len(events))
	}
	event := events[0]
	if event.Name != "security.event" {
		t.Fatalf("unexpected event name %q", event.Name)
	}

	attrs := attribute.NewSet(event.Attributes...)
	if value, ok := attrs.Value(attribute.Key("security.blocked")); !ok || !value.AsBool() {
		t.Fatalf("expected security.blocked attribute true")
	}
	if value, ok := attrs.Value(attribute.Key("security.block_reason")); !ok || value.AsString() != "blocked" {
		t.Fatalf("expected block_reason 'blocked', got %v", value)
	}
	if value, ok := attrs.Value(attribute.Key("security.violations.count")); !ok || value.AsInt64() != 1 {
		t.Fatalf("expected violations count 1, got %v", value)
	}
	if value, ok := attrs.Value(attribute.Key("security.findings.count")); !ok || value.AsInt64() != 2 {
		t.Fatalf("expected findings count 2, got %v", value)
	}

	if err := tp.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown tracer provider: %v", err)
	}
}
