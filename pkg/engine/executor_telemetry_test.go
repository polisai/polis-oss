package engine

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type telemetryStubHandler struct{}

func (h *telemetryStubHandler) Execute(_ context.Context, _ *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	if pipelineCtx != nil {
		pipelineCtx.Security.Blocked = true
		pipelineCtx.Security.BlockReason = "WAF_BLOCK"
		pipelineCtx.Security.Findings = append(pipelineCtx.Security.Findings, domain.SecurityFinding{
			Source:   "waf",
			RuleID:   "waf-block",
			Severity: "high",
			Action:   "block",
		})
		pipelineCtx.Security.Violations = append(pipelineCtx.Security.Violations, domain.Violation{Code: "waf:block"})
	}
	// Ensure the handler takes a measurable amount of time so duration metrics record a sample.
	time.Sleep(2 * time.Millisecond)
	return runtime.Success(nil), nil
}

func TestExecutePipelineEmitsTelemetry(t *testing.T) {
	ctx := context.Background()
	recorder, tracerCleanup := setupTestTracer(t)
	defer tracerCleanup()

	reader, meterCleanup := setupTestMeter(t)
	defer meterCleanup()

	telemetry.ResetMetricsForTest()

	executor := newTelemetryTestExecutor()

	pipeline := &domain.Pipeline{
		ID:       "pipeline-test",
		Version:  7,
		AgentID:  "agent-xyz",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{ID: "node-1", Type: "test.success@v1"},
		},
	}

	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:        "POST",
			Path:          "/sensitive/path",
			Host:          "api.example.com",
			Protocol:      "http",
			AgentID:       "agent-xyz",
			SessionID:     "sess-123",
			Streaming:     true,
			StreamingMode: "sse",
			Headers: map[string][]string{
				"Authorization": {"Bearer secret"},
			},
		},
		Telemetry: domain.TelemetryContext{
			Taints: map[string]domain.TelemetryTaint{
				"http.route": {
					Attribute: "http.route",
					Reason:    "pii",
				},
			},
		},
	}

	if err := executor.executePipeline(ctx, pipeline, pipelineCtx); err != nil {
		t.Fatalf("executePipeline: %v", err)
	}

	pipelineSpan, nodeSpan := findTelemetrySpans(t, recorder.Ended())
	assertPipelineSpan(t, pipelineSpan)
	assertNodeSpan(t, nodeSpan)
	assertSecurityEvent(t, nodeSpan)

	metrics := collectTelemetryMetrics(ctx, reader, t)
	execMetric := getMetric(t, metrics, "proxy.node.executions_total")
	assertExecutionMetric(t, execMetric)
	durationMetric := getMetric(t, metrics, "proxy.node.duration_ms")
	assertDurationMetric(t, durationMetric)
}

func setupTestTracer(t *testing.T) (*tracetest.SpanRecorder, func()) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	prevTracer := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	return recorder, func() {
		otel.SetTracerProvider(prevTracer)
		if err := tp.Shutdown(context.Background()); err != nil {
			t.Logf("tracer provider shutdown: %v", err)
		}
	}
}

func setupTestMeter(t *testing.T) (*sdkmetric.ManualReader, func()) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prevMeter := otel.GetMeterProvider()
	otel.SetMeterProvider(meterProvider)
	return reader, func() {
		otel.SetMeterProvider(prevMeter)
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Logf("meter provider shutdown: %v", err)
		}
	}
}

func newTelemetryTestExecutor() *DAGExecutor {
	executor := NewDAGExecutor(DAGExecutorConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	executor.RegisterHandler("test.success@v1", &telemetryStubHandler{})
	return executor
}

func findTelemetrySpans(t *testing.T, spans []sdktrace.ReadOnlySpan) (sdktrace.ReadOnlySpan, sdktrace.ReadOnlySpan) {
	t.Helper()
	var pipelineSpan, nodeSpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		switch span.Name() {
		case "pipeline.execute":
			pipelineSpan = span
		case "pipeline.node":
			nodeSpan = span
		}
	}
	if pipelineSpan == nil {
		t.Fatalf("expected pipeline span")
	}
	if nodeSpan == nil {
		t.Fatalf("expected node span")
	}
	return pipelineSpan, nodeSpan
}

func assertPipelineSpan(t *testing.T, span sdktrace.ReadOnlySpan) {
	t.Helper()
	attrs := attribute.NewSet(span.Attributes()...)
	assertStringAttr(t, attrs, "pipeline.id", "pipeline-test")
	assertInt64Attr(t, attrs, "pipeline.version", 7)
	assertStringAttr(t, attrs, "agent.id", "agent-xyz")
	assertStringAttr(t, attrs, "protocol.name", "http")
	if _, ok := attrs.Value(attribute.Key("http.route")); ok {
		t.Fatalf("http.route attribute should have been redacted")
	}
	assertBoolAttr(t, attrs, "request.streaming", true)
	assertStringAttr(t, attrs, "request.streaming_mode", "sse")
}

func assertNodeSpan(t *testing.T, span sdktrace.ReadOnlySpan) {
	t.Helper()
	attrs := attribute.NewSet(span.Attributes()...)
	assertStringAttr(t, attrs, "node.kind", "test.success")
	assertStringAttr(t, attrs, "node.version", "v1")
	assertStringAttr(t, attrs, "node.outcome", string(runtime.OutcomeSuccess))
	assertInt64Attr(t, attrs, "node.retry.count", 0)
	assertStringAttr(t, attrs, "pipeline.id", "pipeline-test")
}

func assertSecurityEvent(t *testing.T, span sdktrace.ReadOnlySpan) {
	t.Helper()
	for _, event := range span.Events() {
		if event.Name != "security.event" {
			continue
		}
		attrs := attribute.NewSet(event.Attributes...)
		assertBoolAttr(t, attrs, "security.blocked", true)
		assertStringAttr(t, attrs, "security.block_reason", "WAF_BLOCK")
		return
	}
	t.Fatalf("expected security.event on node span")
}

func assertStringAttr(t *testing.T, attrs attribute.Set, key, want string) {
	t.Helper()
	value, ok := attrs.Value(attribute.Key(key))
	if !ok || value.AsString() != want {
		t.Fatalf("unexpected %s attribute: %v", key, value)
	}
}

func assertInt64Attr(t *testing.T, attrs attribute.Set, key string, want int64) {
	t.Helper()
	value, ok := attrs.Value(attribute.Key(key))
	if !ok || value.AsInt64() != want {
		t.Fatalf("unexpected %s attribute: %v", key, value)
	}
}

func assertBoolAttr(t *testing.T, attrs attribute.Set, key string, want bool) {
	t.Helper()
	value, ok := attrs.Value(attribute.Key(key))
	if !ok || value.AsBool() != want {
		t.Fatalf("unexpected %s attribute: %v", key, value)
	}
}

func collectTelemetryMetrics(ctx context.Context, reader *sdkmetric.ManualReader, t *testing.T) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	metrics := make(map[string]metricdata.Metrics)
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			metrics[m.Name] = m
		}
	}
	return metrics
}

func getMetric(t *testing.T, metrics map[string]metricdata.Metrics, name string) metricdata.Metrics {
	t.Helper()
	metric, ok := metrics[name]
	if !ok {
		t.Fatalf("missing %s metric", name)
	}
	return metric
}

func assertExecutionMetric(t *testing.T, metric metricdata.Metrics) {
	t.Helper()
	data, ok := metric.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("unexpected executions metric data type %T", metric.Data)
	}
	if len(data.DataPoints) != 1 {
		t.Fatalf("expected 1 executions datapoint, got %d", len(data.DataPoints))
	}
	dp := data.DataPoints[0]
	if dp.Value != 1 {
		t.Fatalf("expected executions count 1, got %d", dp.Value)
	}
	assertStringAttr(t, dp.Attributes, "node.kind", "test.success")
}

func assertDurationMetric(t *testing.T, metric metricdata.Metrics) {
	t.Helper()
	data, ok := metric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("unexpected duration metric data type %T", metric.Data)
	}
	if len(data.DataPoints) != 1 {
		t.Fatalf("expected 1 duration datapoint, got %d", len(data.DataPoints))
	}
	if data.DataPoints[0].Count != 1 {
		t.Fatalf("expected duration count 1, got %d", data.DataPoints[0].Count)
	}
}
