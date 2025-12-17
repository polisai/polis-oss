package bridge

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// TracingManager handles OpenTelemetry tracing setup and operations
type TracingManager struct {
	tracer     trace.Tracer
	propagator propagation.TextMapPropagator
	enabled    bool
}

// NewTracingManager creates a new tracing manager
func NewTracingManager(config *TracingConfig) (*TracingManager, error) {
	if config == nil || !config.Enabled {
		return &TracingManager{enabled: false}, nil
	}

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create OTLP exporter
	exporter, err := otlptracegrpc.New(
		context.Background(),
		otlptracegrpc.WithEndpoint(config.Endpoint),
		otlptracegrpc.WithInsecure(), // Use insecure for local development
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create trace provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Set global trace provider
	otel.SetTracerProvider(tp)

	// Set global propagator
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(propagator)

	// Create tracer
	tracer := tp.Tracer("polis-bridge")

	return &TracingManager{
		tracer:     tracer,
		propagator: propagator,
		enabled:    true,
	}, nil
}

// StartSpan starts a new span with the given name and attributes
func (tm *TracingManager) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if !tm.enabled {
		return ctx, trace.SpanFromContext(ctx)
	}

	return tm.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// InjectHTTPHeaders injects trace context into HTTP headers
func (tm *TracingManager) InjectHTTPHeaders(ctx context.Context, headers http.Header) {
	if !tm.enabled {
		return
	}

	tm.propagator.Inject(ctx, propagation.HeaderCarrier(headers))
}

// ExtractHTTPHeaders extracts trace context from HTTP headers
func (tm *TracingManager) ExtractHTTPHeaders(ctx context.Context, headers http.Header) context.Context {
	if !tm.enabled {
		return ctx
	}

	return tm.propagator.Extract(ctx, propagation.HeaderCarrier(headers))
}

// InjectProcessEnv injects trace context into process environment variables
func (tm *TracingManager) InjectProcessEnv(ctx context.Context, env []string) []string {
	if !tm.enabled {
		return env
	}

	// Create a map carrier for environment variables
	envMap := make(map[string]string)
	for _, e := range env {
		if idx := findEquals(e); idx >= 0 {
			key := e[:idx]
			value := e[idx+1:]
			envMap[key] = value
		}
	}

	// Inject trace context
	tm.propagator.Inject(ctx, &envMapCarrier{envMap})

	// Convert back to slice
	result := make([]string, 0, len(envMap))
	for k, v := range envMap {
		result = append(result, k+"="+v)
	}

	return result
}

// ExtractProcessEnv extracts trace context from process environment variables
func (tm *TracingManager) ExtractProcessEnv(ctx context.Context, env []string) context.Context {
	if !tm.enabled {
		return ctx
	}

	// Create a map carrier for environment variables
	envMap := make(map[string]string)
	for _, e := range env {
		if idx := findEquals(e); idx >= 0 {
			key := e[:idx]
			value := e[idx+1:]
			envMap[key] = value
		}
	}

	// Extract trace context
	return tm.propagator.Extract(ctx, &envMapCarrier{envMap})
}

// AddSpanAttributes adds attributes to the current span
func (tm *TracingManager) AddSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	if !tm.enabled {
		return
	}

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}

// RecordError records an error on the current span
func (tm *TracingManager) RecordError(ctx context.Context, err error) {
	if !tm.enabled || err == nil {
		return
	}

	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
}

// SetSpanStatus sets the status of the current span
func (tm *TracingManager) SetSpanStatus(ctx context.Context, code codes.Code, description string) {
	if !tm.enabled {
		return
	}

	span := trace.SpanFromContext(ctx)
	span.SetStatus(code, description)
}

// GetTraceID returns the trace ID from the current span context
func (tm *TracingManager) GetTraceID(ctx context.Context) string {
	if !tm.enabled {
		return ""
	}

	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}

	return span.SpanContext().TraceID().String()
}

// GetSpanID returns the span ID from the current span context
func (tm *TracingManager) GetSpanID(ctx context.Context) string {
	if !tm.enabled {
		return ""
	}

	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}

	return span.SpanContext().SpanID().String()
}

// envMapCarrier implements propagation.TextMapCarrier for environment variables
type envMapCarrier struct {
	env map[string]string
}

func (c *envMapCarrier) Get(key string) string {
	return c.env[key]
}

func (c *envMapCarrier) Set(key, value string) {
	c.env[key] = value
}

func (c *envMapCarrier) Keys() []string {
	keys := make([]string, 0, len(c.env))
	for k := range c.env {
		keys = append(keys, k)
	}
	return keys
}

// findEquals finds the first occurrence of '=' in a string
func findEquals(s string) int {
	for i, c := range s {
		if c == '=' {
			return i
		}
	}
	return -1
}

// HTTPMiddleware creates middleware that adds tracing to HTTP requests
func (tm *TracingManager) HTTPMiddleware(next http.Handler) http.Handler {
	if !tm.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract trace context from headers
		ctx := tm.ExtractHTTPHeaders(r.Context(), r.Header)

		// Start span for HTTP request
		ctx, span := tm.StartSpan(ctx, "http_request",
			attribute.String("http.method", r.Method),
			attribute.String("http.url", r.URL.String()),
			attribute.String("http.scheme", r.URL.Scheme),
			attribute.String("http.host", r.Host),
		)
		defer span.End()

		// Update request context
		r = r.WithContext(ctx)

		// Wrap response writer to capture status code
		wrapped := &tracingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call next handler
		next.ServeHTTP(wrapped, r)

		// Add response attributes
		span.SetAttributes(
			attribute.Int("http.status_code", wrapped.statusCode),
		)

		// Set span status based on HTTP status code
		if wrapped.statusCode >= 400 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", wrapped.statusCode))
		} else {
			span.SetStatus(codes.Ok, "")
		}
	})
}

// tracingResponseWriter wraps http.ResponseWriter to capture status code
type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *tracingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}