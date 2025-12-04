package telemetry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/polisai/polis-oss/pkg/domain"
)

// Config describes the telemetry bootstrap options.
type Config struct {
	ServiceName  string
	Endpoint     string
	Environment  string
	Insecure     bool
	Headers      map[string]string
	ResourceTags map[string]string
}

// SetupProvider initialises the process-wide OpenTelemetry tracer provider using
// the supplied configuration and returns a shutdown function that callers must
// invoke during graceful termination to flush buffered spans.
func SetupProvider(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if cfg.Endpoint == "" {
		// No endpoint configured, return no-op shutdown
		return func(context.Context) error { return nil }, nil
	}

	clientOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		clientOpts = append(clientOpts, otlptracegrpc.WithInsecure())
	} else {
		clientOpts = append(clientOpts, otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
	}
	if len(cfg.Headers) > 0 {
		clientOpts = append(clientOpts, otlptracegrpc.WithHeaders(cfg.Headers))
	}

	clientOpts = append(clientOpts, otlptracegrpc.WithDialOption(
		grpc.WithReturnConnectionError(), //nolint:staticcheck // Requested alternative to grpc.WithBlock for connection errors.
	))

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	exporter, err := otlptrace.New(dialCtx, otlptracegrpc.NewClient(clientOpts...))
	if err != nil {
		return nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	attrs := []attribute.KeyValue{semconv.ServiceName(cfg.ServiceName)}
	if cfg.Environment != "" {
		attrs = append(attrs, attribute.String("deployment.environment", cfg.Environment))
	}
	for k, v := range cfg.ResourceTags {
		attrs = append(attrs, attribute.String(k, v))
	}

	res, err := resource.New(ctx,
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithAttributes(attrs...),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithMaxExportBatchSize(100), sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)

	return provider.Shutdown, nil
}

// RedactAttributes applies a conservative redaction policy to telemetry attributes before export.
//
// The redaction strategy combines default deny-lists with taints recorded in the pipeline telemetry
// context. Taints result in attribute removal, while explicit redaction directives can mask values
// instead of dropping them entirely. Callers may pass a nil telemetry context to apply only the
// default deny-list.
func RedactAttributes(ctx *domain.TelemetryContext, attrs []attribute.KeyValue) []attribute.KeyValue {
	if len(attrs) == 0 {
		return attrs
	}

	dropKeys := map[string]struct{}{
		"http.request.header.authorization": {},
		"http.response.header.set_cookie":   {},
		"request.body":                      {},
		"response.body":                     {},
	}

	redactionStrategies := map[string]string{}

	if ctx != nil {
		for key := range ctx.Taints {
			dropKeys[key] = struct{}{}
		}
		for _, redaction := range ctx.Redactions {
			strategy := strings.ToLower(redaction.Strategy)
			if strategy == "" {
				strategy = "drop"
			}
			redactionStrategies[redaction.Attribute] = strategy
		}
	}

	redacted := make([]attribute.KeyValue, 0, len(attrs))
	for _, kv := range attrs {
		key := string(kv.Key)
		if _, drop := dropKeys[key]; drop {
			continue
		}

		strategy := redactionStrategies[key]
		switch strategy {
		case "drop":
			continue
		case "mask":
			// Mask: show partial data (e.g., first/last chars)
			redacted = append(redacted, attribute.String(key, maskValue(kv.Value.AsString())))
		case "hash":
			// Hash: produce deterministic hash for correlation without exposing data
			redacted = append(redacted, attribute.String(key, hashValue(kv.Value.AsString())))
		case "replace", "redact":
			// Replace/Redact: complete removal with placeholder
			redacted = append(redacted, attribute.String(key, "[REDACTED]"))
		default:
			redacted = append(redacted, kv)
		}
	}

	return redacted
}

// maskValue shows partial data for debugging while protecting sensitive portions.
// Shows first 4 and last 4 characters with *** in between (e.g., "1234***6789").
func maskValue(s string) string {
	if len(s) <= 8 {
		return "***" // Too short to mask meaningfully
	}
	return s[:4] + "***" + s[len(s)-4:]
}

// hashValue produces a deterministic hex hash for correlation tracking.
func hashValue(s string) string {
	if s == "" {
		return "[REDACTED:empty]"
	}
	// Simple hash for demonstration - use crypto-secure hash in production
	hash := 0
	for _, ch := range s {
		hash = hash*31 + int(ch)
	}
	return fmt.Sprintf("[REDACTED:hash:%08x]", hash&0xFFFFFFFF)
}
