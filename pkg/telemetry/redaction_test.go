package telemetry

import (
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"go.opentelemetry.io/otel/attribute"
)

func TestRedactAttributesHonorsTaintsAndStrategies(t *testing.T) {
	tctx := &domain.TelemetryContext{
		Taints: map[string]domain.TelemetryTaint{
			"custom.secret": {Attribute: "custom.secret"},
		},
		Redactions: []domain.TelemetryRedaction{
			{Attribute: "user.email", Strategy: "mask"},
		},
	}

	attrs := []attribute.KeyValue{
		attribute.String("http.request.header.authorization", "Bearer secret"),
		attribute.String("user.email", "person@example.com"),
		attribute.String("custom.secret", "top-secret"),
		attribute.String("safe.field", "value"),
	}

	filtered := RedactAttributes(tctx, attrs)

	if len(filtered) != 2 {
		t.Fatalf("expected 2 attributes after redaction, got %d", len(filtered))
	}

	for _, kv := range filtered {
		switch kv.Key {
		case "user.email":
			if got := kv.Value.AsString(); got != "pers***.com" {
				t.Fatalf("unexpected masked email %q", got)
			}
		case "safe.field":
			if kv.Value.AsString() != "value" {
				t.Fatalf("unexpected safe field value %q", kv.Value.AsString())
			}
		default:
			t.Fatalf("unexpected attribute %q present after redaction", kv.Key)
		}
	}
}
