package telemetry

import (
	"github.com/polisai/polis-oss/pkg/policy"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// RecordPolicyDecision annotates the provided span with the policy decision outcome.
func RecordPolicyDecision(span trace.Span, decision policy.Decision) {
	if !span.IsRecording() {
		return
	}

	span.SetAttributes(
		attribute.String("policy.decision.action", string(decision.Action)),
	)

	if decision.Reason != "" {
		span.SetAttributes(attribute.String("policy.decision.reason", decision.Reason))
	}

	for key, value := range decision.Metadata {
		if value == "" {
			continue
		}
		span.SetAttributes(attribute.String("policy."+key, value))
	}

	// Populate a generic violation code if present in metadata
	if code, ok := decision.Metadata["violation_code"]; ok && code != "" {
		span.SetAttributes(attribute.String("policy.violation_code", code))
	} else if decision.Action == policy.ActionBlock || decision.Action == policy.ActionRedact {
		// Fallback to reason as a coarse code
		span.SetAttributes(attribute.String("policy.violation_code", decision.Reason))
	}

	if decision.Action == policy.ActionBlock {
		span.AddEvent("policy.blocked")
	}
}

// RecordPolicyFindings attaches coarse-grained information about policy findings to the span.
func RecordPolicyFindings(span trace.Span, findings map[string]any) {
	if !span.IsRecording() || len(findings) == 0 {
		return
	}

	for domain := range findings {
		span.SetAttributes(attribute.Bool("policy.findings."+domain, true))
	}
}
