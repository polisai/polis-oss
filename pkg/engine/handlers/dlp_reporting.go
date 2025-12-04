package handlers

import (
	"fmt"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/policy/dlp"
)

// RecordDLPFindings appends security findings and telemetry taints for DLP outcomes.
func RecordDLPFindings(pipelineCtx *domain.PipelineContext, report dlp.Report, scope string) {
	if len(report.Findings) == 0 && !report.RedactionsApplied {
		return
	}

	scope = strings.ToLower(scope)
	location := "response body"
	attribute := "http.response.body"
	blockTarget := "response"
	if scope == "request" {
		location = "request body"
		attribute = "http.request.body"
		blockTarget = "request"
	}

	highestSeverity := "low"

	for _, finding := range report.Findings {
		severity := severityForDLPAction(finding.Action)
		metadata := map[string]interface{}{
			"start":  finding.Start,
			"end":    finding.End,
			"action": string(finding.Action),
		}

		pipelineCtx.Security.Findings = append(pipelineCtx.Security.Findings, domain.SecurityFinding{
			Source:   "dlp",
			RuleID:   finding.Rule,
			Severity: severity,
			Action:   string(finding.Action),
			Summary:  fmt.Sprintf("DLP rule %s triggered on %s", finding.Rule, location),
			Metadata: metadata,
		})

		if finding.Action == dlp.ActionBlock {
			pipelineCtx.Security.Violations = append(pipelineCtx.Security.Violations, domain.Violation{
				Code:     "DLP_BLOCKED",
				Severity: severity,
				Message:  fmt.Sprintf("dlp rule %s blocked %s", finding.Rule, blockTarget),
				Details:  metadata,
			})
		}

		highestSeverity = maxSeverityLabel(highestSeverity, severity)
	}

	if report.RedactionsApplied {
		updateTelemetryTaint(&pipelineCtx.Telemetry, attribute, "dlp.redaction", highestSeverity, "dlp")
		pipelineCtx.Telemetry.Redactions = append(pipelineCtx.Telemetry.Redactions, domain.TelemetryRedaction{
			Attribute: attribute,
			Strategy:  "replace",
			Reason:    "dlp.redaction",
			Source:    "dlp",
		})
	} else if len(report.Findings) > 0 {
		updateTelemetryTaint(&pipelineCtx.Telemetry, attribute, "dlp.finding", highestSeverity, "dlp")
	}
}

func updateTelemetryTaint(ctx *domain.TelemetryContext, key, reason, severity, source string) {
	if ctx.Taints == nil {
		ctx.Taints = make(map[string]domain.TelemetryTaint)
	}

	severity = strings.ToLower(severity)
	current, ok := ctx.Taints[key]
	if !ok || severityRank(severity) > severityRank(strings.ToLower(current.Severity)) {
		ctx.Taints[key] = domain.TelemetryTaint{
			Attribute: key,
			Reason:    reason,
			Severity:  severity,
			Source:    source,
		}
	}
}

func severityForDLPAction(action dlp.Action) string {
	switch action {
	case dlp.ActionBlock:
		return "high"
	case dlp.ActionRedact:
		return "medium"
	default:
		return "low"
	}
}

func maxSeverityLabel(current, candidate string) string {
	if severityRank(candidate) > severityRank(current) {
		return candidate
	}
	return current
}

func severityRank(label string) int {
	switch strings.ToLower(label) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
