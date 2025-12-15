package engine

import (
	"bufio"
	"context"
	"io"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/policy/dlp"
)

// getDLPPosture retrieves the DLP failure posture from the pipeline context.
// Returns "fail-open" by default if not specified.
func getDLPPosture(pipelineCtx *domain.PipelineContext) string {
	if posture, ok := pipelineCtx.Variables["dlp.posture"].(string); ok && posture != "" {
		return posture
	}
	return "fail-open"
}

// redactSSEStream reads from src, parses SSE data fields, applies DLP/redaction, and writes to dst.
// It maintains the SSE framing (data: prefix) to ensure protocol compliance.
func redactSSEStream(ctx context.Context, src io.Reader, dst *flushCountingWriter, cfg dlp.Config) (dlp.Report, error) {
	scanner, err := dlp.NewScanner(cfg)
	if err != nil {
		return dlp.Report{}, err
	}

	sseScanner := bufio.NewScanner(src)
	// Support large SSE events (up to 10MB)
	buf := make([]byte, 64*1024)
	sseScanner.Buffer(buf, 10*1024*1024)

	var combinedReport dlp.Report

	for sseScanner.Scan() {
		line := sseScanner.Text()

		// Only inspect "data:" fields, ignore "id:", "event:", "retry:" etc. to avoid breaking protocol
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimPrefix(line, "data:")

			// SSE spec: remove single leading space if present
			content := payload
			hasLeadingSpace := false
			if strings.HasPrefix(payload, " ") {
				content = strings.TrimPrefix(payload, " ")
				hasLeadingSpace = true
			}

			// Scan the content
			report, err := scanner.Scan(ctx, content)
			if err != nil {
				// In stream mode, regex errors usually mean we can't redact.
				// We return the error so the caller can decide based on posture.
				return combinedReport, err
			}

			if report.Blocked {
				combinedReport.Blocked = true
				return combinedReport, nil // Block immediately
			}

			// Aggregate findings
			combinedReport.Findings = append(combinedReport.Findings, report.Findings...)
			combinedReport.RedactionsApplied = combinedReport.RedactionsApplied || report.RedactionsApplied

			if report.RedactionsApplied {
				// Reconstruct line
				prefix := "data:"
				if hasLeadingSpace {
					prefix += " "
				}
				line = prefix + report.Redacted
			}
		}

		if _, err := dst.Write([]byte(line + "\n")); err != nil {
			return combinedReport, err
		}
	}

	return combinedReport, sseScanner.Err()
}
