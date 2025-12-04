package engine

import "github.com/polisai/polis-oss/pkg/domain"

// getDLPPosture retrieves the DLP failure posture from the pipeline context.
// Returns "fail-open" by default if not specified.
func getDLPPosture(pipelineCtx *domain.PipelineContext) string {
	if posture, ok := pipelineCtx.Variables["dlp.posture"].(string); ok && posture != "" {
		return posture
	}
	return "fail-open"
}
