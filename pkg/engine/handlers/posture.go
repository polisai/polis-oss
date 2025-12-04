package handlers

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
)

// resolveNodePosture returns the effective failure posture for a node.
//
// Priority order:
//  1. node.Posture (top-level field in pipeline definition)
//  2. node.Config["posture"] (legacy placement, string only)
//  3. defaultPosture (already lower-cased for handlers)
func resolveNodePosture(node *domain.PipelineNode, defaultPosture string, logger *slog.Logger) string {
	posture := strings.ToLower(defaultPosture)

	if node == nil {
		return posture
	}

	if node.Posture != "" {
		return strings.ToLower(node.Posture)
	}

	// Backwards compatibility: some pipelines still set posture under config.
	if node.Config != nil {
		if raw, ok := node.Config["posture"]; ok {
			switch value := raw.(type) {
			case string:
				if value == "" {
					return posture
				}
				if logger != nil {
					logger.Warn("pipeline node posture configured under config.posture; prefer using node.posture",
						"node_id", node.ID,
					)
				}
				return strings.ToLower(value)
			default:
				if logger != nil {
					logger.Warn("pipeline node posture ignored because value is not a string",
						"node_id", node.ID,
						"type", fmt.Sprintf("%T", raw),
					)
				}
			}
		}
	}

	return posture
}
