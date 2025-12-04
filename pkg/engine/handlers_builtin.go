package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

// PassthroughNodeHandler logs the node execution and continues to success.
type PassthroughNodeHandler struct {
	logger *slog.Logger
}

// Execute logs the node execution and continues to success.
func (h *PassthroughNodeHandler) Execute(_ context.Context, node *domain.PipelineNode, _ *domain.PipelineContext) (runtime.NodeResult, error) {
	h.logger.Debug("passthrough node executed",
		"node_id", node.ID,
		"node_type", node.Type,
	)
	return runtime.Success(nil), nil
}

// TerminalDenyHandler is a handler that denies the request.
type TerminalDenyHandler struct {
	logger *slog.Logger
}

// Execute denies the request by returning an error.
func (h *TerminalDenyHandler) Execute(_ context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	status := parseStatus(node.Config["status"], http.StatusForbidden)
	code := strings.TrimSpace(fmt.Sprint(node.Config["code"]))
	if code == "" || code == "<nil>" {
		code = "ACCESS_DENIED"
	}
	message := strings.TrimSpace(fmt.Sprint(node.Config["message"]))
	if message == "" || message == "<nil>" {
		message = "Access denied"
	}

	if pipelineCtx != nil {
		if pipelineCtx.Variables == nil {
			pipelineCtx.Variables = make(map[string]interface{})
		}
		pipelineCtx.Variables[responseErrorCodeKey] = code
		pipelineCtx.Variables[responseErrorMessageKey] = message

		pipelineCtx.Security.Blocked = true
		if pipelineCtx.Security.BlockReason == "" {
			pipelineCtx.Security.BlockReason = code
		}

		if pipelineCtx.Response.Status == 0 {
			pipelineCtx.Response.Status = status
		}
		if pipelineCtx.Response.Headers == nil {
			pipelineCtx.Response.Headers = make(map[string][]string)
		}
		if _, ok := pipelineCtx.Response.Headers["Content-Type"]; !ok {
			pipelineCtx.Response.Headers["Content-Type"] = []string{"application/json"}
		}
	}

	if h.logger != nil {
		h.logger.Info("terminal deny executed",
			"node_id", node.ID,
			"status", status,
			"code", code,
		)
	}

	return runtime.NodeResult{Outcome: runtime.OutcomeDeny}, nil
}

func parseStatus(raw interface{}, fallback int) int {
	switch v := raw.(type) {
	case int:
		if v > 0 {
			return v
		}
	case int32:
		if v > 0 {
			return int(v)
		}
	case int64:
		if v > 0 {
			return int(v)
		}
	case float64:
		if v > 0 {
			return int(v)
		}
	case float32:
		if v > 0 {
			return int(v)
		}
	case string:
		if v == "" {
			break
		}
		var parsed int
		if _, err := fmt.Sscanf(v, "%d", &parsed); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

// TerminalErrorHandler is a handler that returns an error response.
type TerminalErrorHandler struct {
	logger *slog.Logger
}

// Execute returns an error to indicate request failure.
func (h *TerminalErrorHandler) Execute(_ context.Context, node *domain.PipelineNode, _ *domain.PipelineContext) (runtime.NodeResult, error) {
	h.logger.Info("terminal error executed", "node_id", node.ID)
	return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("terminal error node reached")
}

// TerminalAllowHandler completes the pipeline successfully.
type TerminalAllowHandler struct {
	logger *slog.Logger
}

// Execute records a successful terminal outcome (HTTP 200 by default).
func (h *TerminalAllowHandler) Execute(_ context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	if h.logger != nil {
		h.logger.Info("terminal allow executed", "node_id", node.ID)
	}

	if pipelineCtx.Response.Headers == nil {
		pipelineCtx.Response.Headers = make(map[string][]string)
	}

	if pipelineCtx.Response.Status == 0 {
		pipelineCtx.Response.Status = http.StatusOK
	}

	return runtime.Success(nil), nil
}
