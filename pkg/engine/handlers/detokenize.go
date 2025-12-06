package handlers

import (
	"context"
	"log/slog"
	"regexp"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/storage"
)

// tokenPattern matches the [TOKEN::{UUID}] format
var tokenPattern = regexp.MustCompile(`\[TOKEN::[a-fA-F0-9-]{36}\]`)

// DetokenizeHandler restores original PII values from tokens in the response body.
type DetokenizeHandler struct {
	logger *slog.Logger
	vault  storage.TokenVault
}

// NewDetokenizeHandler creates a new detokenization handler.
func NewDetokenizeHandler(logger *slog.Logger, vault storage.TokenVault) *DetokenizeHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &DetokenizeHandler{
		logger: logger,
		vault:  vault,
	}
}

// Execute scans the response body for tokens and replaces them with original values.
func (h *DetokenizeHandler) Execute(ctx context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	if h.vault == nil {
		h.logger.Warn("detokenization skipped: no vault configured")
		return runtime.Success(nil), nil
	}

	// This handler operates on the response body, which might be streaming.
	// For simplicity in Phase 1, we'll assume buffered processing or simple string replacement on small responses.
	// Ideally, this should support streaming replacement similar to DLP.
	// However, since we need to look up values, valid replace logic is complex in streams if tokens span chunks.
	// Given tokens are fixed format `[TOKEN::{UUID}]`, we can likely stream it, but let's stick to the current body buffer pattern
	// used in other handlers if available, or just wrap the response writer for later execution if this is an egress modifier.
	//
	// WAIT: Pipeline nodes run *before* egress (request) or *after* egress (response)?
	// The DAG executes nodes. If this node is placed after egress, it can modify pipelineCtx.Response.
	// But `http_handler` writes the response *after* the DAG execution completes (or during egress).
	// Truly intercepting the response requires the Egress node to support a "response processor" or this handler
	// to wrap the response writer.
	//
	// In the current architecture, `egress.http` writes directly to the response writer.
	// To support post-egress modification, `egress.http` needs to support response transformation middlewares OR
	// we need a way to chain response processing.
	//
	// Looking at `executor.go`, it runs nodes. `egress.http` is just another node.
	// If `egress.http` writes to the network, subsequent nodes can't modify the body easily unless `egress.http` buffered it.
	//
	// Implementation Plan Check: "Combine with legacy or check architecture".
	// `egress.http` supports DLP via `pipelineCtx.Variables["dlp.config"]`.
	// We can add `detokenize` support similarly: configuration for the egress node.
	//
	// OPTION A: `DetokenizeHandler` sets a variable (like DLP) that `egress.http` uses.
	// OPTION B: `DetokenizeHandler` acts as a distinct phase? No, DAG is generic.
	//
	// Let's go with OPTION A: Handlers configure the context, Egress executes it.
	// This matches DLP design.

	pipelineCtx.Variables["detokenize.enabled"] = true

	h.logger.Debug("detokenization enabled for response")
	return runtime.Success(nil), nil
}
