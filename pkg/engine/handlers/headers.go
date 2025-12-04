package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

// HeadersHandler strips hop-by-hop headers and canonicalizes header names.
// Authorization headers are preserved for upstream authentication (passthrough mode).
type HeadersHandler struct {
	sanitizer *headerSanitizer
	logger    *slog.Logger
}

// NewHeadersHandler creates a new header stripping and canonicalization handler.
func NewHeadersHandler(logger *slog.Logger) *HeadersHandler {
	if logger == nil {
		logger = slog.Default()
	}

	return &HeadersHandler{
		sanitizer: newHeaderSanitizer(),
		logger:    logger,
	}
}

// Execute strips inbound credential headers from the pipeline context.
func (h *HeadersHandler) Execute(_ context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	originalCount := len(pipelineCtx.Request.Headers)

	// Strip blocked headers
	h.sanitizer.stripHeaders(pipelineCtx.Request.Headers)

	strippedCount := originalCount - len(pipelineCtx.Request.Headers)

	if strippedCount > 0 {
		h.logger.Info("headers handler: stripped credential headers",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
			"stripped_count", strippedCount,
		)
	}

	return runtime.Success(nil), nil
}

// headerSanitizer removes credential-bearing headers before forwarding requests upstream.
type headerSanitizer struct {
	blocked map[string]struct{}
}

// newHeaderSanitizer constructs a sanitizer with default credential headers.
func newHeaderSanitizer() *headerSanitizer {
	defaultCredentialHeaders := []string{
		// NOTE: Authorization header is preserved for upstream authentication
		"Proxy-Authorization", // Strip proxy auth headers
		"Cookie",              // Strip cookies to prevent session hijacking
		"X-Forwarded-Access-Token",
		"X-Forwarded-Authorization",
		"X-Identity-Token",
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Transfer-Encoding",
		"TE",
		"Trailer",
		"Upgrade",
	}

	sanitizer := &headerSanitizer{blocked: make(map[string]struct{})}
	for _, name := range defaultCredentialHeaders {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical != "" {
			sanitizer.blocked[canonical] = struct{}{}
		}
	}
	return sanitizer
}

// stripHeaders removes blocked headers from the header map.
func (s *headerSanitizer) stripHeaders(headers map[string][]string) {
	if headers == nil {
		return
	}

	for name := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if _, blocked := s.blocked[canonical]; blocked {
			delete(headers, name)
		}
	}
}
