package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/storage"
	"go.opentelemetry.io/otel/trace"
)

// Metadata header constants for agent identity and session metrics.
const (
	HeaderAgentID                 = "X-Agent-ID"
	HeaderAgentSubject            = "X-Agent-Subject"
	HeaderAgentIssuer             = "X-Agent-Issuer"
	HeaderAgentAudience           = "X-Agent-Audience"
	HeaderAgentScopes             = "X-Agent-Scopes"
	HeaderSessionTokensIn         = "X-Session-Tokens-In"
	HeaderSessionTokensOut        = "X-Session-Tokens-Out"
	HeaderSessionEstimatedCostUSD = "X-Session-Estimated-Cost-Usd"
)

type sessionIDContextKey struct{}

// DAGHandler wraps DAGExecutor to provide http.Handler integration for production use.
// It extracts session IDs, agent IDs, and constructs pipeline context from HTTP requests,
// then handles DAG execution errors with appropriate HTTP responses.
type DAGHandler struct {
	executor   *DAGExecutor
	logger     *slog.Logger
	httpClient *http.Client
}

// DAGHandlerConfig holds configuration for creating a DAGHandler.
type DAGHandlerConfig struct {
	Registry   *PipelineRegistry
	Logger     *slog.Logger
	TokenVault storage.TokenVault
}

// NewDAGHandler constructs an http.Handler that resolves agent pipelines from the
// registry and executes them through a shared DAG executor while preserving
// observability defaults.
func NewDAGHandler(cfg DAGHandlerConfig) *DAGHandler {
	if cfg.Registry == nil {
		panic("pipeline: pipeline registry is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	executor := NewDAGExecutor(DAGExecutorConfig{
		Registry:   cfg.Registry,
		Logger:     logger,
		TokenVault: cfg.TokenVault,
	})

	return &DAGHandler{
		executor: executor,
		logger:   logger,
		httpClient: &http.Client{
			Transport: http.DefaultTransport,
		},
	}
}

// ServeHTTP implements http.Handler for DAG-based request processing.
func (h *DAGHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Wrap ResponseWriter to prevent superfluous WriteHeader calls
	w = &statusRecorder{ResponseWriter: w}

	ctx := r.Context()

	h.logger.Info("received HTTP request",
		"method", r.Method,
		"path", r.URL.Path,
		"remote_addr", r.RemoteAddr,
		"ua", r.UserAgent(),
	)

	// Extract or generate session ID
	sessionID := extractSessionID(r)
	ctx = context.WithValue(ctx, sessionIDContextKey{}, sessionID)
	r = r.WithContext(ctx)

	h.logger.Debug("processing request via DAG",
		"method", r.Method,
		"path", r.URL.Path,
		"session_id", sessionID,
	)

	// Extract agent ID, goal ID, and protocol from request
	agentID := extractAgentID(r)
	protocol := extractProtocol(r)

	// If no agent ID found, use wildcard "*" to match catch-all pipeline
	// This is common in standard proxy mode where clients don't send X-Agent-ID
	if agentID == "" {
		agentID = "*"
		h.logger.Debug("no agent ID in request, using wildcard",
			"host", r.Host,
			"path", r.URL.Path,
			"method", r.Method,
		)
	}

	h.logger.Debug("extracted request metadata",
		"agent_id", agentID,
		"protocol", protocol,
		"session_id", sessionID,
	)

	// Build pipeline context from request
	pipelineCtx := h.buildPipelineContext(r, agentID)

	// Store request body in context for egress handler
	if r.Body != nil {
		h.logger.Info("reading request body")
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			h.logger.Error("failed to read request body", "error", err)
		} else {
			h.logger.Info("request body read", "bytes", len(bodyBytes), "content", string(bodyBytes))
			// Restore body for future reads
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			pipelineCtx.Variables["request.body"] = io.NopCloser(bytes.NewBuffer(bodyBytes))
			pipelineCtx.Variables["request.body_text"] = string(bodyBytes) // Explicit string availability for nodes
		}
	} else {
		h.logger.Info("request body is nil")
	}
	pipelineCtx.Variables["request.query"] = r.URL.RawQuery

	// Execute pipeline for this session
	err := h.executor.ExecuteForSession(ctx, sessionID, agentID, protocol, pipelineCtx)
	if err != nil {
		h.logger.Error("pipeline execution failed",
			"session_id", sessionID,
			"agent_id", agentID,
			"error", err,
		)
		h.writeErrorResponse(ctx, w, http.StatusInternalServerError, "PIPELINE_ERROR", "Pipeline execution failed")
		return
	}

	// After pipeline execution, check if egress response is available
	if targetURL, ok := pipelineCtx.Variables["egress.target_url"].(string); ok && targetURL != "" {
		h.logger.Debug("executing egress HTTP call", "target_url", targetURL, "session_id", sessionID)

		// Execute the egress HTTP call
		if err := h.executeEgressHTTP(ctx, w, r, pipelineCtx); err != nil {
			h.logger.Error("egress HTTP execution failed",
				"session_id", sessionID,
				"error", err,
			)
			h.writeErrorResponse(ctx, w, http.StatusBadGateway, "EGRESS_ERROR", "Failed to proxy request to upstream")
			return
		}
	} else {
		// No egress call prepared - pipeline completed without egress
		h.logger.Debug("pipeline execution completed without egress", "session_id", sessionID)
		h.writeDirectResponse(ctx, w, pipelineCtx)
	}
}

// extractAgentID extracts the agent ID from the request with the following precedence:
// 1. X-Agent-ID header
func extractAgentID(r *http.Request) string {
	// 1. X-Agent-ID header (explicit specification)
	if agentID := r.Header.Get(HeaderAgentID); agentID != "" {
		r.Header.Del(HeaderAgentID)
		return agentID
	}

	return ""
}

// extractProtocol extracts the protocol from the request.
// For Phase 1, always returns "http". Future phases will detect grpc, ws, mcp, etc.
func extractProtocol(r *http.Request) string {
	// Check for WebSocket upgrade
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		return "ws"
	}

	// Check for gRPC (Content-Type: application/grpc)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		return "grpc"
	}

	// Default to HTTP
	return "http"
}

// extractSessionID extracts or generates a session ID with the following precedence:
// 1. X-Session-ID header
// 2. session cookie
// 3. Generate new UUIDv4
func extractSessionID(r *http.Request) string {
	// 1. Check X-Session-ID header
	if headerID := r.Header.Get("X-Session-ID"); headerID != "" {
		return headerID
	}

	// 2. Check session cookie
	if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// 3. Generate new UUID
	return uuid.New().String()
}

// SessionIDFromContext extracts the session ID from the request context.
func SessionIDFromContext(ctx context.Context) string {
	if sessionID, ok := ctx.Value(sessionIDContextKey{}).(string); ok {
		return sessionID
	}
	return ""
}

// buildPipelineContext constructs a PipelineContext from an HTTP request.
func (h *DAGHandler) buildPipelineContext(r *http.Request, agentID string) *domain.PipelineContext {
	// Copy headers to avoid mutation, filtering hop-by-hop headers
	headers := make(map[string][]string)
	for k, v := range r.Header {
		// Skip hop-by-hop headers that should not be forwarded to upstream
		if isHopByHopHeader(k) {
			continue
		}
		headers[k] = v
	}

	protocol := extractProtocol(r)
	streamingMode := ""
	streaming := false
	if protocol == "ws" {
		streaming = true
		streamingMode = "websocket"
	}

	identityMeta := consumeIdentityHeaders(headers)
	sessionMeta := consumeSessionHeaders(headers)

	h.logger.Info("session metadata extracted",
		"tokens_in", sessionMeta.TokensIn,
		"tokens_out", sessionMeta.TokensOut,
		"cost_usd", sessionMeta.CostUSD,
		"headers_remaining", len(headers),
	)

	ctx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:        r.Method,
			Path:          r.URL.Path,
			Host:          r.Host,
			Headers:       headers,
			Protocol:      protocol,
			AgentID:       agentID,
			TenantID:      "",
			SessionID:     SessionIDFromContext(r.Context()),
			Streaming:     streaming,
			StreamingMode: streamingMode,
			TriggerIndex:  -1,
		},
		Response: domain.ResponseContext{
			Headers:  make(map[string][]string),
			Trailers: make(map[string][]string),
		},
		Session: domain.SessionContext{
			TotalTokensIn:    0,
			TotalTokensOut:   0,
			EstimatedCostUSD: 0.0,
		},
		Variables: make(map[string]interface{}),
		Budgets:   domain.BudgetContext{},
		Security: domain.SecurityContext{
			Findings:   []domain.SecurityFinding{},
			Violations: []domain.Violation{},
		},
		Telemetry: domain.TelemetryContext{
			Taints: make(map[string]domain.TelemetryTaint),
		},
	}

	applyIdentityMetadata(ctx, identityMeta)
	applySessionMetadata(ctx, sessionMeta)

	return ctx
}

// writeErrorResponse writes a JSON error response in OpenAI-compatible format.
func (h *DAGHandler) writeErrorResponse(ctx context.Context, w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// OpenTelemetry trace ID
	var traceID string
	if span := trace.SpanFromContext(ctx); span != nil {
		if sc := span.SpanContext(); sc.IsValid() {
			traceID = sc.TraceID().String()
		}
	}

	// OpenAI-compatible error structure
	errResp := map[string]any{
		"error": map[string]any{
			"message":  message,
			"type":     "policy_violation", // Use a generic type or map from code
			"param":    nil,
			"code":     code,
			"trace_id": traceID, // Extension field
		},
	}

	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		h.logger.Error("failed to encode error response", "error", err)
	}
}

// writeDirectResponse writes the response recorded in the pipeline context (non-egress path).
func (h *DAGHandler) writeDirectResponse(ctx context.Context, w http.ResponseWriter, pipelineCtx *domain.PipelineContext) {
	status := http.StatusOK
	if pipelineCtx != nil && pipelineCtx.Response.Status > 0 {
		status = pipelineCtx.Response.Status
	}

	if pipelineCtx != nil && len(pipelineCtx.Response.Headers) > 0 {
		copyResponseHeaders(w.Header(), http.Header(pipelineCtx.Response.Headers))
	}

	if pipelineCtx != nil && (pipelineCtx.Security.Blocked || status >= http.StatusBadRequest) {
		code := responseErrorCodeFromContext(pipelineCtx)
		message := responseErrorMessageFromContext(pipelineCtx, status)
		h.writeErrorResponse(ctx, w, status, code, message)
		return
	}

	w.WriteHeader(status)
}

func responseErrorCodeFromContext(pctx *domain.PipelineContext) string {
	if pctx == nil {
		return "REQUEST_BLOCKED"
	}
	if pctx.Variables != nil {
		if code, ok := pctx.Variables[responseErrorCodeKey].(string); ok && code != "" {
			return code
		}
	}
	if pctx.Security.BlockReason != "" {
		return pctx.Security.BlockReason
	}
	return "REQUEST_BLOCKED"
}

func responseErrorMessageFromContext(pctx *domain.PipelineContext, status int) string {
	if pctx != nil && pctx.Variables != nil {
		if msg, ok := pctx.Variables[responseErrorMessageKey].(string); ok && msg != "" {
			return msg
		}
	}
	if text := http.StatusText(status); text != "" {
		return text
	}
	return "Request blocked by policy"
}

type identityMetadata struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   []string
}

type sessionMetadata struct {
	TokensIn  *int
	TokensOut *int
	CostUSD   *float64
}

func consumeIdentityHeaders(headers map[string][]string) identityMetadata {
	return identityMetadata{
		Subject:  firstHeaderValue(headers, HeaderAgentSubject, true),
		Issuer:   firstHeaderValue(headers, HeaderAgentIssuer, true),
		Audience: listHeaderValues(headers, HeaderAgentAudience),
		Scopes:   listHeaderValues(headers, HeaderAgentScopes),
	}
}

func consumeSessionHeaders(headers map[string][]string) sessionMetadata {
	return sessionMetadata{
		TokensIn:  intHeaderValue(headers, HeaderSessionTokensIn),
		TokensOut: intHeaderValue(headers, HeaderSessionTokensOut),
		CostUSD:   floatHeaderValue(headers, HeaderSessionEstimatedCostUSD),
	}
}

func applyIdentityMetadata(ctx *domain.PipelineContext, meta identityMetadata) {
	if ctx == nil {
		return
	}
	if ctx.Variables == nil {
		ctx.Variables = make(map[string]interface{})
	}
	if meta.Subject != "" {
		ctx.Variables["auth.subject"] = meta.Subject
	}
	if meta.Issuer != "" {
		ctx.Variables["auth.issuer"] = meta.Issuer
	}
	if len(meta.Audience) > 0 {
		ctx.Variables["auth.audiences"] = append([]string(nil), meta.Audience...)
	}
	if len(meta.Scopes) > 0 {
		ctx.Variables["auth.scopes"] = append([]string(nil), meta.Scopes...)
	}
}

func applySessionMetadata(ctx *domain.PipelineContext, meta sessionMetadata) {
	if ctx == nil {
		return
	}
	if meta.TokensIn != nil {
		ctx.Session.TotalTokensIn = *meta.TokensIn
	}
	if meta.TokensOut != nil {
		ctx.Session.TotalTokensOut = *meta.TokensOut
	}
	if meta.CostUSD != nil {
		ctx.Session.EstimatedCostUSD = *meta.CostUSD
	}
}

func firstHeaderValue(headers map[string][]string, key string, trim bool) string {
	values := consumeHeader(headers, key)
	if len(values) == 0 {
		return ""
	}
	value := values[0]
	if trim {
		return strings.TrimSpace(value)
	}
	return value
}

func listHeaderValues(headers map[string][]string, key string) []string {
	values := consumeHeader(headers, key)
	if len(values) == 0 {
		return nil
	}
	var result []string
	for _, raw := range values {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';'
		}) {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
	}
	return result
}

func intHeaderValue(headers map[string][]string, key string) *int {
	values := consumeHeader(headers, key)
	if len(values) == 0 {
		return nil
	}
	if value, err := strconv.Atoi(strings.TrimSpace(values[0])); err == nil {
		return &value
	}
	return nil
}

func floatHeaderValue(headers map[string][]string, key string) *float64 {
	values := consumeHeader(headers, key)
	if len(values) == 0 {
		return nil
	}
	if value, err := strconv.ParseFloat(strings.TrimSpace(values[0]), 64); err == nil {
		return &value
	}
	return nil
}

func consumeHeader(headers map[string][]string, key string) []string {
	if len(headers) == 0 {
		return nil
	}
	// Try direct lookup with canonical key first (fast path)
	canonical := http.CanonicalHeaderKey(key)
	if values, ok := headers[canonical]; ok {
		delete(headers, canonical)
		return values
	}
	// Fallback to case-insensitive search
	for existingKey, values := range headers {
		if strings.EqualFold(existingKey, key) {
			delete(headers, existingKey)
			return values
		}
	}
	return nil
}

// statusRecorder wraps http.ResponseWriter to prevent multiple WriteHeader calls.
type statusRecorder struct {
	http.ResponseWriter
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.ResponseWriter.WriteHeader(code)
		r.wroteHeader = true
	}
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker to allow connection takeover for HTTPS tunneling.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hijacker.Hijack()
}
