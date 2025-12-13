// Package handlers provides node handler implementations for the DAG pipeline executor.
// Each handler type implements the NodeHandler interface and processes a specific
// step in the request pipeline (auth, headers, policy, egress, etc.).
package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

// EgressHTTPHandler prepares HTTP egress requests in passthrough mode.
// This handler builds the egress request and stores it in the pipeline context
// for the DAGHandler to execute after pipeline completion.
// Client Authorization headers are forwarded directly to upstream.
type EgressHTTPHandler struct {
	logger *slog.Logger
}

type timeoutCandidate struct {
	source string
	ms     int
}

// NewEgressHTTPHandler creates a new HTTP egress handler.
func NewEgressHTTPHandler(logger *slog.Logger) *EgressHTTPHandler {
	if logger == nil {
		logger = slog.Default()
	}

	return &EgressHTTPHandler{
		logger: logger,
	}
}

// Execute prepares the egress HTTP request with support for multiple upstream resolution modes:
// 1. Standard Proxy Protocol: Extract target from request (Host header, absolute URI)
// 2. Static Configuration: Use node config upstream_url
// 3. Dynamic Custom Header: X-Target-URL header (for LLM-directed agent calls)
func (h *EgressHTTPHandler) Execute(_ context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	if pipelineCtx == nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("egress: pipeline context is nil")
	}
	if pipelineCtx.Variables == nil {
		pipelineCtx.Variables = make(map[string]interface{})
	}

	mode := getUpstreamMode(node.Config)

	targetURL, err := h.resolveTargetURL(mode, node, pipelineCtx)
	if err != nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, err
	}

	if targetURL == nil {
		h.logger.Error("egress handler: no upstream URL determined",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
			"mode", mode,
		)
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("egress: no upstream URL determined (mode=%s)", mode)
	}

	if mode != "proxy" {
		targetURL.Path = pipelineCtx.Request.Path
		if rawQuery, ok := pipelineCtx.Variables["request.query"].(string); ok {
			targetURL.RawQuery = rawQuery
		}
	}

	egressHeaders := make(http.Header)
	for name, values := range pipelineCtx.Request.Headers {
		egressHeaders[name] = append([]string(nil), values...)
	}

	if removed := applyStripHeaders(node.Config, egressHeaders); removed > 0 {
		h.logger.Debug("egress handler: stripped headers before upstream call",
			"node_id", node.ID,
			"removed", removed,
		)
	}

	timeout, candidates := resolveEgressTimeout(pipelineCtx, node)
	h.recordTimeoutMetadata(node, pipelineCtx, timeout, candidates)

	h.applyStreamingConfiguration(node, pipelineCtx)

	pipelineCtx.Variables["egress.target_url"] = targetURL.String()
	pipelineCtx.Variables["egress.headers"] = egressHeaders

	pipelineCtx.Variables["egress.method"] = pipelineCtx.Request.Method

	h.logger.Info("egress handler: prepared egress request",
		"node_id", node.ID,
		"agent_id", pipelineCtx.Request.AgentID,
		"target_url", targetURL.String(),
		"method", pipelineCtx.Request.Method,
	)

	return runtime.Success(nil), nil
}

func (h *EgressHTTPHandler) resolveTargetURL(mode string, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (*url.URL, error) {
	switch mode {
	case "proxy":
		return h.resolveProxyTarget(node, pipelineCtx)
	case "custom_header":
		return h.resolveCustomHeaderTarget(node, pipelineCtx)
	case "static":
		return h.resolveStaticTarget(node, pipelineCtx)
	default:
		return h.resolveStaticTarget(node, pipelineCtx)
	}
}

func (h *EgressHTTPHandler) resolveProxyTarget(node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (*url.URL, error) {
	targetURL, err := h.extractProxyTarget(pipelineCtx)
	if err != nil {
		h.logger.Error("egress handler: failed to extract proxy target",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
			"error", err,
		)
		return nil, fmt.Errorf("egress: failed to extract proxy target: %w", err)
	}

	h.logger.Info("egress handler: using standard proxy protocol",
		"node_id", node.ID,
		"agent_id", pipelineCtx.Request.AgentID,
		"target_host", targetURL.Host,
	)

	return targetURL, nil
}

func (h *EgressHTTPHandler) resolveCustomHeaderTarget(node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (*url.URL, error) {
	targetHeader := getHeader(pipelineCtx.Request.Headers, "X-Target-URL")
	if targetHeader == "" {
		return nil, nil
	}

	if err := h.validateUpstreamURL(targetHeader, node.Config); err != nil {
		h.logger.Warn("egress handler: rejected dynamic upstream URL",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
			"target_url", targetHeader,
			"error", err,
		)
		return nil, fmt.Errorf("egress: dynamic upstream rejected: %w", err)
	}

	targetURL, err := url.Parse(targetHeader)
	if err != nil {
		h.logger.Error("egress handler: unable to parse validated upstream URL",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
			"target_url", targetHeader,
			"error", err,
		)
		return nil, fmt.Errorf("egress: invalid upstream URL: %w", err)
	}

	h.logger.Info("egress handler: using custom header upstream",
		"node_id", node.ID,
		"agent_id", pipelineCtx.Request.AgentID,
		"target_url", targetHeader,
	)

	return targetURL, nil
}

func (h *EgressHTTPHandler) resolveStaticTarget(node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (*url.URL, error) {
	configURL, ok := node.Config["upstream_url"].(string)
	if !ok || strings.TrimSpace(configURL) == "" {
		return nil, nil
	}

	targetURL, err := url.Parse(configURL)
	if err != nil {
		h.logger.Error("egress handler: invalid configured upstream_url",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
			"upstream_url", configURL,
			"error", err,
		)
		return nil, fmt.Errorf("egress: invalid configured upstream_url: %w", err)
	}

	h.logger.Info("egress handler: using static upstream configuration",
		"node_id", node.ID,
		"agent_id", pipelineCtx.Request.AgentID,
		"target_url", configURL,
	)

	return targetURL, nil
}

func (h *EgressHTTPHandler) recordTimeoutMetadata(node *domain.PipelineNode, pipelineCtx *domain.PipelineContext, timeout time.Duration, candidates []timeoutCandidate) {
	if timeout <= 0 || pipelineCtx == nil {
		return
	}

	pipelineCtx.Variables["egress.timeout"] = timeout

	selectedMs := int(timeout / time.Millisecond)
	selectedSources := make([]string, 0, len(candidates))
	candidateSummaries := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.ms <= 0 {
			continue
		}
		candidateSummaries = append(candidateSummaries, fmt.Sprintf("%dms<- %s", candidate.ms, candidate.source))
		if candidate.ms == selectedMs {
			selectedSources = append(selectedSources, candidate.source)
		}
	}

	if len(candidateSummaries) > 0 {
		pipelineCtx.Variables["egress.timeout.candidates"] = candidateSummaries
	}
	if len(selectedSources) > 0 {
		pipelineCtx.Variables["egress.timeout.sources"] = selectedSources
	}
	pipelineCtx.Variables["egress.timeout.selected_ms"] = selectedMs

	if len(candidates) > 1 {
		unique := make(map[int][]string)
		for _, candidate := range candidates {
			unique[candidate.ms] = append(unique[candidate.ms], candidate.source)
		}
		if len(unique) > 1 {
			sources := make([]string, 0, len(unique))
			for value, list := range unique {
				sources = append(sources, fmt.Sprintf("%dms<- %s", value, strings.Join(list, ",")))
			}
			h.logger.Warn("egress timeout configured from multiple sources; using smallest",
				"node_id", node.ID,
				"selected_timeout_ms", selectedMs,
				"sources", sources,
			)
		}
	}

	h.logger.Debug("egress handler: configured timeout",
		"node_id", node.ID,
		"timeout_ms", selectedMs,
	)
}

func (h *EgressHTTPHandler) applyStreamingConfiguration(node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) {
	streamingEnabled := pipelineCtx.Request.Streaming
	if existing, ok := pipelineCtx.Variables["egress.streaming.enabled"].(bool); ok && existing {
		streamingEnabled = true
	}

	configStreaming, streamingModeOverride, idleTimeout := streamingSettingsFromConfig(node.Config)
	if configStreaming {
		streamingEnabled = true
		pipelineCtx.Variables["egress.streaming.source"] = "node.config.streaming"
	}

	if streamingModeOverride != "" {
		pipelineCtx.Request.StreamingMode = streamingModeOverride
	}

	if streamingEnabled {
		pipelineCtx.Request.Streaming = true
		pipelineCtx.Variables["egress.streaming.enabled"] = true
		if pipelineCtx.Request.StreamingMode != "" {
			pipelineCtx.Variables["egress.streaming.mode"] = pipelineCtx.Request.StreamingMode
		}
	}

	if idleTimeout > 0 {
		pipelineCtx.Variables["egress.streaming.idle_timeout"] = idleTimeout
		pipelineCtx.Variables["egress.streaming.idle_timeout_ms"] = int(idleTimeout / time.Millisecond)
	}

	if streamingEnabled {
		h.logger.Debug("egress handler: streaming mode enabled",
			"node_id", node.ID,
			"mode", pipelineCtx.Request.StreamingMode,
			"idle_timeout_ms", pipelineCtx.Variables["egress.streaming.idle_timeout_ms"],
		)
	}
}

// validateUpstreamURL checks if a dynamic upstream URL is allowed based on allowlist configuration.
func (h *EgressHTTPHandler) validateUpstreamURL(targetURL string, config map[string]interface{}) error {
	// Parse URL to validate format
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Require HTTPS for security (unless explicitly disabled)
	requireHTTPS, _ := config["require_https"].(bool)
	if requireHTTPS && parsedURL.Scheme != "https" {
		return fmt.Errorf("only HTTPS URLs allowed, got: %s", parsedURL.Scheme)
	}

	// Check against allowlist (supports domain patterns and full URLs)
	allowlist, ok := config["upstream_allowlist"].([]interface{})
	if !ok || len(allowlist) == 0 {
		// No allowlist = deny all dynamic upstreams
		return fmt.Errorf("no upstream allowlist configured")
	}

	targetHost := parsedURL.Hostname()
	targetBase := parsedURL.Scheme + "://" + parsedURL.Host

	for _, entry := range allowlist {
		pattern, ok := entry.(string)
		if !ok {
			continue
		}

		// Support patterns:
		// 1. "*.example.com" - wildcard subdomain
		// 2. "api.example.com" - exact domain
		// 3. "https://api.example.com" - exact base URL

		if pattern == "*" {
			// Allow all (use with caution!)
			return nil
		}

		// Wildcard domain match (*.example.com)
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(targetHost, suffix) {
				return nil
			}
		}

		// Exact domain match
		if pattern == targetHost {
			return nil
		}

		// Full URL prefix match
		if strings.HasPrefix(targetBase, pattern) || strings.HasPrefix(targetURL, pattern) {
			return nil
		}
	}

	return fmt.Errorf("URL not in allowlist: %s", targetHost)
}

func applyStripHeaders(config map[string]interface{}, headers http.Header) int {
	if headers == nil {
		return 0
	}

	stripList := extractStripHeaders(config)
	if len(stripList) == 0 {
		return 0
	}

	removed := 0
	for _, name := range stripList {
		if name == "" {
			continue
		}
		before := len(headers)
		headers.Del(name)
		if len(headers) < before {
			removed++
		}
	}
	return removed
}

func extractStripHeaders(config map[string]interface{}) []string {
	if config == nil {
		return nil
	}

	raw, ok := config["strip_headers"]
	if !ok {
		if alt, ok := config["stripHeaders"]; ok {
			raw = alt
		} else {
			return nil
		}
	}

	var result []string
	switch value := raw.(type) {
	case []interface{}:
		for _, item := range value {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				result = append(result, s)
			}
		}
	case []string:
		for _, item := range value {
			if strings.TrimSpace(item) != "" {
				result = append(result, item)
			}
		}
	default:
		if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
			result = append(result, s)
		}
	}
	return result
}

func resolveEgressTimeout(pipelineCtx *domain.PipelineContext, node *domain.PipelineNode) (time.Duration, []timeoutCandidate) {
	if node == nil {
		return 0, nil
	}

	var candidates []timeoutCandidate

	if pipelineCtx != nil && pipelineCtx.Pipeline != nil && pipelineCtx.Pipeline.Defaults.TimeoutMS > 0 {
		candidates = append(candidates, timeoutCandidate{
			source: "pipeline.defaults.timeoutMs",
			ms:     pipelineCtx.Pipeline.Defaults.TimeoutMS,
		})
	}

	if node.Governance.TimeoutMS > 0 {
		candidates = append(candidates, timeoutCandidate{
			source: fmt.Sprintf("node.%s.governance.timeoutMs", node.ID),
			ms:     node.Governance.TimeoutMS,
		})
	}

	if cfgTimeout, cfgSource := timeoutFromEgressConfig(node.Config); cfgTimeout > 0 {
		candidates = append(candidates, timeoutCandidate{source: cfgSource, ms: cfgTimeout})
	}

	return pickEgressTimeout(candidates)
}

func timeoutFromEgressConfig(config map[string]interface{}) (int, string) {
	if config == nil {
		return 0, ""
	}

	for _, key := range []string{"timeout_ms", "timeoutMs"} {
		if value, ok := config[key]; ok {
			if ms, ok := toInt(value); ok && ms > 0 {
				return ms, fmt.Sprintf("node.config.%s", key)
			}
		}
	}

	if spec, ok := config["spec"].(map[string]interface{}); ok {
		for _, key := range []string{"timeout_ms", "timeoutMs"} {
			if value, ok := spec[key]; ok {
				if ms, ok := toInt(value); ok && ms > 0 {
					return ms, fmt.Sprintf("node.config.spec.%s", key)
				}
			}
		}
	}

	return 0, ""
}

func pickEgressTimeout(candidates []timeoutCandidate) (time.Duration, []timeoutCandidate) {
	if len(candidates) == 0 {
		return 0, nil
	}

	shortest := candidates[0].ms
	for _, candidate := range candidates[1:] {
		if candidate.ms > 0 && candidate.ms < shortest {
			shortest = candidate.ms
		}
	}

	if shortest <= 0 {
		return 0, candidates
	}

	return time.Duration(shortest) * time.Millisecond, candidates
}

func streamingSettingsFromConfig(config map[string]interface{}) (bool, string, time.Duration) {
	if config == nil {
		return false, "", 0
	}

	enabled := boolFromConfig(config, "streaming") || boolFromConfig(config, "streaming_enabled")
	mode := stringFromConfig(config, "streaming_mode")
	idleTimeout := durationFromKeys(config, []string{"idle_timeout_ms", "idleTimeoutMs"})

	if spec, ok := config["spec"].(map[string]interface{}); ok {
		if !enabled {
			enabled = boolFromConfig(spec, "streaming") || boolFromConfig(spec, "streaming_enabled")
		}
		if mode == "" {
			mode = stringFromConfig(spec, "streaming_mode")
		}
		if idleTimeout == 0 {
			idleTimeout = durationFromKeys(spec, []string{"idle_timeout_ms", "idleTimeoutMs"})
		}
	}

	return enabled, mode, idleTimeout
}

func stringFromConfig(config map[string]interface{}, key string) string {
	if value, ok := config[key]; ok {
		switch v := value.(type) {
		case string:
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func boolFromConfig(config map[string]interface{}, key string) bool {
	if value, ok := config[key]; ok {
		switch v := value.(type) {
		case bool:
			return v
		case string:
			return strings.EqualFold(strings.TrimSpace(v), "true")
		case int:
			return v != 0
		case int32:
			return v != 0
		case int64:
			return v != 0
		case float64:
			return int(v) != 0
		case float32:
			return int(v) != 0
		}
	}
	return false
}

func durationFromKeys(config map[string]interface{}, keys []string) time.Duration {
	for _, key := range keys {
		if value, ok := config[key]; ok {
			if ms, ok := toInt(value); ok && ms > 0 {
				return time.Duration(ms) * time.Millisecond
			}
		}
	}
	return 0
}

func toInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	case string:
		if v == "" {
			return 0, false
		}
		var parsed int
		if _, err := fmt.Sscanf(v, "%d", &parsed); err == nil {
			return parsed, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// getHeader safely retrieves a header value from the multi-value header map.
func getHeader(headers map[string][]string, name string) string {
	values, ok := headers[name]
	if !ok || len(values) == 0 {
		// Try canonical form
		canonical := http.CanonicalHeaderKey(name)
		values, ok = headers[canonical]
		if !ok || len(values) == 0 {
			return ""
		}
	}
	return values[0]
}

// getUpstreamMode determines the upstream URL resolution mode from node configuration.
// Supported modes:
// - "proxy": Standard HTTP proxy protocol (extract from Host header or absolute URI)
// - "custom_header": Use X-Target-URL header (for LLM-directed agent calls)
// - "static": Use configured upstream_url (default)
func getUpstreamMode(config map[string]interface{}) string {
	if mode, ok := config["upstream_mode"].(string); ok {
		return mode
	}
	// Backward compatibility: check legacy allow_dynamic_upstream flag
	if allowDynamic, ok := config["allow_dynamic_upstream"].(bool); ok && allowDynamic {
		return "custom_header"
	}
	return "static"
}

// extractProxyTarget extracts the target URL from the incoming request using standard proxy semantics.
// It handles both absolute URIs (GET http://example.com/path) and relative URIs with Host header.
func (h *EgressHTTPHandler) extractProxyTarget(pipelineCtx *domain.PipelineContext) (*url.URL, error) {
	req := pipelineCtx.Request

	// Check if request URI is absolute (e.g., GET http://example.com/path HTTP/1.1)
	if strings.HasPrefix(req.Path, "http://") || strings.HasPrefix(req.Path, "https://") {
		// Parse absolute URI directly
		targetURL, err := url.Parse(req.Path)
		if err != nil {
			return nil, fmt.Errorf("invalid absolute URI: %w", err)
		}
		return targetURL, nil
	}

	// Extract Host header for relative URIs
	hostHeader := getHeader(req.Headers, "Host")

	// Fallback to Request.Host if header wasn't provided by the CLI or caller
	if hostHeader == "" {
		hostHeader = req.Host
		if hostHeader != "" {
			h.logger.Debug("egress handler: using host from request.Host fallback", "host", hostHeader)
		}
	}
	if hostHeader == "" {
		return nil, fmt.Errorf("missing Host header for proxy target resolution")
	}

	// Determine scheme. Default to https for security, but respect request protocol and proxy.allow_http
	scheme := "https"
	if strings.EqualFold(pipelineCtx.Request.Protocol, "http") {
		scheme = "http"
	}
	if useHTTP, ok := pipelineCtx.Variables["proxy.allow_http"].(bool); ok && useHTTP {
		scheme = "http"
	}

	// Build target URL
	targetURL := &url.URL{
		Scheme: scheme,
		Host:   hostHeader,
		Path:   req.Path,
	}

	// Add query parameters
	if rawQuery, ok := pipelineCtx.Variables["request.query"].(string); ok {
		targetURL.RawQuery = rawQuery
	}

	return targetURL, nil
}
