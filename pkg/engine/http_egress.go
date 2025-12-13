package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/polisai/polis-oss/internal/governance"
	"github.com/polisai/polis-oss/pkg/domain"
	handlers "github.com/polisai/polis-oss/pkg/engine/handlers"
	"github.com/polisai/polis-oss/pkg/policy/dlp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// executeEgressHTTP executes an egress HTTP request with optional DLP scanning and redaction.
// It supports both buffered and streaming DLP modes, with fail-open/fail-closed postures.
//
//nolint:gocyclo // Complexity justified by DLP hybrid buffering and fail-open logic
func (h *DAGHandler) executeEgressHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, pipelineCtx *domain.PipelineContext) error {
	// Extract egress request details from pipeline context
	targetURL, _ := pipelineCtx.Variables["egress.target_url"].(string)
	method, _ := pipelineCtx.Variables["egress.method"].(string)
	if method == "" {
		method = r.Method
	}

	// Get egress headers
	egressHeaders, ok := pipelineCtx.Variables["egress.headers"].(http.Header)
	if !ok {
		egressHeaders = make(http.Header)
	}

	// Get request body from context
	var reqBody io.Reader
	if body, ok := pipelineCtx.Variables["request.body"].(io.ReadCloser); ok && body != nil {
		reqBody = body
	}

	timeout := DefaultEgressTimeout
	var timeoutSources []string
	var timeoutCandidates []string

	if rawSources, ok := pipelineCtx.Variables["egress.timeout.sources"].([]string); ok && len(rawSources) > 0 {
		timeoutSources = append(timeoutSources, rawSources...)
	}

	if rawCandidates, ok := pipelineCtx.Variables["egress.timeout.candidates"].([]string); ok && len(rawCandidates) > 0 {
		timeoutCandidates = append(timeoutCandidates, rawCandidates...)
	}

	if rawTimeout, ok := pipelineCtx.Variables["egress.timeout"]; ok {
		switch v := rawTimeout.(type) {
		case time.Duration:
			if v > 0 {
				timeout = v
			}
		case int:
			if v > 0 {
				timeout = time.Duration(v)
			}
		case int64:
			if v > 0 {
				timeout = time.Duration(v)
			}
		}
	}

	if rawSelected, ok := pipelineCtx.Variables["egress.timeout.selected_ms"]; ok {
		switch v := rawSelected.(type) {
		case int:
			if v > 0 {
				timeout = time.Duration(v) * time.Millisecond
			}
		}
	}

	// Handle HTTPS CONNECT Tunneling
	if method == http.MethodConnect {
		h.logger.Info("establishing HTTPS tunnel", "target", targetURL)

		// 1. Hijack the connection
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return fmt.Errorf("webserver does not support hijacking")
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			return fmt.Errorf("failed to hijack connection: %w", err)
		}
		// Close client connection when done
		defer clientConn.Close()

		// 2. Dial Upstream
		// Extract Host:Port from URL (for CONNECT, path is usually host:port)
		// If scheme is present in targetURL, strip it, but usually targetURL from egress handler is proper.
		// However, for CONNECT, we need to ensure we have host:port.
		// The EgressHTTPHandler populates egress.target_url.
		// If it has http/https scheme, we strip it for Dial.

		connectTarget := targetURL
		if strings.HasPrefix(connectTarget, "http://") {
			connectTarget = strings.TrimPrefix(connectTarget, "http://")
		} else if strings.HasPrefix(connectTarget, "https://") {
			connectTarget = strings.TrimPrefix(connectTarget, "https://")
		}
		// Ensure port if missing (default to 443 for CONNECT)
		if !strings.Contains(connectTarget, ":") {
			connectTarget += ":443"
		}

		// Use a dialer with timeout
		dialer := net.Dialer{
			Timeout: timeout,
		}
		destConn, err := dialer.DialContext(ctx, "tcp", connectTarget)
		if err != nil {
			h.logger.Error("upstream dial failed", "target", connectTarget, "error", err)
			// Since we hijacked, we must write raw HTTP response
			_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return nil // We handled the error by writing to the connection
		}
		defer destConn.Close()

		// 3. Send 200 Connection Established to Client
		_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			h.logger.Error("failed to write 200 OK to client", "error", err)
			return nil
		}

		// 4. Bidirectional Copy
		h.logger.Debug("tunnel established, piping data", "target", connectTarget)
		go transfer(destConn, clientConn)
		transfer(clientConn, destConn)

		return nil
	}

	// Create egress request
	egressReq, err := http.NewRequestWithContext(ctx, method, targetURL, reqBody)

	if err != nil {
		return fmt.Errorf("failed to create egress request: %w", err)
	}

	// Copy headers
	egressReq.Header = egressHeaders

	// Ensure Transfer-Encoding is NOT sent in headers (it's a property of the request)
	egressReq.Header.Del("Transfer-Encoding")

	// Explicitly set ContentLength if present in headers (required for some upstreams like OpenAI)
	// We remove it from the header map to avoid duplication/conflicts, as http.Client uses the struct field.
	if cl := egressHeaders.Get("Content-Length"); cl != "" {
		if size, err := strconv.Atoi(cl); err == nil && size >= 0 {
			egressReq.ContentLength = int64(size)
			egressReq.TransferEncoding = nil
			egressReq.Header.Del("Content-Length")
		}
	}

	timeoutMs := int(timeout / time.Millisecond)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Update request with timeout context
	egressReq = egressReq.WithContext(ctx)

	logArgs := []any{
		"method", method,
		"target_url", targetURL,
		"timeout_ms", timeoutMs,
	}
	if len(timeoutSources) > 0 {
		logArgs = append(logArgs, "timeout_sources", timeoutSources)
	}
	if len(timeoutCandidates) > 0 {
		logArgs = append(logArgs, "timeout_candidates", timeoutCandidates)
	}
	h.logger.Debug("executing egress HTTP request", logArgs...)

	// Perform the request using shared client
	resp, err := h.httpClient.Do(egressReq)
	if err != nil {
		return fmt.Errorf("egress HTTP request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			h.logger.LogAttrs(ctx, slog.LevelWarn, "failed to close response body", slog.String("error", cerr.Error()))
		}
	}()

	pipelineCtx.Response.Status = resp.StatusCode
	pipelineCtx.Response.Headers = cloneHTTPHeaders(resp.Header)

	if rawOps, ok := pipelineCtx.Variables[handlers.ResponseTransformKey]; ok {
		if ops, ok := rawOps.([]handlers.HeaderTransformOperation); ok && len(ops) > 0 {
			h.logger.Debug("applying response header transforms", "operations", len(ops))
			handlers.ApplyResponseHeaderTransforms(ops, resp.Header, pipelineCtx)
			pipelineCtx.Response.Headers = cloneHTTPHeaders(resp.Header)
			delete(pipelineCtx.Variables, handlers.ResponseTransformKey)
		}
	}

	var (
		dlpCfg     dlp.Config
		dlpEnabled bool
	)

	streamingEnabled := pipelineCtx.Request.Streaming
	if val, ok := pipelineCtx.Variables["egress.streaming.enabled"].(bool); ok && val {
		streamingEnabled = true
	}

	streamingMode := pipelineCtx.Request.StreamingMode
	if mode, ok := pipelineCtx.Variables["egress.streaming.mode"].(string); ok && mode != "" {
		streamingMode = mode
		pipelineCtx.Request.StreamingMode = mode
	}
	if streamingEnabled {
		pipelineCtx.Variables["response.streaming"] = true
		if streamingMode != "" {
			pipelineCtx.Variables["response.streaming.mode"] = streamingMode
		}
	}

	idleTimeout := streamingIdleTimeoutFromContext(pipelineCtx)

	if cfg, ok := pipelineCtx.Variables["dlp.config"].(dlp.Config); ok && len(cfg.Rules) > 0 {
		dlpCfg = cfg
		dlpEnabled = true
	}

	// Copy response headers to client (filtering hop-by-hop headers)
	copyResponseHeaders(w.Header(), resp.Header)

	if dlpEnabled || streamingEnabled {
		w.Header().Del("Content-Length")
		delete(pipelineCtx.Response.Headers, "Content-Length")
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	streamWriter := newFlushCountingWriter(w)
	bodyReader := io.Reader(resp.Body)
	if streamingEnabled && idleTimeout > 0 {
		bodyReader = governance.NewIdleTimeoutReader(resp, idleTimeout)
	}

	if streamingEnabled {
		h.logger.Debug("egress streaming active",
			"target_url", targetURL,
			"mode", streamingMode,
			"idle_timeout_ms", int(idleTimeout/time.Millisecond),
		)
	}

	var dlpReport dlp.Report

	if dlpEnabled {
		cfg := dlpCfg
		mode := strings.ToLower(cfg.Mode)
		if mode == "" {
			mode = "stream"
		}

		var (
			dlpErr     error
			rawPayload []byte
		)

		switch mode {
		case "buffered":
			rawPayload, err = io.ReadAll(bodyReader)
			if err != nil {
				return fmt.Errorf("dlp: failed to read response: %w", err)
			}

			if cfg.MaxReadBytes > 0 && int64(len(rawPayload)) > cfg.MaxReadBytes {
				dlpErr = fmt.Errorf("dlp: inspected body exceeds max_read limit")
				break
			}

			scanner, buildErr := dlp.NewScanner(cfg)
			if buildErr != nil {
				return fmt.Errorf("dlp: failed to build scanner: %w", buildErr)
			}

			dlpReport, dlpErr = scanner.Scan(ctx, string(rawPayload))
			if dlpErr == nil && !dlpReport.Blocked {
				bodyToWrite := rawPayload
				if dlpReport.RedactionsApplied {
					bodyToWrite = []byte(dlpReport.Redacted)
				}
				if _, writeErr := streamWriter.Write(bodyToWrite); writeErr != nil {
					return fmt.Errorf("failed to write response body: %w", writeErr)
				}
			}
		default:
			// Stream mode with hybrid buffering: buffer small responses (<1MB) in memory
			// to enable fail-open recovery, spill larger responses to stream-only mode.
			const memoryThreshold = 1 * 1024 * 1024 // 1MB
			posture := strings.ToLower(getDLPPosture(pipelineCtx))
			needsFailOpenRecovery := (posture == "fail-open" || posture == "")

			redactor, buildErr := dlp.NewStreamRedactor(cfg)
			if buildErr != nil {
				h.logger.Error("failed to build dlp redactor", "error", buildErr)
				return fmt.Errorf("dlp: failed to build redactor: %w", buildErr)
			}

			if needsFailOpenRecovery {
				// Hybrid approach: buffer in memory for fail-open recovery
				var memBuf bytes.Buffer
				teeReader := io.TeeReader(bodyReader, &memBuf)

				// Track how much we've buffered (limit to threshold to detect overflow)
				limitedReader := io.LimitReader(teeReader, memoryThreshold)

				dlpReport, dlpErr = redactor.RedactStream(ctx, limitedReader, streamWriter)

				// Check if we hit the threshold (need to continue streaming)
				if memBuf.Len() >= int(memoryThreshold) {
					// Large response: continue streaming without buffer
					h.logger.Debug("dlp: response hit memory threshold, continuing without fail-open recovery",
						"buffered_bytes", memBuf.Len(),
						"threshold", memoryThreshold,
					)
					// Copy remaining data from original reader
					if _, copyErr := io.Copy(streamWriter, bodyReader); copyErr != nil {
						h.logger.Error("failed to copy remaining response", "error", copyErr)
						return fmt.Errorf("failed to copy remaining response: %w", copyErr)
					}
					rawPayload = nil // Cannot recover if error occurs
				} else {
					// Small response: fully buffered, can recover on error
					rawPayload = memBuf.Bytes()
				}
			} else {
				// Fail-closed: stream directly without buffering
				dlpReport, dlpErr = redactor.RedactStream(ctx, bodyReader, streamWriter)
			}
		}

		handlers.RecordDLPFindings(pipelineCtx, dlpReport, "response")

		if dlpReport.Blocked {
			pipelineCtx.Security.Blocked = true
			pipelineCtx.Security.BlockReason = "dlp.blocked"
			return fmt.Errorf("dlp: response blocked by policy")
		}

		if dlpErr != nil {
			if errors.Is(dlpErr, dlp.ErrBlocked) {
				pipelineCtx.Security.Blocked = true
				pipelineCtx.Security.BlockReason = "dlp.blocked"
				return fmt.Errorf("dlp: response blocked by policy")
			}

			posture := strings.ToLower(getDLPPosture(pipelineCtx))
			if posture == "fail-open" || posture == "" {
				h.logger.Warn("dlp redaction error - falling back to raw body",
					"error", dlpErr,
					"posture", posture,
				)
				switch mode {
				case "buffered":
					// Buffered mode: rawPayload is available, write it to client
					if len(rawPayload) > 0 {
						if _, writeErr := streamWriter.Write(rawPayload); writeErr != nil {
							h.logger.Error("failed to write buffered response after dlp error", "error", writeErr)
							return fmt.Errorf("failed to write response body: %w", writeErr)
						}
					}
				default:
					// Stream mode: response body has already been consumed by RedactStream.
					// Cannot recover original response data. The client will receive an
					// incomplete response. To avoid this, configure DLP with fail-closed
					// posture or use buffered mode for fail-open scenarios.
					h.logger.Error("dlp stream redaction failed with fail-open posture - response may be incomplete",
						"error", dlpErr,
						"posture", posture,
					)
					// Attempt to copy any remaining data (likely none)
					if _, copyErr := io.Copy(streamWriter, bodyReader); copyErr != nil {
						h.logger.Error("failed to copy response body after dlp error", "error", copyErr)
						return fmt.Errorf("failed to copy response body: %w", copyErr)
					}
				}
			} else {
				return fmt.Errorf("dlp: redaction error: %w", dlpErr)
			}
		}
	} else {
		if _, err := io.Copy(streamWriter, bodyReader); err != nil {
			h.logger.Error("failed to copy response body", "error", err)
			return fmt.Errorf("failed to copy response body: %w", err)
		}
	}

	pipelineCtx.Response.BytesSent = streamWriter.count

	h.logger.Debug("egress HTTP request completed",
		"status_code", resp.StatusCode,
		"target_url", targetURL,
	)

	// Attach summarized egress info to the current span (avoid sensitive data)
	if span := trace.SpanFromContext(ctx); span != nil {
		attrs := []attribute.KeyValue{
			attribute.Int("http.status_code", resp.StatusCode),
			attribute.Int64("http.response_body_size", streamWriter.count),
		}
		if timeoutMs > 0 {
			attrs = append(attrs, attribute.Int("proxy.egress.timeout_ms", timeoutMs))
		}
		if len(timeoutSources) > 0 {
			attrs = append(attrs, attribute.StringSlice("proxy.egress.timeout_sources", timeoutSources))
		}
		if len(timeoutCandidates) > 0 {
			attrs = append(attrs, attribute.StringSlice("proxy.egress.timeout_candidates", timeoutCandidates))
		}
		if streamingEnabled {
			attrs = append(attrs, attribute.Bool("proxy.egress.streaming", true))
			if streamingMode != "" {
				attrs = append(attrs, attribute.String("proxy.egress.streaming_mode", streamingMode))
			}
			if idleTimeout > 0 {
				attrs = append(attrs, attribute.Int("proxy.egress.streaming_idle_timeout_ms", int(idleTimeout/time.Millisecond)))
			}
		}
		span.SetAttributes(attrs...)
		span.AddEvent("egress.http.complete")
	}

	return nil
}

// copyResponseHeaders copies HTTP response headers from source to destination, filtering hop-by-hop headers.
func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		// Skip hop-by-hop headers per RFC 7230
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// cloneHTTPHeaders creates a deep copy of HTTP headers.
func cloneHTTPHeaders(src http.Header) map[string][]string {
	if len(src) == 0 {
		return map[string][]string{}
	}
	headers := make(map[string][]string, len(src))
	for key, values := range src {
		headers[key] = append([]string(nil), values...)
	}
	return headers
}

func streamingIdleTimeoutFromContext(pipelineCtx *domain.PipelineContext) time.Duration {
	if pipelineCtx == nil {
		return 0
	}
	if pipelineCtx.Variables == nil {
		return 0
	}

	if d, ok := pipelineCtx.Variables["egress.streaming.idle_timeout"].(time.Duration); ok && d > 0 {
		return d
	}

	if raw, ok := pipelineCtx.Variables["egress.streaming.idle_timeout_ms"]; ok {
		switch v := raw.(type) {
		case int:
			if v > 0 {
				return time.Duration(v) * time.Millisecond
			}
		case int64:
			if v > 0 {
				return time.Duration(v) * time.Millisecond
			}
		case float64:
			if v > 0 {
				return time.Duration(int64(v)) * time.Millisecond
			}
		case float32:
			if v > 0 {
				return time.Duration(int(v)) * time.Millisecond
			}
		}
	}

	return 0
}

// flushCountingWriter wraps an http.ResponseWriter to count bytes written and auto-flush.
type flushCountingWriter struct {
	http.ResponseWriter
	flusher http.Flusher
	count   int64
}

// newFlushCountingWriter creates a new flushCountingWriter.
func newFlushCountingWriter(w http.ResponseWriter) *flushCountingWriter {
	fw := &flushCountingWriter{ResponseWriter: w}
	if flusher, ok := w.(http.Flusher); ok {
		fw.flusher = flusher
	}
	return fw
}

// Write writes data to the underlying ResponseWriter and auto-flushes if supported.
func (w *flushCountingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err == nil {
		w.count += int64(n)
		if w.flusher != nil {
			w.flusher.Flush()
		}
	}
	return n, err
}

// isHopByHopHeader identifies HTTP hop-by-hop headers that should not be forwarded.
func isHopByHopHeader(header string) bool {
	// Per RFC 7230, these headers are hop-by-hop and must not be forwarded
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	headerLower := strings.ToLower(header)
	for _, h := range hopByHop {
		if strings.ToLower(h) == headerLower {
			return true
		}
	}
	return false
}

// transfer copies data from src to dst until EOF or error.
func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()

	if _, err := io.Copy(dst, src); err != nil {
		// Log error if needed, but usually just connection close
	}
}
