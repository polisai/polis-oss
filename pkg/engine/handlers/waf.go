package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/policy/waf"
)

// WAFHandler performs streaming request inspection prior to egress.
//
// The handler reads the inbound request body once, applies the configured WAF
// rules, and stores the replayable body back into the pipeline context. This
// ensures downstream handlers can stream the request to upstream services
// without buffering while allowing the WAF to enforce fail-closed posture.
//
// Uses a hybrid approach: small bodies (<1MB) are buffered in memory for fast
// replay, while larger bodies spill to temporary files to control memory usage.
//
// Configuration (node.Config):
//
//	rules:       []map[string]any {name, pattern, severity, action}
//	chunk_size:  int (optional, bytes; default 16KB)
//	overlap:     int (optional, bytes; default 256)
//	max_read:    int (optional, max inspected bytes)
//	max_matches: int (optional, cap on recorded findings)
//
// Posture: defaults to fail-closed. Set node.Posture to "fail-open" to allow
// traffic to continue even when a blocking rule matches (violations recorded).
type WAFHandler struct {
	logger   *slog.Logger
	registry *waf.Registry
}

// NewWAFHandler constructs a WAF handler with the provided logger.
func NewWAFHandler(logger *slog.Logger) *WAFHandler {
	return NewWAFHandlerWithRegistry(logger, waf.GlobalRegistry())
}

// NewWAFHandlerWithRegistry constructs a WAF handler with a custom registry (mainly for tests).
func NewWAFHandlerWithRegistry(logger *slog.Logger, registry *waf.Registry) *WAFHandler {
	if logger == nil {
		logger = slog.Default()
	}
	if registry == nil {
		registry = waf.GlobalRegistry()
	}
	return &WAFHandler{logger: logger, registry: registry}
}

// Execute runs streaming inspection against the request body.
func (h *WAFHandler) Execute(ctx context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	h.logger.InfoContext(ctx, "WAF handler invoked", "node_id", node.ID)

	cfg, err := h.parseWAFConfig(node.Config)
	if err != nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, err
	}

	posture := resolveNodePosture(node, "fail-closed", h.logger)

	if len(cfg.Rules) == 0 {
		// Nothing to inspect; keep body untouched.
		return runtime.Success(nil), nil
	}

	body, _ := pipelineCtx.Variables["request.body"].(io.ReadCloser)
	if body == nil {
		return runtime.Success(nil), nil
	}

	// Build stream inspector
	inspector, err := waf.NewStreamInspector(cfg)
	if err != nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("waf: failed to build inspector: %w", err)
	}

	// Inspect and replay using hybrid approach (memory/file)
	replayBody, report, err := h.inspectAndReplay(ctx, body, inspector)
	if err != nil {
		h.logger.ErrorContext(ctx, "waf inspection failed", "error", err)
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, err
	}

	pipelineCtx.Variables["request.body"] = replayBody

	h.recordFindings(pipelineCtx, report)

	h.logger.InfoContext(ctx, "waf inspection complete",
		"node_id", node.ID,
		"matches", len(report.Matches),
		"blocked", report.Blocked,
		"posture", posture,
	)

	if report.Blocked {
		pipelineCtx.Security.Blocked = true
		pipelineCtx.Security.BlockReason = "waf.blocked"

		if !isFailOpen(posture) {
			for _, m := range report.Matches {
				h.logger.InfoContext(ctx, "waf match detail", "rule", m.Rule, "match", m.Match)
			}
			h.logger.InfoContext(ctx, "waf blocking request",
				"node_id", node.ID,
				"matches", len(report.Matches),
			)
			// Return without error to prevent retry - WAF blocking is deterministic
			return runtime.NodeResult{Outcome: runtime.OutcomeDeny}, nil
		}
	}

	return runtime.Success(nil), nil
}

func (h *WAFHandler) inspectAndReplay(ctx context.Context, body io.ReadCloser, inspector *waf.StreamInspector) (io.ReadCloser, waf.Report, error) {
	defer func() {
		if err := body.Close(); err != nil {
			h.logger.WarnContext(ctx, "failed to close request body", "error", err)
		}
	}()

	// Hybrid approach: use in-memory buffer for small bodies (<1MB),
	// spill to temp file for larger bodies to control memory usage.
	const memoryThreshold = 1 * 1024 * 1024 // 1MB

	var (
		memBuf    bytes.Buffer
		tmpFile   *os.File
		totalRead int64
		useFile   bool
	)

	cleanup := func() {
		if tmpFile != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
		}
	}

	buffer := make([]byte, inspector.ChunkSize())
	for {
		// Note: io.Reader.Read is context-agnostic and cannot be canceled via context.
		// The handler's context timeout/cancellation applies to the overall execution,
		// not to individual I/O operations. Use context.Background() for inspector calls
		// to avoid mid-inspection cancellation, but Read() itself is unaffected.
		n, readErr := body.Read(buffer)
		if n > 0 {
			// Inspect chunk with background context to avoid mid-inspection cancellation
			if err := inspector.Process(context.Background(), buffer[:n]); err != nil {
				cleanup()
				return nil, inspector.Report(), fmt.Errorf("waf: inspection failed: %w", err)
			}

			totalRead += int64(n)

			// Decide where to store: memory or file
			if !useFile && totalRead <= memoryThreshold {
				// Small body: buffer in memory
				_, _ = memBuf.Write(buffer[:n]) // bytes.Buffer.Write never returns an error
			} else {
				// Large body: spill to temp file
				if !useFile {
					// First time exceeding threshold - create temp file
					var err error
					tmpFile, err = os.CreateTemp("", "proxy-waf-*")
					if err != nil {
						return nil, waf.Report{}, fmt.Errorf("waf: failed to create temp file: %w", err)
					}
					useFile = true

					// Write existing memory buffer to file
					if memBuf.Len() > 0 {
						if _, err := tmpFile.Write(memBuf.Bytes()); err != nil {
							cleanup()
							return nil, inspector.Report(), fmt.Errorf("waf: failed to write buffer to file: %w", err)
						}
						memBuf.Reset() // Free memory
					}
				}

				// Write current chunk to file
				if _, err := tmpFile.Write(buffer[:n]); err != nil {
					cleanup()
					return nil, inspector.Report(), fmt.Errorf("waf: failed to buffer body: %w", err)
				}
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			cleanup()
			return nil, inspector.Report(), fmt.Errorf("waf: failed to read body: %w", readErr)
		}
	}

	// Return appropriate replay body
	if useFile {
		// File-based replay
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			cleanup()
			return nil, inspector.Report(), fmt.Errorf("waf: failed to rewind body: %w", err)
		}
		replay := &tempReplayBody{file: tmpFile, path: tmpFile.Name()}
		return replay, inspector.Report(), nil
	}

	// Memory-based replay
	replay := io.NopCloser(bytes.NewReader(memBuf.Bytes()))
	return replay, inspector.Report(), nil
}

func (h *WAFHandler) recordFindings(pipelineCtx *domain.PipelineContext, report waf.Report) {
	if len(report.Matches) == 0 {
		return
	}

	highestWeight := severityWeight(waf.SeverityLow)
	highestLabel := string(waf.SeverityLow)
	for _, match := range report.Matches {
		metadata := map[string]interface{}{
			"match":  match.Match,
			"start":  match.Start,
			"end":    match.End,
			"action": string(match.Action),
		}
		finding := domain.SecurityFinding{
			Source:   "waf",
			RuleID:   match.Rule,
			Severity: string(match.Severity),
			Action:   string(match.Action),
			Summary:  fmt.Sprintf("WAF rule %s matched request body", match.Rule),
			Metadata: metadata,
		}
		pipelineCtx.Security.Findings = append(pipelineCtx.Security.Findings, finding)

		if weight := severityWeight(match.Severity); weight > highestWeight {
			highestWeight = weight
			highestLabel = string(match.Severity)
		}

		if match.Action == waf.ActionBlock {
			violation := domain.Violation{
				Code:     "WAF_BLOCKED",
				Severity: string(match.Severity),
				Message:  fmt.Sprintf("waf rule %s blocked request", match.Rule),
				Details:  metadata,
			}
			pipelineCtx.Security.Violations = append(pipelineCtx.Security.Violations, violation)
		}
	}

	key := "http.request.body"
	pipelineCtx.Telemetry.Taints[key] = domain.TelemetryTaint{
		Attribute: key,
		Reason:    "waf.match",
		Severity:  highestLabel,
		Source:    "waf",
	}
}

func (h *WAFHandler) parseWAFConfig(config map[string]interface{}) (waf.Config, error) {
	if config == nil {
		return waf.Config{}, nil
	}

	cfg := waf.Config{}
	defaultAction := waf.Action("")
	defaultSeverity := waf.Severity("")

	if action, ok := asString(config["action"]); ok {
		action = strings.ToLower(action)
		candidate := waf.Action(action)
		if !isValidWAFAction(candidate) {
			return cfg, fmt.Errorf("waf: invalid default action %q", action)
		}
		defaultAction = candidate
	}

	if severity, ok := asString(config["severity"]); ok {
		severity = strings.ToLower(severity)
		candidate := waf.Severity(severity)
		if !isValidWAFSeverity(candidate) {
			return cfg, fmt.Errorf("waf: invalid default severity %q", severity)
		}
		defaultSeverity = candidate
	}

	if rulesRaw, ok := config["rules"]; ok {
		rulesSlice, ok := rulesRaw.([]interface{})
		if !ok {
			return cfg, fmt.Errorf("waf: rules must be an array")
		}
		for _, item := range rulesSlice {
			switch value := item.(type) {
			case string:
				rule, ok := h.registry.Resolve(value)
				if !ok {
					return cfg, fmt.Errorf("waf: unknown rule id %q", value)
				}
				cfg.Rules = append(cfg.Rules, rule)
			case map[string]interface{}:
				rule, err := h.parseWAFRuleDefinition(value, defaultAction, defaultSeverity)
				if err != nil {
					return cfg, err
				}
				cfg.Rules = append(cfg.Rules, rule)
			default:
				return cfg, fmt.Errorf("waf: rule entries must be objects or identifiers")
			}
		}
	}

	if chunkSize, ok := asInt(config["chunk_size"]); ok {
		cfg.ChunkSize = chunkSize
	}
	if overlap, ok := asInt(config["overlap"]); ok {
		cfg.Overlap = overlap
	}
	if maxRead, ok := asInt64(config["max_read"]); ok {
		cfg.MaxReadBytes = maxRead
	}
	if maxMatches, ok := asInt(config["max_matches"]); ok {
		cfg.MaxFindings = maxMatches
	}

	return cfg, nil
}

func (h *WAFHandler) parseWAFRuleDefinition(ruleMap map[string]interface{}, defaultAction waf.Action, defaultSeverity waf.Severity) (waf.Rule, error) {
	var baseRule waf.Rule
	if id, ok := asString(ruleMap["id"]); ok && id != "" {
		rule, resolved := h.registry.Resolve(id)
		if !resolved {
			return waf.Rule{}, fmt.Errorf("waf: unknown rule id %q", id)
		}
		baseRule = rule
	}

	if name, ok := asString(ruleMap["name"]); ok && name != "" {
		baseRule.Name = name
	}

	if pattern, ok := asString(ruleMap["pattern"]); ok && pattern != "" {
		baseRule.Pattern = pattern
	}

	if severity, ok := asString(ruleMap["severity"]); ok && severity != "" {
		candidate := waf.Severity(strings.ToLower(severity))
		if !isValidWAFSeverity(candidate) {
			return waf.Rule{}, fmt.Errorf("waf: invalid severity %q for rule", severity)
		}
		baseRule.Severity = candidate
	}

	if action, ok := asString(ruleMap["action"]); ok && action != "" {
		candidate := waf.Action(strings.ToLower(action))
		if !isValidWAFAction(candidate) {
			return waf.Rule{}, fmt.Errorf("waf: invalid action %q for rule", action)
		}
		baseRule.Action = candidate
	}

	if strings.TrimSpace(baseRule.Name) == "" {
		return waf.Rule{}, fmt.Errorf("waf: rule name is required")
	}
	if strings.TrimSpace(baseRule.Pattern) == "" {
		return waf.Rule{}, fmt.Errorf("waf: pattern is required for rule %s", baseRule.Name)
	}

	if baseRule.Action == "" {
		if defaultAction != "" {
			baseRule.Action = defaultAction
		} else {
			baseRule.Action = waf.ActionBlock
		}
	}

	if baseRule.Severity == "" {
		if defaultSeverity != "" {
			baseRule.Severity = defaultSeverity
		} else {
			baseRule.Severity = waf.SeverityMedium
		}
	}

	return baseRule, nil
}

func isValidWAFAction(action waf.Action) bool {
	switch action {
	case waf.ActionAllow, waf.ActionBlock:
		return true
	default:
		return false
	}
}

func isValidWAFSeverity(severity waf.Severity) bool {
	switch severity {
	case waf.SeverityLow, waf.SeverityMedium, waf.SeverityHigh:
		return true
	default:
		return false
	}
}

func isFailOpen(posture string) bool {
	return strings.EqualFold(posture, "fail-open")
}

func asString(value interface{}) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case fmt.Stringer:
		return v.String(), true
	default:
		return "", false
	}
}

func asInt(value interface{}) (int, bool) {
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
	default:
		return 0, false
	}
}

func asInt64(value interface{}) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case float32:
		return int64(v), true
	default:
		return 0, false
	}
}

func severityWeight(sev waf.Severity) int {
	switch strings.ToLower(string(sev)) {
	case string(waf.SeverityHigh):
		return 3
	case string(waf.SeverityMedium):
		return 2
	case string(waf.SeverityLow):
		fallthrough
	default:
		return 1
	}
}
