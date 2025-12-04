package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/policy/dlp"
)

// DLPHandler configures streaming response inspection for the egress stage.
//
// The handler parses configuration from the pipeline node and stores it in the
// pipeline context so that the egress handler can apply streaming redaction to
// the upstream response body. DLP nodes default to a fail-open posture: scanner
// errors will be logged and the response will proceed unless the rule action is
// block.
//
// DLPHandler stores DLP configuration for downstream egress processing.
type DLPHandler struct {
	logger   *slog.Logger
	registry *dlp.Registry
}

const (
	dlpModeStream   = "stream"
	dlpModeBuffered = "buffered"
)

// NewDLPHandler constructs a DLP handler instance.
func NewDLPHandler(logger *slog.Logger) *DLPHandler {
	return NewDLPHandlerWithRegistry(logger, dlp.GlobalRegistry())
}

// NewDLPHandlerWithRegistry constructs a DLP handler with a custom registry (useful for tests).
func NewDLPHandlerWithRegistry(logger *slog.Logger, registry *dlp.Registry) *DLPHandler {
	if logger == nil {
		logger = slog.Default()
	}
	if registry == nil {
		registry = dlp.GlobalRegistry()
	}
	return &DLPHandler{logger: logger, registry: registry}
}

// Execute stores DLP configuration for downstream egress processing.
func (h *DLPHandler) Execute(ctx context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	cfg, err := h.parseDLPConfig(node.Config)
	if err != nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, err
	}

	scope := strings.ToLower(cfg.Scope)
	if scope == "" {
		scope = "response"
	}

	posture := cfg.Posture
	if posture == "" {
		posture = resolveNodePosture(node, "fail-open", h.logger)
	}
	posture = strings.ToLower(posture)
	cfg.Posture = posture

	if len(cfg.Rules) == 0 {
		delete(pipelineCtx.Variables, "dlp.config")
		delete(pipelineCtx.Variables, "dlp.posture")
		return runtime.Success(nil), nil
	}

	switch scope {
	case "request":
		delete(pipelineCtx.Variables, "dlp.config")
		delete(pipelineCtx.Variables, "dlp.posture")
		return h.inspectRequest(ctx, node, pipelineCtx, cfg)
	default:
		mode := cfg.Mode
		if mode == "" {
			mode = dlpModeStream
		}
		cfg.Mode = mode

		pipelineCtx.Variables["dlp.config"] = cfg
		pipelineCtx.Variables["dlp.mode"] = mode
		pipelineCtx.Variables["dlp.posture"] = posture

		h.logger.Debug("dlp inspection enabled",
			"rules", len(cfg.Rules),
			"posture", posture,
			"scope", scope,
		)

		return runtime.Success(nil), nil
	}
}

func (h *DLPHandler) parseDLPConfig(config map[string]interface{}) (dlp.Config, error) {
	if config == nil {
		return dlp.Config{Scope: "response"}, nil
	}

	cfg := dlp.Config{}
	defaultAction := dlp.Action("")

	if action, ok := asString(config["action"]); ok {
		action = strings.ToLower(action)
		candidate := dlp.Action(action)
		if !isValidDLPAction(candidate) {
			return cfg, fmt.Errorf("dlp: invalid default action %q", action)
		}
		defaultAction = candidate
	}

	if rulesRaw, ok := config["rules"]; ok {
		rulesSlice, ok := rulesRaw.([]interface{})
		if !ok {
			return cfg, fmt.Errorf("dlp: rules must be an array")
		}
		for _, item := range rulesSlice {
			switch value := item.(type) {
			case string:
				rule, ok := h.registry.Resolve(value)
				if !ok {
					return cfg, fmt.Errorf("dlp: unknown rule id %q", value)
				}
				if defaultAction != "" {
					rule.Action = defaultAction
				}
				cfg.Rules = append(cfg.Rules, rule)
			case map[string]interface{}:
				rule, err := h.parseRuleDefinition(value, defaultAction)
				if err != nil {
					return cfg, err
				}
				cfg.Rules = append(cfg.Rules, rule)
			default:
				return cfg, fmt.Errorf("dlp: rule entries must be objects or identifiers")
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

	if mode, ok := asString(config["mode"]); ok {
		cfg.Mode = strings.ToLower(mode)
	}

	if scope, ok := asString(config["scope"]); ok {
		cfg.Scope = strings.ToLower(scope)
	}

	if posture, ok := asString(config["posture"]); ok {
		cfg.Posture = strings.ToLower(posture)
	}

	if cfg.Scope == "" {
		cfg.Scope = "response"
	}

	switch cfg.Scope {
	case "request", "response":
	default:
		return cfg, fmt.Errorf("dlp: unsupported scope %q", cfg.Scope)
	}

	if cfg.Mode == "" {
		cfg.Mode = dlpModeStream
	}

	return cfg, nil
}

func (h *DLPHandler) parseRuleDefinition(ruleMap map[string]interface{}, defaultAction dlp.Action) (dlp.Rule, error) {
	var baseRule dlp.Rule
	if id, ok := asString(ruleMap["id"]); ok && id != "" {
		rule, resolved := h.registry.Resolve(id)
		if !resolved {
			return dlp.Rule{}, fmt.Errorf("dlp: unknown rule id %q", id)
		}
		baseRule = rule
	}

	if name, ok := asString(ruleMap["name"]); ok && name != "" {
		baseRule.Name = name
	}

	if pattern, ok := asString(ruleMap["pattern"]); ok && pattern != "" {
		baseRule.Pattern = pattern
	}

	if action, ok := asString(ruleMap["action"]); ok && action != "" {
		candidate := dlp.Action(strings.ToLower(action))
		if !isValidDLPAction(candidate) {
			return dlp.Rule{}, fmt.Errorf("dlp: invalid action %q for rule", action)
		}
		baseRule.Action = candidate
	}

	if replacement, ok := asString(ruleMap["replacement"]); ok {
		baseRule.Replacement = replacement
	}

	if strings.TrimSpace(baseRule.Name) == "" {
		return dlp.Rule{}, fmt.Errorf("dlp: rule name is required")
	}
	if strings.TrimSpace(baseRule.Pattern) == "" {
		return dlp.Rule{}, fmt.Errorf("dlp: pattern is required for rule %s", baseRule.Name)
	}

	if defaultAction != "" {
		baseRule.Action = defaultAction
	} else if baseRule.Action == "" {
		baseRule.Action = dlp.ActionRedact
	}

	return baseRule, nil
}

func (h *DLPHandler) inspectRequest(_ context.Context, _ *domain.PipelineNode, pipelineCtx *domain.PipelineContext, cfg dlp.Config) (runtime.NodeResult, error) {
	body, _ := pipelineCtx.Variables["request.body"].(io.ReadCloser)
	if body == nil {
		return runtime.Success(nil), nil
	}

	const memoryThreshold = 1 * 1024 * 1024 // 1MB
	sanitizedBuffer := newHybridBuffer(memoryThreshold)
	rawBuffer := newHybridBuffer(memoryThreshold)

	defer func() {
		// Original body is fully consumed; ensure it is closed.
		if err := body.Close(); err != nil {
			h.logger.Warn("dlp request: failed to close request body", "error", err)
		}
	}()

	mode := cfg.Mode
	if mode == "" {
		mode = dlpModeStream
	}

	var (
		report dlp.Report
		err    error
	)

	switch mode {
	case dlpModeBuffered:
		payload, readErr := io.ReadAll(body)
		if readErr != nil {
			rawBuffer.Cleanup()
			sanitizedBuffer.Cleanup()
			return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("dlp: failed to read request body: %w", readErr)
		}
		if _, writeErr := rawBuffer.Write(payload); writeErr != nil {
			rawBuffer.Cleanup()
			sanitizedBuffer.Cleanup()
			return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("dlp: failed to buffer request body: %w", writeErr)
		}
		if cfg.MaxReadBytes > 0 && int64(len(payload)) > cfg.MaxReadBytes {
			rawBuffer.Cleanup()
			sanitizedBuffer.Cleanup()
			return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("dlp: inspected body exceeds max_read limit")
		}

		scanner, buildErr := dlp.NewScanner(cfg)
		if buildErr != nil {
			rawBuffer.Cleanup()
			sanitizedBuffer.Cleanup()
			return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("dlp: failed to build scanner: %w", buildErr)
		}

		// Use context.Background() for scanning to avoid context deadline
		// interrupting pattern matching. The scanner has its own bounds (MaxReadBytes,
		// MaxFindings) and the node timeout applies to the entire handler, not the scan operation.
		report, err = scanner.Scan(context.Background(), string(payload))
		if err == nil {
			target := payload
			if report.RedactionsApplied {
				target = []byte(report.Redacted)
			}
			if _, writeErr := sanitizedBuffer.Write(target); writeErr != nil {
				rawBuffer.Cleanup()
				sanitizedBuffer.Cleanup()
				return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("dlp: failed to buffer redacted body: %w", writeErr)
			}
		}
	default:
		redactor, buildErr := dlp.NewStreamRedactor(cfg)
		if buildErr != nil {
			rawBuffer.Cleanup()
			sanitizedBuffer.Cleanup()
			return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("dlp: failed to build redactor: %w", buildErr)
		}

		tee := io.TeeReader(body, rawBuffer)
		// Use context.Background() for stream redaction to avoid context deadline
		// interrupting I/O operations. The redactor has its own bounds (MaxReadBytes,
		// MaxFindings, ChunkSize) and the node timeout applies to the entire handler,
		// not individual chunk processing.
		report, err = redactor.RedactStream(context.Background(), tee, sanitizedBuffer)
	}

	if report.Blocked {
		rawBuffer.Cleanup()
		sanitizedBuffer.Cleanup()
		pipelineCtx.Security.Blocked = true
		pipelineCtx.Security.BlockReason = "dlp.blocked"
		// Return without error to prevent retry logic - DLP blocking is deterministic
		return runtime.NodeResult{Outcome: runtime.OutcomeDeny}, nil
	}

	if err != nil {
		if errors.Is(err, dlp.ErrBlocked) {
			pipelineCtx.Security.Blocked = true
			pipelineCtx.Security.BlockReason = "dlp.blocked"
			// Return without error to prevent retry - DLP blocking is deterministic
			return runtime.NodeResult{Outcome: runtime.OutcomeDeny}, nil
		}

		posture := strings.ToLower(cfg.Posture)
		if posture == "" {
			posture = "fail-open"
		}
		if posture == "fail-open" {
			h.logger.Warn("dlp request redaction error - allowing per fail-open posture",
				"error", err,
				"posture", posture,
			)

			replay, replayErr := rawBuffer.Reader()
			if replayErr != nil {
				rawBuffer.Cleanup()
				sanitizedBuffer.Cleanup()
				return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("dlp: failed to create request body replay: %w", replayErr)
			}
			pipelineCtx.Variables["request.body"] = replay
			rawBuffer = nil
			sanitizedBuffer.Cleanup()
			return runtime.Success(nil), nil
		}

		rawBuffer.Cleanup()
		sanitizedBuffer.Cleanup()
		return runtime.NodeResult{Outcome: runtime.OutcomeDeny}, fmt.Errorf("dlp: redaction error: %w", err)
	}

	replay, replayErr := sanitizedBuffer.Reader()
	if replayErr != nil {
		rawBuffer.Cleanup()
		sanitizedBuffer.Cleanup()
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("dlp: failed to prepare sanitized body: %w", replayErr)
	}

	pipelineCtx.Variables["request.body"] = replay
	rawBuffer.Cleanup()

	length := sanitizedBuffer.Len()
	if length >= 0 {
		h.updateRequestLength(pipelineCtx, length)
	}

	RecordDLPFindings(pipelineCtx, report, "request")

	return runtime.Success(nil), nil
}

func (h *DLPHandler) updateRequestLength(pipelineCtx *domain.PipelineContext, length int) {
	if pipelineCtx.Request.Headers == nil {
		pipelineCtx.Request.Headers = make(map[string][]string)
	}
	pipelineCtx.Request.Headers["Content-Length"] = []string{strconv.Itoa(length)}
	delete(pipelineCtx.Request.Headers, "Transfer-Encoding")
}

func isValidDLPAction(action dlp.Action) bool {
	switch action {
	case dlp.ActionAllow, dlp.ActionRedact, dlp.ActionBlock:
		return true
	default:
		return false
	}
}
