package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/policy"
	telem "github.com/polisai/polis-oss/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// PolicyHandler evaluates OPA policies against the current pipeline context.
// This handler respects node posture configuration (fail-open/fail-closed) and
// routes execution based on policy decision (success/failure edges).
type PolicyHandler struct {
	logger *slog.Logger
}

// NewPolicyHandler creates a new OPA policy evaluation handler.
func NewPolicyHandler(logger *slog.Logger) *PolicyHandler {
	if logger == nil {
		logger = slog.Default()
	}

	return &PolicyHandler{
		logger: logger,
	}
}

// Execute evaluates the policy and stores the decision in the pipeline context.
// Returns an error if evaluation fails and posture is fail-closed.
func (h *PolicyHandler) Execute(ctx context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	// Get pre-initialized engine from pipeline context
	if pipelineCtx.Pipeline == nil || pipelineCtx.Pipeline.EngineContext == nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("policy node %s: no pipeline engine context", node.ID)
	}

	engineAny, ok := pipelineCtx.Pipeline.EngineContext.GetPolicyEngine(node.ID)
	if !ok {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("policy node %s: no engine initialized", node.ID)
	}

	// Type assert to *policy.Engine
	engine, ok := engineAny.(*policy.Engine)
	if !ok || engine == nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("policy node %s: engine has wrong type", node.ID)
	}

	// Build policy input from pipeline context
	input := h.buildPolicyInput(pipelineCtx, node)

	// Evaluate policy
	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		h.logger.Error("policy handler: evaluation failed",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
			"error", err,
		)

		// Check node posture for failure handling
		posture := h.getPosture(node)
		if posture == "fail-closed" {
			return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("policy: evaluation failed (fail-closed): %w", err)
		}

		// Fail-open: log error but allow request to proceed
		h.logger.Warn("policy handler: evaluation failed but allowing due to fail-open posture",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
		)

		// Store failure in context for observability
		pipelineCtx.Variables["policy.evaluation_failed"] = true
		// Annotate span
		if span := trace.SpanFromContext(ctx); span != nil {
			span.AddEvent("policy.evaluate.error")
		}
		return runtime.Success(nil), nil
	}

	h.publishPolicyDecision(pipelineCtx, node, decision)

	// Record policy decision on the current span
	if span := trace.SpanFromContext(ctx); span != nil {
		telem.RecordPolicyDecision(span, decision)
	}

	h.logger.Info("policy handler: evaluation complete",
		"node_id", node.ID,
		"agent_id", pipelineCtx.Request.AgentID,
		"action", decision.Action,
		"reason", decision.Reason,
	)

	// Handle policy decision
	switch decision.Action {
	case policy.ActionAllow:
		return runtime.Success(nil), nil

	case policy.ActionRedact:
		// Store redaction flag for downstream handlers
		pipelineCtx.Variables["policy.redact_required"] = true
		return runtime.Success(nil), nil

	case policy.ActionBlock:
		// Policy denied the request - return without error to prevent retry
		// Policy decisions are deterministic and should not be retried
		return runtime.NodeResult{Outcome: runtime.OutcomeDeny}, nil

	default:
		h.logger.Warn("policy handler: unknown action",
			"node_id", node.ID,
			"agent_id", pipelineCtx.Request.AgentID,
			"action", decision.Action,
		)
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("policy: unknown action %q", decision.Action)
	}
}

// buildPolicyInput constructs a policy.Input from the pipeline context.
func (h *PolicyHandler) buildPolicyInput(pipelineCtx *domain.PipelineContext, node *domain.PipelineNode) policy.Input {
	// Extract identity from context variables (stored by auth handler if present)
	identity := domain.PolicyIdentity{}
	if subject, ok := pipelineCtx.Variables["auth.subject"].(string); ok {
		identity.Subject = subject
	}
	if issuer, ok := pipelineCtx.Variables["auth.issuer"].(string); ok {
		identity.Issuer = issuer
	}
	if pipelineCtx.Variables != nil {
		if audiences := extractStringSlice(pipelineCtx.Variables["auth.audiences"]); len(audiences) > 0 {
			identity.Audience = audiences
		}
		if scopes := collectScopes(pipelineCtx.Variables); len(scopes) > 0 {
			identity.Scopes = scopes
		}
	}

	// Build attributes map shared with policy bundles.
	attributes := map[string]any{
		"http.method":                pipelineCtx.Request.Method,
		"http.path":                  pipelineCtx.Request.Path,
		"protocol":                   pipelineCtx.Request.Protocol,
		"session.tokens_in":          pipelineCtx.Session.TotalTokensIn,
		"session.tokens_out":         pipelineCtx.Session.TotalTokensOut,
		"session.estimated_cost_usd": pipelineCtx.Session.EstimatedCostUSD,
	}

	// Add tenant and session identifiers if present
	if pipelineCtx.Request.TenantID != "" {
		attributes["tenant.id"] = pipelineCtx.Request.TenantID
	}
	if pipelineCtx.Request.SessionID != "" {
		attributes["session.id"] = pipelineCtx.Request.SessionID
	}

	// Get entrypoint from node configuration or use default
	entrypoint := "policy/decision"
	if ep, ok := node.Config["entrypoint"].(string); ok && ep != "" {
		entrypoint = ep
	}

	return policy.Input{
		RouteID:    pipelineCtx.Request.AgentID, // Using AgentID as RouteID for MVP
		Identity:   identity,
		Attributes: attributes,
		Findings:   make(map[string]any), // TODO: Populate from content scan results
		Entrypoint: entrypoint,
	}
}

func collectScopes(vars map[string]any) []string {
	if len(vars) == 0 {
		return nil
	}
	keys := []string{"auth.scopes", "auth.scope", "auth.claims.scope", "auth.claims.scp"}
	var scopes []string
	for _, key := range keys {
		values := extractStringSlice(vars[key])
		if len(values) > 0 {
			scopes = append(scopes, values...)
		}
	}
	return dedupeStrings(scopes)
}

func extractStringSlice(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 {
				return fields
			}
			return []string{trimmed}
		}
		return nil
	default:
		return nil
	}
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// getPosture extracts the failure posture from node configuration.
// Returns "fail-closed" by default for security.
func (h *PolicyHandler) getPosture(node *domain.PipelineNode) string {
	return resolveNodePosture(node, "fail-closed", h.logger)
}

func (h *PolicyHandler) publishPolicyDecision(pipelineCtx *domain.PipelineContext, node *domain.PipelineNode, decision policy.Decision) {
	if pipelineCtx.Variables == nil {
		pipelineCtx.Variables = make(map[string]any)
	}

	// Preserve legacy keys for compatibility.
	pipelineCtx.Variables["policy.action"] = string(decision.Action)
	pipelineCtx.Variables["policy.reason"] = decision.Reason
	if len(decision.Metadata) > 0 {
		pipelineCtx.Variables["policy.metadata"] = clonePolicyMetadata(decision.Metadata)
	}

	baseKey := fmt.Sprintf("policy.%s", node.ID)

	nodeSnapshot := map[string]any{
		"action": string(decision.Action),
		"reason": decision.Reason,
	}

	if len(decision.Metadata) > 0 {
		nodeSnapshot["metadata"] = clonePolicyMetadata(decision.Metadata)
	}

	if len(decision.Outputs) > 0 {
		nodeSnapshot["outputs"] = cloneAny(decision.Outputs)
	}

	pipelineCtx.Variables[baseKey] = nodeSnapshot

	flatten := func(key string, value any) {
		if key == "" {
			return
		}
		namespacedKey := fmt.Sprintf("%s.%s", baseKey, key)
		pipelineCtx.Variables[namespacedKey] = value
		if shouldPromoteKey(key) && isScalarValue(value) {
			if _, exists := pipelineCtx.Variables[key]; !exists {
				pipelineCtx.Variables[key] = value
			}
		}
	}

	for key, raw := range decision.Metadata {
		flatten(key, normalizeMetadataValue(raw))
	}

	for key, value := range decision.Outputs {
		flatten(key, value)
	}
}

func clonePolicyMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(metadata))
	for key, value := range metadata {
		cloned[key] = value
	}
	return cloned
}

func cloneAny(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func normalizeMetadataValue(value string) any {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return value
	}
	if b, err := strconv.ParseBool(trimmed); err == nil {
		return b
	}
	if i, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return f
	}
	return value
}

func shouldPromoteKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		allowed := r == '_' || r == '-' || r == '.' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
		if !allowed {
			return false
		}
		if i == 0 && (r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func isScalarValue(value any) bool {
	switch value.(type) {
	case nil:
		return false
	case string, bool, float32, float64, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}
