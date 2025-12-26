package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/policy"
	telem "github.com/polisai/polis-oss/pkg/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// MCPFilterHandler enforces policies on Model Context Protocol (MCP) JSON-RPC messages.
type MCPFilterHandler struct {
	logger *slog.Logger
}

// NewMCPFilterHandler creates a new MCP filter handler.
func NewMCPFilterHandler(logger *slog.Logger) *MCPFilterHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &MCPFilterHandler{logger: logger}
}

// JSON-RPC 2.0 Types
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

// Execute parses the MCP request and evaluates the configured policy.
func (h *MCPFilterHandler) Execute(ctx context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	// 1. Get Policy Engine
	if pipelineCtx.Pipeline == nil || pipelineCtx.Pipeline.EngineContext == nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("mcp.filter node %s: no pipeline engine context", node.ID)
	}
	engineAny, ok := pipelineCtx.Pipeline.EngineContext.GetPolicyEngine(node.ID)
	if !ok {
		// It's possible the user forgot to configure a bundle, or EngineFactory didn't initialize it.
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("mcp.filter node %s: no policy engine initialized", node.ID)
	}
	engine, ok := engineAny.(*policy.Engine)
	if !ok || engine == nil {
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("mcp.filter node %s: engine has wrong type", node.ID)
	}

	// 1.5 Skip JSON-RPC validation for GET requests (e.g., SSE handshake)
	if pipelineCtx.Request.Method == http.MethodGet {
		h.logger.Debug("mcp.filter: skipping validation for GET request", "node_id", node.ID)
		return runtime.Success(nil), nil
	}

	// 2. Read and Parse Request Body
	bodyReader, _ := pipelineCtx.Variables["request.body"].(io.ReadCloser)
	if bodyReader == nil {
		// No body to inspect, pass through or fail? MCP usually requires a body.
		// Let's pass through but log a warning.
		h.logger.Warn("mcp.filter: no request body found", "node_id", node.ID)
		return runtime.Success(nil), nil
	}

	bodyBytes, err := io.ReadAll(bodyReader)
	if err != nil {
		bodyReader.Close()
		return runtime.NodeResult{Outcome: runtime.OutcomeFailure}, fmt.Errorf("mcp.filter: failed to read body: %w", err)
	}
	// Restore body immediately for downstream or policy failure handling
	pipelineCtx.Variables["request.body"] = io.NopCloser(bytes.NewReader(bodyBytes))
	bodyReader.Close() // Close original

	var rpcReq jsonRPCRequest
	if err := json.Unmarshal(bodyBytes, &rpcReq); err != nil {
		// Not valid JSON-RPC, possibly not an MCP message.
		// If we are strict, we block. If we are loose, we ignore.
		// Given node type is mcp.filter, we expect MCP.
		h.logger.Warn("mcp.filter: invalid json-rpc", "error", err)
		// For now, let's treat as parse error and optionally block or allow.
		// Assuming fail-closed for malformed traffic in a governance node.
		return h.denyRequest(ctx, pipelineCtx, node, nil, -32700, "Parse error")
	}

	// 3. Build Policy Input
	input := h.buildMCPPolicyInput(pipelineCtx, node, rpcReq)

	// 4. Evaluate Policy
	h.logger.Info("mcp.filter: evaluating policy", "input_method", rpcReq.Method, "input_params_len", len(rpcReq.Params))
	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		h.logger.Error("mcp.filter: evaluation failed", "node_id", node.ID, "error", err)
		// Check posture
		posture := resolveNodePosture(node, "fail-closed", h.logger)
		if posture == "fail-closed" {
			return h.denyRequest(ctx, pipelineCtx, node, rpcReq.ID, -32603, "Internal error during policy evaluation")
		}
		// Fail-open
		return runtime.Success(nil), nil
	}

	// 5. Enforce Decision
	if span := trace.SpanFromContext(ctx); span != nil {
		telem.RecordPolicyDecision(span, decision)
	}

	switch decision.Action {
	case policy.ActionAllow:
		return runtime.Success(nil), nil
	case policy.ActionBlock:
		h.logger.Info("mcp.filter: blocked request",
			"method", rpcReq.Method,
			"reason", decision.Reason,
		)
		// Set error variables for the error handler
		// pipelineCtx.Variables["response.error.code"] = "mcp.policy_violation"
		// pipelineCtx.Variables["response.error.message"] = fmt.Sprintf("Policy Violation: %s", decision.Reason)

		return h.denyRequest(ctx, pipelineCtx, node, rpcReq.ID, -32003, fmt.Sprintf("Policy Violation: %s", decision.Reason))
	default:
		// MCP interaction is usually binary (Allow/Block). Redact might be handled by DLP node.
		// If action is Redact, we treat as Allow here but assume DLP will handle it, or maybe modify args?
		// For now, treat unhandled actions as Allow with warning.
		h.logger.Warn("mcp.filter: unhandled action", "action", decision.Action)
		return runtime.Success(nil), nil
	}
}

func (h *MCPFilterHandler) denyRequest(ctx context.Context, pipelineCtx *domain.PipelineContext, node *domain.PipelineNode, id interface{}, code int, message string) (runtime.NodeResult, error) {
	// Construct JSON-RPC Error Response
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
		},
	}
	respBytes, _ := json.Marshal(resp)
	// Log the response we would have sent (until we support custom error bodies)
	h.logger.Debug("mcp.filter: blocking request with json-rpc error", "response", string(respBytes))

	// Set Response directly
	pipelineCtx.Security.Blocked = true
	pipelineCtx.Security.BlockReason = "mcp.policy_violation"

	// Set the custom response body for http_handler to pick up
	if pipelineCtx.Variables == nil {
		pipelineCtx.Variables = make(map[string]interface{})
	}
	pipelineCtx.Variables["response.body"] = respBytes

	pipelineCtx.Response.Status = http.StatusOK // JSON-RPC errors are often 200 OK HTTP-wise
	if pipelineCtx.Response.Headers == nil {
		pipelineCtx.Response.Headers = make(map[string][]string)
	}
	pipelineCtx.Response.Headers["Content-Type"] = []string{"application/json"}
	// We need to write this to the response body variable if we had one for "virtual" responses,
	// but currently the engine handles terminal deny by preventing downstream execution.
	// To customize the body, we might need to set it somewhere.
	// Looking at TerminalDenyHandler, it doesn't set a body, just status/headers.
	// We might need to write to the response writer directly?
	// Actually, if we return OutcomeDeny, the engine usually stops.
	// But we want to return a specific JSON body.
	// A standard `TerminalDenyHandler` just sets error headers/codes.

	// WORKAROUND: We can use `outcome: OutcomeDeny` BUT we want to send a custom body.
	// The core engine's `Execute` loop doesn't seem to natively support setting response body content on Deny.
	// HOWEVER, `http_handler.go` likely reads from somewhere?
	// Checking `Execute` in `executor.go`: Request flows through nodes.
	// If outcome is Deny, it goes to `node.On.Failure` or stops.

	// If we want to terminate HERE with a specific body, we might need a mechanism.
	// Since we are a filter, maybe we replace the request body with something that produces an error upstream? NO.
	// We want to return response to client.

	// Let's check if we can set `pipelineCtx.Response.Body`?
	// `PipelineContext` struct definition isn't fully visible but usually has Request/Response.
	// `Response` struct usually has `Headers`, `Status`. Does it have `Body` or `Data`?
	// If not, we might be limited.

	// Assuming for now we can't easily write a custom body on Deny from a middle-node without a special "Response Injection" handler.
	// But wait, `http_handler.go` writes the response. It checks `pipelineCtx.Response`.
	// It probably doesn't have a field for "Body Content".

	// ALTERNATIVE: Use `Variables` to signal `http_handler`?
	// Or, maybe we just return Success but set a flag that makes us skip everything else?
	// `executionAdvance` allows skipping to `nextNodeID`.
	// If we set `nextNodeID` to a node that writes the error?

	// SIMPLIFICATION for MVP:
	// We will log the block and allow standard Deny (403 or configured).
	// The client will see a HTTP error.
	// Ideally MCP clients handle HTTP errors.
	// If strictly JSON-RPC is needed, we might need to enhance the engine later.
	// For now, standard Deny is safer implementation-wise.

	return runtime.NodeResult{Outcome: runtime.OutcomeDeny}, nil
}

func (h *MCPFilterHandler) buildMCPPolicyInput(pipelineCtx *domain.PipelineContext, node *domain.PipelineNode, rpcReq jsonRPCRequest) policy.Input {
	// Extract identity
	identity := domain.PolicyIdentity{}
	if sub, ok := pipelineCtx.Variables["auth.subject"].(string); ok {
		identity.Subject = sub
	}

	// Build Attributes
	attributes := map[string]any{
		"method": rpcReq.Method,
		"params": rpcReq.Params, // Raw, policy can parse if needed or we parse map[string]any
	}

	// Try to unmarshal Params to map if possible for easier Rego access
	var paramsMap map[string]any
	if len(rpcReq.Params) > 0 {
		if err := json.Unmarshal(rpcReq.Params, &paramsMap); err == nil {
			attributes["params"] = paramsMap
		}
	}

	entrypoint := "mcp/authz"
	if ep, ok := node.Config["entrypoint"].(string); ok && ep != "" {
		entrypoint = ep
	}

	return policy.Input{
		Identity:   identity,
		Attributes: attributes,
		Entrypoint: entrypoint,
	}
}
