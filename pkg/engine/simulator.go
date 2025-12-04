package engine

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/handlers"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

// Simulator executes pipelines deterministically without side effects.
// All external calls are stubbed, and execution is traced for inspection.
type Simulator struct {
	registry *PipelineRegistry
	logger   *slog.Logger
}

// NewSimulator creates a new deterministic pipeline simulator.
func NewSimulator(registry *PipelineRegistry, logger *slog.Logger) *Simulator {
	if logger == nil {
		logger = slog.Default()
	}

	return &Simulator{
		registry: registry,
		logger:   logger,
	}
}

// Simulate executes a pipeline with the given input and returns the trace.
// This is a deterministic, side-effect-free simulation for testing and validation.
func (s *Simulator) Simulate(ctx context.Context, req domain.SimulationRequest) (*domain.SimulationResponse, error) {
	s.logger.Info("starting pipeline simulation",
		slog.String("agent_id", req.AgentID),
		slog.String("pipeline_id", req.PipelineID))

	// Get pipeline
	var pipeline *domain.Pipeline
	var err error

	if req.PipelineID != "" {
		// Use specific pipeline ID
		var ok bool
		pipeline, ok = s.registry.GetPipeline(req.PipelineID)
		if !ok {
			return nil, fmt.Errorf("pipeline %q not found", req.PipelineID)
		}
	} else if req.AgentID != "" {
		// Select by agent ID
		pipeline, err = s.registry.SelectPipeline(req.AgentID, "")
		if err != nil {
			return nil, fmt.Errorf("pipeline selection failed: %w", err)
		}
	} else {
		return nil, fmt.Errorf("either agentId or pipelineId must be provided")
	}

	// Convert simple headers to multi-value headers
	headers := make(map[string][]string, len(req.Request.Headers))
	for k, v := range req.Request.Headers {
		headers[k] = []string{v}
	}

	// Build pipeline context from simulation request
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:  req.Request.Method,
			Path:    req.Request.Path,
			Headers: headers,
		},
		Session:   domain.SessionContext{},
		Variables: req.Context,
		Budgets:   domain.BudgetContext{},
	}

	if pipelineCtx.Variables == nil {
		pipelineCtx.Variables = make(map[string]interface{})
	}

	// Execute simulation
	trace, mockResponse, err := s.simulateExecution(ctx, pipeline, pipelineCtx)
	if err != nil {
		// Return trace even on error for debugging
		return &domain.SimulationResponse{
			Response:     mockResponse,
			FinalContext: pipelineCtx.Variables,
			Trace:        trace,
		}, err
	}

	s.logger.Info("pipeline simulation complete",
		slog.String("pipeline_id", pipeline.ID),
		slog.Int("trace_length", len(trace)))

	return &domain.SimulationResponse{
		Response:     mockResponse,
		FinalContext: pipelineCtx.Variables,
		Trace:        trace,
	}, nil
}

// simulateExecution executes the pipeline deterministically and returns the trace.
func (s *Simulator) simulateExecution(ctx context.Context, pipeline *domain.Pipeline, pipelineCtx *domain.PipelineContext) ([]domain.TraceEntry, domain.MockResponse, error) {
	trace := make([]domain.TraceEntry, 0, len(pipeline.Nodes))

	// Default mock response
	mockResponse := domain.MockResponse{
		Status:  200,
		Headers: make(map[string]string),
		Body:    "",
	}

	if len(pipeline.Nodes) == 0 {
		return trace, mockResponse, fmt.Errorf("pipeline %q has no nodes", pipeline.ID)
	}

	// Start from first node
	currentNodeID := pipeline.Nodes[0].ID
	visited := make(map[string]bool)
	maxIterations := len(pipeline.Nodes) * 10

	for i := 0; i < maxIterations; i++ {
		if currentNodeID == "" {
			// Execution complete
			break
		}

		if visited[currentNodeID] {
			return trace, mockResponse, fmt.Errorf("cycle detected: node %q visited twice", currentNodeID)
		}
		visited[currentNodeID] = true

		// Find node
		node := s.findNode(pipeline, currentNodeID)
		if node == nil {
			return trace, mockResponse, fmt.Errorf("node %q not found", currentNodeID)
		}

		// Simulate node execution
		start := time.Now()
		outcome, nextNodeID, err := s.simulateNode(ctx, pipeline, node, pipelineCtx, &mockResponse)
		duration := time.Since(start)

		// Record trace entry
		entry := domain.TraceEntry{
			NodeID:    node.ID,
			NodeType:  node.Type,
			Outcome:   outcome,
			EdgeTaken: nextNodeID,
			Duration:  duration.String(),
			Metadata:  make(map[string]interface{}),
		}

		// Add node config to metadata for inspection
		if len(node.Config) > 0 {
			entry.Metadata["config"] = node.Config
		}

		trace = append(trace, entry)

		if err != nil {
			entry.Metadata["error"] = err.Error()
			return trace, mockResponse, err
		}

		currentNodeID = nextNodeID
	}

	if currentNodeID != "" {
		return trace, mockResponse, fmt.Errorf("max iterations exceeded (possible infinite loop)")
	}

	return trace, mockResponse, nil
}

// simulateNode simulates a single node execution without side effects.
func (s *Simulator) simulateNode(ctx context.Context, pipeline *domain.Pipeline, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext, mockResponse *domain.MockResponse) (outcome string, nextNodeID string, err error) {
	s.logger.Debug("simulating node",
		slog.String("node_id", node.ID),
		slog.String("node_type", node.Type))

	// Check when conditions (stub - always evaluates to true for simulation)
	if len(node.When) > 0 {
		// In a real implementation, this would evaluate CEL expressions
		s.logger.Debug("when conditions present (skipped in simulation)",
			slog.String("node_id", node.ID))
	}

	// Simulate node based on type (deterministic, no side effects)
	// outcome defaults to "success" for unknown types (see default case)

	switch node.Type {
	case "auth", "auth.jwt.validate":
		// Simulate auth: check if Authorization header exists
		authHeaders, ok := pipelineCtx.Request.Headers["Authorization"]
		if ok && len(authHeaders) > 0 && authHeaders[0] != "" {
			outcome = "success"
			pipelineCtx.Variables["auth.validated"] = true
		} else {
			outcome = "failure"
			pipelineCtx.Variables["auth.validated"] = false
			mockResponse.Status = 401
			mockResponse.Body = `{"error":"unauthorized"}`
		}

	case "policy", "policy.opa":
		// Execute actual policy engine
		if pipeline.EngineContext == nil || pipeline.EngineContext.PolicyEngines == nil {
			s.logger.Warn("policy engine not initialized for simulation", slog.String("node_id", node.ID))
			outcome = "success"
			pipelineCtx.Variables["policy.allowed"] = true
		} else {
			// Ensure pipeline is set in context for handler
			pipelineCtx.Pipeline = pipeline

			// Execute policy via handler
			handler := handlers.NewPolicyHandler(s.logger)
			result, err := handler.Execute(ctx, node, pipelineCtx)
			if err != nil {
				s.logger.Error("policy execution error in simulation", slog.String("node_id", node.ID), slog.String("error", err.Error()))
				outcome = "failure"
				mockResponse.Status = 500
				mockResponse.Body = `{"error":"policy_error"}`
			} else {
				switch result.Outcome {
				case runtime.OutcomeSuccess:
					outcome = "success"
					pipelineCtx.Variables["policy.allowed"] = true
				case runtime.OutcomeDeny:
					outcome = "deny"
					mockResponse.Status = 403
					mockResponse.Body = `{"error":"policy_denied"}`
				case runtime.OutcomeFailure:
					outcome = "failure"
					mockResponse.Status = 500
					mockResponse.Body = `{"error":"policy_error"}`
				default:
					outcome = "success"
				}
			}
		}

	case "waf", "waf.inspect":
		// Simulate WAF: check for SQL injection patterns in path
		if strings.Contains(pipelineCtx.Request.Path, "DROP TABLE") || strings.Contains(pipelineCtx.Request.Path, "'; DELETE") {
			outcome = "failure"
			pipelineCtx.Variables["waf.violation"] = "sql_injection"
			mockResponse.Status = 403
			mockResponse.Body = `{"error":"waf_violation"}`
		} else {
			outcome = "success"
		}

	case "dlp", "dlp.inspect":
		// Simulate DLP: check for PII patterns in body
		if mockResponse.Body != "" && (strings.Contains(mockResponse.Body, "SSN:") || strings.Contains(mockResponse.Body, "credit_card:")) {
			outcome = "success"
			pipelineCtx.Variables["dlp.redacted"] = true
			// Redact PII in simulation
			mockResponse.Body = "[REDACTED]"
		} else {
			outcome = "success"
		}

	case "egress", "egress.http":
		// Simulate egress: set mock response
		outcome = "success"
		mockResponse.Status = 200
		mockResponse.Headers["X-Simulated"] = "true"
		mockResponse.Body = `{"message":"simulated response"}`
		pipelineCtx.Variables["egress.called"] = true

	case "ratelimit":
		// Simulate rate limit: check budget
		if pipelineCtx.Budgets.Requests != nil && *pipelineCtx.Budgets.Requests <= 0 {
			outcome = "ratelimited"
			mockResponse.Status = 429
			mockResponse.Body = `{"error":"rate_limited"}`
		} else {
			outcome = "success"
			if pipelineCtx.Budgets.Requests != nil {
				remaining := *pipelineCtx.Budgets.Requests - 1
				pipelineCtx.Budgets.Requests = &remaining
			}
		}

	case "terminal_deny", "terminal.deny":
		outcome = "deny"
		mockResponse.Status = 403
		mockResponse.Body = `{"error":"access_denied"}`
		return outcome, "", fmt.Errorf("access denied by terminal node")

	case "terminal_error", "terminal.error":
		outcome = "error"
		mockResponse.Status = 500
		mockResponse.Body = `{"error":"terminal_error"}`
		return outcome, "", fmt.Errorf("terminal error node reached")

	default:
		// Unknown node type - log and continue
		s.logger.Warn("unknown node type in simulation",
			slog.String("node_id", node.ID),
			slog.String("node_type", node.Type))
		outcome = "success"
	}

	// Determine next node based on outcome
	nextNodeID = s.getNextNode(node, outcome)

	return outcome, nextNodeID, nil
}

// getNextNode determines the next node ID based on the outcome.
func (s *Simulator) getNextNode(node *domain.PipelineNode, outcome string) string {
	// Check node handlers first
	switch outcome {
	case "success":
		if node.On.Success != "" {
			return node.On.Success
		}
	case "failure":
		if node.On.Failure != "" {
			return node.On.Failure
		}
	case "timeout":
		if node.On.Timeout != "" {
			return node.On.Timeout
		}
	case "ratelimited":
		if node.On.RateLimited != "" {
			return node.On.RateLimited
		}
	case "circuitopen":
		if node.On.CircuitOpen != "" {
			return node.On.CircuitOpen
		}
	}

	// Check else handler
	if node.On.Else != "" {
		return node.On.Else
	}

	// No handler - execution complete
	return ""
}

// findNode finds a node by ID in the pipeline.
func (s *Simulator) findNode(pipeline *domain.Pipeline, nodeID string) *domain.PipelineNode {
	for i := range pipeline.Nodes {
		if pipeline.Nodes[i].ID == nodeID {
			return &pipeline.Nodes[i]
		}
	}
	return nil
}
