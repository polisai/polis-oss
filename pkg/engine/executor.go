package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/bits"
	"net/textproto"
	"strings"
	"time"

	"github.com/polisai/polis-oss/internal/governance"
	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/expr"
	handlers "github.com/polisai/polis-oss/pkg/engine/handlers"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"github.com/polisai/polis-oss/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// DefaultEgressTimeout is the default timeout for egress HTTP requests.
	// TODO: Make this configurable via governance policy.
	DefaultEgressTimeout = 60 * time.Second
)

// DAGExecutor executes pipeline DAGs with node-by-node traversal.
type DAGExecutor struct {
	registry       *PipelineRegistry
	logger         *slog.Logger
	handlers       *handlerRegistry
	breakerManager *governance.CircuitBreakerManager
	breakerConfigs map[string]string
	exprEval       *expr.Evaluator
	triggerMatcher *triggerMatcher
}

// handlerRegistry stores canonical handlers and alias mappings.
type handlerRegistry struct {
	handlers map[string]runtime.NodeHandler
	aliases  map[string]string
}

type handlerMetadata struct {
	Kind      string
	Version   string
	Canonical string
}

type executionAdvance struct {
	nextNodeID string
	outcome    runtime.NodeOutcome
}

type timeoutCandidate struct {
	source string
	ms     int
}

type nodeExecutionMeta struct {
	deadline   time.Duration
	retries    int
	maxRetries int
}

// DAGExecutorConfig holds dependencies for creating a DAGExecutor.
type DAGExecutorConfig struct {
	Registry *PipelineRegistry
	Logger   *slog.Logger
}

// NewDAGExecutor creates a new DAG executor with the given configuration.
func NewDAGExecutor(cfg DAGExecutorConfig) *DAGExecutor {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	executor := &DAGExecutor{
		registry:       cfg.Registry,
		logger:         logger,
		handlers:       newHandlerRegistry(),
		breakerManager: governance.NewCircuitBreakerManager(),
		breakerConfigs: make(map[string]string),
		exprEval:       expr.NewEvaluator(expr.Options{}),
		triggerMatcher: newTriggerMatcher(logger),
	}

	// Register real handlers (Phase 3B)
	executor.registerDefaultHandlers()

	return executor
}

// Execute runs the pipeline for the given agent and protocol with the provided context.
// See ExecuteForSession for production usage with session pinning.
func (e *DAGExecutor) Execute(ctx context.Context, agentID, protocol string, pipelineCtx *domain.PipelineContext) error {
	pipeline, err := e.registry.SelectPipeline(agentID, protocol)
	if err != nil {
		return fmt.Errorf("pipeline selection failed: %w", err)
	}

	return e.executePipeline(ctx, pipeline, pipelineCtx)
}

// ExecuteForSession runs the pipeline for a session, supporting zero-downtime updates.
func (e *DAGExecutor) ExecuteForSession(ctx context.Context, sessionID, agentID, protocol string, pipelineCtx *domain.PipelineContext) error {
	pipeline, err := e.registry.SelectPipelineForSession(sessionID, agentID, protocol)
	if err != nil {
		return fmt.Errorf("pipeline selection failed: %w", err)
	}

	return e.executePipeline(ctx, pipeline, pipelineCtx)
}

// executePipeline executes a selected pipeline DAG.
func (e *DAGExecutor) executePipeline(ctx context.Context, pipeline *domain.Pipeline, pipelineCtx *domain.PipelineContext) error {
	pipelineCtx.Pipeline = pipeline
	e.applyTriggers(pipeline, pipelineCtx)

	e.logger.Info("executing pipeline",
		"pipeline_id", pipeline.ID,
		"agent_id", pipeline.AgentID,
		"protocol", pipeline.Protocol,
	)

	tracer := otel.Tracer("proxy.pipeline")
	var span trace.Span
	ctx, span = tracer.Start(ctx, "pipeline.execute")
	baseAttrs := []attribute.KeyValue{
		attribute.String("pipeline.id", pipeline.ID),
		attribute.Int("pipeline.version", pipeline.Version),
		attribute.String("agent.id", pipeline.AgentID),
		attribute.String("protocol.name", pipeline.Protocol),
		attribute.String("session.id", pipelineCtx.Request.SessionID),
		attribute.String("protocol.session_id", pipelineCtx.Request.SessionID),
		attribute.String("http.method", pipelineCtx.Request.Method),
		attribute.String("http.route", pipelineCtx.Request.Path),
	}
	if pipelineCtx.Request.Streaming {
		baseAttrs = append(baseAttrs, attribute.Bool("request.streaming", true))
	}
	if pipelineCtx.Request.StreamingMode != "" {
		baseAttrs = append(baseAttrs, attribute.String("request.streaming_mode", pipelineCtx.Request.StreamingMode))
	}
	if pipelineCtx.Request.TriggerType != "" {
		baseAttrs = append(baseAttrs, attribute.String("request.trigger_type", pipelineCtx.Request.TriggerType))
	}
	if pipelineCtx.Request.TriggerIndex >= 0 {
		baseAttrs = append(baseAttrs, attribute.Int("request.trigger_index", pipelineCtx.Request.TriggerIndex))
	}
	span.SetAttributes(telemetry.RedactAttributes(&pipelineCtx.Telemetry, baseAttrs)...)
	defer span.End()

	if len(pipeline.Nodes) == 0 {
		return fmt.Errorf("pipeline %q has no nodes", pipeline.ID)
	}

	var telemetryCtx *domain.TelemetryContext
	if pipelineCtx != nil {
		telemetryCtx = &pipelineCtx.Telemetry
	}

	currentNodeID := pipeline.Nodes[0].ID
	visited := make(map[string]bool)
	maxIterations := len(pipeline.Nodes) * 10

	for i := 0; i < maxIterations; i++ {
		e.logger.Info("DAG loop", "iteration", i, "max", maxIterations, "node", currentNodeID)
		if currentNodeID == "" {
			e.logger.Info("pipeline execution complete", "pipeline_id", pipeline.ID)
			return nil
		}

		if visited[currentNodeID] {
			return fmt.Errorf("cycle detected: node %q visited twice", currentNodeID)
		}
		visited[currentNodeID] = true

		node := e.findNode(pipeline, currentNodeID)
		if node == nil {
			return fmt.Errorf("node %q not found in pipeline %q", currentNodeID, pipeline.ID)
		}

		initialAttrs := []attribute.KeyValue{
			attribute.String("node.id", node.ID),
			attribute.String("node.type", node.Type),
		}
		nodeCtx, nodeSpan := tracer.Start(ctx, "pipeline.node",
			trace.WithAttributes(telemetry.RedactAttributes(telemetryCtx, initialAttrs)...),
		)

		advance, err := e.executeNode(nodeCtx, pipeline, node, pipelineCtx)
		outcomeAttr := []attribute.KeyValue{
			attribute.String("node.outcome", string(advance.outcome)),
		}
		nodeSpan.SetAttributes(telemetry.RedactAttributes(telemetryCtx, outcomeAttr)...)

		if err != nil {
			e.logger.Error("node execution failed",
				"pipeline_id", pipeline.ID,
				"node_id", node.ID,
				"error", err,
			)
			nodeSpan.RecordError(err)
			nodeSpan.SetStatus(codes.Error, err.Error())
			nodeSpan.End()
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("node %q execution failed: %w", node.ID, err)
		}

		nodeSpan.End()
		currentNodeID = advance.nextNodeID
	}

	return fmt.Errorf("pipeline %q exceeded maximum iterations (%d)", pipeline.ID, maxIterations)
}

func (e *DAGExecutor) applyTriggers(pipeline *domain.Pipeline, pipelineCtx *domain.PipelineContext) {
	if e.triggerMatcher == nil || pipelineCtx == nil || pipeline == nil {
		return
	}

	if len(pipeline.Triggers) == 0 {
		return
	}

	match := e.triggerMatcher.Match(pipeline, pipelineCtx)
	if !match.Matched {
		return
	}

	if match.TriggerType != "" {
		pipelineCtx.Request.TriggerType = match.TriggerType
	}
	if match.TriggerIndex >= 0 {
		pipelineCtx.Request.TriggerIndex = match.TriggerIndex
	}

	if pipelineCtx.Variables == nil {
		pipelineCtx.Variables = make(map[string]interface{})
	}

	if match.TriggerType != "" {
		pipelineCtx.Variables["trigger.match.type"] = match.TriggerType
	}
	pipelineCtx.Variables["trigger.match.index"] = match.TriggerIndex

	if len(match.Labels) > 0 {
		pipelineCtx.Variables["trigger.match.labels"] = match.Labels
	}

	if match.Streaming {
		pipelineCtx.Request.Streaming = true
		if match.StreamingMode != "" {
			pipelineCtx.Request.StreamingMode = match.StreamingMode
		}
		pipelineCtx.Variables["request.streaming"] = true
		if pipelineCtx.Request.StreamingMode != "" {
			pipelineCtx.Variables["request.streaming.mode"] = pipelineCtx.Request.StreamingMode
		}
		// Only set egress streaming defaults if not already configured by handlers.
		if _, ok := pipelineCtx.Variables["egress.streaming.enabled"].(bool); !ok {
			pipelineCtx.Variables["egress.streaming.enabled"] = true
		}
		if _, ok := pipelineCtx.Variables["egress.streaming.mode"].(string); !ok && pipelineCtx.Request.StreamingMode != "" {
			pipelineCtx.Variables["egress.streaming.mode"] = pipelineCtx.Request.StreamingMode
		}
	}

	logArgs := []any{
		"pipeline_id", pipeline.ID,
		"trigger_type", match.TriggerType,
		"trigger_index", match.TriggerIndex,
	}
	if match.Streaming {
		logArgs = append(logArgs, "streaming", true)
		if match.StreamingMode != "" {
			logArgs = append(logArgs, "streaming_mode", match.StreamingMode)
		}
	}
	if len(match.Labels) > 0 {
		logArgs = append(logArgs, "trigger_labels", match.Labels)
	}
	e.logger.Debug("pipeline trigger matched", logArgs...)
}

// executeNode executes a single node and returns the next node based on the outcome.
func (e *DAGExecutor) executeNode(ctx context.Context, pipeline *domain.Pipeline, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (executionAdvance, error) {
	if shouldSkip, nextNode, err := e.evaluateWhenConditions(ctx, pipeline, node, pipelineCtx); err != nil {
		return executionAdvance{}, err
	} else if shouldSkip {
		return executionAdvance{nextNodeID: nextNode, outcome: runtime.OutcomeSuccess}, nil
	}

	handler, meta, ok := e.handlers.resolve(node.Type)
	if !ok {
		return executionAdvance{}, fmt.Errorf("no handler registered for type %q", node.Type)
	}

	span := trace.SpanFromContext(ctx)
	var telemetryCtx *domain.TelemetryContext
	if pipelineCtx != nil {
		telemetryCtx = &pipelineCtx.Telemetry
	}
	canonicalKind, canonicalVersion := parseNodeType(meta.Canonical)
	if canonicalKind == "" {
		canonicalKind = meta.Kind
	}
	nodeKind := canonicalKind
	nodeVersion := canonicalVersion
	if nodeVersion == "" {
		nodeVersion = meta.Version
	}
	if nodeVersion == "" {
		nodeVersion = "unspecified"
	}
	if span.IsRecording() {
		attrs := []attribute.KeyValue{
			attribute.String("node.kind", nodeKind),
			attribute.String("node.version", nodeVersion),
			attribute.String("node.canonical", meta.Canonical),
		}
		if pipeline != nil {
			attrs = append(attrs,
				attribute.String("pipeline.id", pipeline.ID),
				attribute.Int("pipeline.version", pipeline.Version),
			)
		}
		if pipelineCtx != nil && pipelineCtx.Request.Streaming {
			attrs = append(attrs, attribute.Bool("request.streaming", true))
			if pipelineCtx.Request.StreamingMode != "" {
				attrs = append(attrs, attribute.String("request.streaming_mode", pipelineCtx.Request.StreamingMode))
			}
		}
		span.SetAttributes(telemetry.RedactAttributes(telemetryCtx, attrs)...)
	}

	start := time.Now()
	result, execMeta, execErr := e.executeWithGovernance(ctx, pipeline, node, pipelineCtx, handler, meta)
	duration := time.Since(start)
	result = result.WithDefaults()

	outcome := result.Outcome
	if execErr != nil {
		outcome = classifyError(execErr)
	}

	if span.IsRecording() {
		attrs := []attribute.KeyValue{
			attribute.String("node.outcome", string(outcome)),
			attribute.Int64("node.duration_ms", duration.Milliseconds()),
			attribute.Int("node.retry.count", execMeta.retries),
		}
		if execMeta.deadline > 0 {
			attrs = append(attrs, attribute.Int("governance.timeout_ms", int(execMeta.deadline/time.Millisecond)))
		}
		if execMeta.maxRetries > 0 {
			attrs = append(attrs, attribute.Int("governance.retry.max_attempts", execMeta.maxRetries+1))
		}
		span.SetAttributes(telemetry.RedactAttributes(telemetryCtx, attrs)...)
	}

	if pipelineCtx != nil {
		if pipelineCtx.Security.Blocked || len(pipelineCtx.Security.Violations) > 0 || len(pipelineCtx.Security.Findings) > 0 {
			reason := pipelineCtx.Security.BlockReason
			telemetry.RecordSecurityEvent(span, pipelineCtx.Security.Blocked, reason, len(pipelineCtx.Security.Findings), len(pipelineCtx.Security.Violations))
		}
	}

	protocol := ""
	agentID := ""
	pipelineID := ""
	pipelineVersion := 0
	if pipelineCtx != nil {
		protocol = pipelineCtx.Request.Protocol
		agentID = pipelineCtx.Request.AgentID
	}
	if pipeline != nil {
		if protocol == "" {
			protocol = pipeline.Protocol
		}
		if agentID == "" {
			agentID = pipeline.AgentID
		}
		pipelineID = pipeline.ID
		pipelineVersion = pipeline.Version
	}

	telemetry.RecordNodeMetrics(ctx, telemetry.NodeMetrics{
		PipelineID:      pipelineID,
		PipelineVersion: pipelineVersion,
		AgentID:         agentID,
		Protocol:        protocol,
		NodeID:          node.ID,
		NodeKind:        nodeKind,
		NodeVersion:     nodeVersion,
		Outcome:         outcome,
		Duration:        duration,
		Retries:         execMeta.retries,
	})

	nextNodeID, routeErr := e.nextNodeForOutcome(ctx, pipeline, node, pipelineCtx, result, outcome)
	if routeErr != nil {
		return executionAdvance{}, routeErr
	}

	if execErr != nil && nextNodeID == "" {
		return executionAdvance{}, execErr
	}

	return executionAdvance{nextNodeID: nextNodeID, outcome: outcome}, nil
}

func (e *DAGExecutor) executeWithGovernance(
	ctx context.Context,
	pipeline *domain.Pipeline,
	node *domain.PipelineNode,
	pipelineCtx *domain.PipelineContext,
	handler runtime.NodeHandler,
	meta handlerMetadata,
) (runtime.NodeResult, nodeExecutionMeta, error) {
	deadline, timeoutSources := resolveTimeout(pipeline, node)
	metaInfo := nodeExecutionMeta{deadline: deadline}
	if len(timeoutSources) > 1 {
		unique := make(map[int][]string)
		for _, candidate := range timeoutSources {
			unique[candidate.ms] = append(unique[candidate.ms], candidate.source)
		}
		if len(unique) > 1 && deadline > 0 {
			sources := make([]string, 0, len(timeoutSources))
			for value, list := range unique {
				sources = append(sources, fmt.Sprintf("%dms<- %s", value, strings.Join(list, ",")))
			}
			e.logger.Warn("multiple timeout values detected; using smallest",
				"node_id", node.ID,
				"selected_timeout_ms", int(deadline/time.Millisecond),
				"sources", sources,
			)
		}
	}
	retryPolicy := buildRetryPolicy(pipeline, node)
	var retryCfg governance.RetryConfig
	if retryPolicy != nil {
		retryCfg = retryPolicy.Config()
		metaInfo.maxRetries = retryCfg.MaxRetries
	}

	breaker, _ := e.resolveCircuitBreaker(pipeline, node, meta)

	attempt := 0
	retries := 0
	for {
		attemptCtx := ctx
		var cancel context.CancelFunc = func() {}
		if deadline > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, deadline)
		}

		result, execErr := e.invokeHandler(attemptCtx, breaker, handler, node, pipelineCtx)
		timeoutExceeded := attemptCtx.Err() == context.DeadlineExceeded
		cancel()

		if timeoutExceeded {
			execErr = fmt.Errorf("%w: node %s exceeded %s timeout", governance.ErrRequestTimeout, node.ID, deadline)
		}

		if !shouldRetry(retryPolicy, retryCfg, attempt, result, execErr) {
			metaInfo.retries = retries
			return result, metaInfo, execErr
		}

		delay := retryPolicy.CalculateBackoff(attempt)
		attempt++
		retries++

		select {
		case <-ctx.Done():
			metaInfo.retries = retries
			return result, metaInfo, ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (e *DAGExecutor) invokeHandler(
	ctx context.Context,
	breaker *governance.CircuitBreaker,
	handler runtime.NodeHandler,
	node *domain.PipelineNode,
	pipelineCtx *domain.PipelineContext,
) (runtime.NodeResult, error) {
	if breaker == nil {
		return handler.Execute(ctx, node, pipelineCtx)
	}

	var result runtime.NodeResult
	err := breaker.ExecuteContext(ctx, func(execCtx context.Context) error {
		var execErr error
		result, execErr = handler.Execute(execCtx, node, pipelineCtx)
		return execErr
	})
	return result, err
}

func shouldRetry(policy *governance.RetryPolicy, cfg governance.RetryConfig, attempt int, result runtime.NodeResult, execErr error) bool {
	if policy == nil {
		return false
	}
	if attempt >= cfg.MaxRetries {
		return false
	}
	if execErr != nil {
		if errors.Is(execErr, governance.ErrCircuitOpen) {
			return false
		}
		if errors.Is(execErr, context.Canceled) || errors.Is(execErr, context.DeadlineExceeded) {
			return false
		}
		return governance.IsRetryableError(execErr)
	}

	switch result.Outcome {
	case runtime.OutcomeRetryable, runtime.OutcomeRateLimited:
		return true
	default:
		return false
	}
}

func classifyError(err error) runtime.NodeOutcome {
	switch {
	case errors.Is(err, governance.ErrRequestTimeout), errors.Is(err, context.DeadlineExceeded):
		return runtime.OutcomeTimeout
	case errors.Is(err, governance.ErrCircuitOpen):
		return runtime.OutcomeCircuitOpen
	default:
		return runtime.OutcomeFailure
	}
}

func (e *DAGExecutor) nextNodeForOutcome(
	ctx context.Context,
	pipeline *domain.Pipeline,
	node *domain.PipelineNode,
	pipelineCtx *domain.PipelineContext,
	result runtime.NodeResult,
	outcome runtime.NodeOutcome,
) (string, error) {
	if result.NextHint != "" {
		if e.findNode(pipeline, result.NextHint) == nil {
			return "", fmt.Errorf("node %q requested unknown next node %q", node.ID, result.NextHint)
		}
		return result.NextHint, nil
	}

	switch outcome {
	case runtime.OutcomeSuccess:
		if node.On.Success != "" {
			return node.On.Success, nil
		}
	case runtime.OutcomeTimeout:
		if node.On.Timeout != "" {
			return node.On.Timeout, nil
		}
	case runtime.OutcomeRateLimited, runtime.OutcomeRetryable:
		if node.On.RateLimited != "" {
			return node.On.RateLimited, nil
		}
	case runtime.OutcomeCircuitOpen:
		if node.On.CircuitOpen != "" {
			return node.On.CircuitOpen, nil
		}
	case runtime.OutcomeDeny:
		if node.On.Failure != "" {
			return node.On.Failure, nil
		}
	case runtime.OutcomeFailure:
		if node.On.Failure != "" {
			return node.On.Failure, nil
		}
	}

	if outcome != runtime.OutcomeSuccess && node.On.Failure != "" {
		return node.On.Failure, nil
	}

	if node.On.Else != "" {
		return node.On.Else, nil
	}

	edgeTarget, edgeErr := e.findNextNodeByEdge(ctx, pipeline, node.ID, pipelineCtx)
	if edgeErr != nil {
		return "", edgeErr
	}
	if edgeTarget != "" {
		return edgeTarget, nil
	}

	return "", nil
}

// evaluateWhenConditions checks if a node should be skipped based on conditional branches.
func (e *DAGExecutor) evaluateWhenConditions(ctx context.Context, pipeline *domain.Pipeline, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (bool, string, error) {
	if node == nil || pipelineCtx == nil {
		return false, "", nil
	}

	if pipeline == nil || !pipeline.Defaults.EnableConditionals || len(node.When) == 0 {
		return false, "", nil
	}

	lookup := e.conditionLookup(pipelineCtx)

	for _, branch := range node.When {
		cond := strings.TrimSpace(branch.If)
		if cond == "" {
			continue
		}

		matched, err := e.exprEval.Evaluate(ctx, cond, lookup)
		if err != nil {
			return false, "", fmt.Errorf("node %s conditional evaluation failed: %w", node.ID, err)
		}
		if matched {
			if branch.Then == "" {
				return true, "", fmt.Errorf("node %s conditional branch missing target", node.ID)
			}
			return true, branch.Then, nil
		}
	}

	return false, "", nil
}

func (e *DAGExecutor) findNextNodeByEdge(ctx context.Context, pipeline *domain.Pipeline, currentNodeID string, pipelineCtx *domain.PipelineContext) (string, error) {
	if pipeline == nil {
		return "", nil
	}

	var fallback string
	lookup := e.conditionLookup(pipelineCtx)

	for _, edge := range pipeline.Edges {
		if edge.From != currentNodeID {
			continue
		}

		condition := strings.TrimSpace(edge.If)
		if condition == "" {
			if fallback == "" {
				fallback = edge.To
			}
			continue
		}

		if !pipeline.Defaults.EnableConditionals {
			if fallback == "" {
				fallback = edge.To
			}
			continue
		}

		matched, err := e.exprEval.Evaluate(ctx, condition, lookup)
		if err != nil {
			return "", fmt.Errorf("edge %s->%s conditional evaluation failed: %w", edge.From, edge.To, err)
		}
		if matched {
			return edge.To, nil
		}
	}

	return fallback, nil
}

//nolint:gocyclo // Enumerating supported lookup namespaces requires branching; kept explicit for clarity.
func (e *DAGExecutor) conditionLookup(pipelineCtx *domain.PipelineContext) expr.LookupFunc {
	return func(path string) (any, bool) {
		if path == "" || pipelineCtx == nil {
			return nil, false
		}

		if value, ok := lookupVariable(pipelineCtx.Variables, path); ok {
			return value, true
		}

		switch {
		case strings.HasPrefix(path, "metadata."):
			key := strings.TrimPrefix(path, "metadata.")
			if value, ok := lookupVariable(pipelineCtx.Variables, key); ok {
				return value, true
			}
			return nil, false
		case strings.HasPrefix(path, "variables."):
			key := strings.TrimPrefix(path, "variables.")
			if value, ok := lookupVariable(pipelineCtx.Variables, key); ok {
				return value, true
			}
			return nil, false
		case strings.HasPrefix(path, "request.headers."):
			return lookupHeaderValue(pipelineCtx.Request.Headers, strings.TrimPrefix(path, "request.headers."))
		case strings.HasPrefix(path, "request.header."):
			return lookupHeaderValue(pipelineCtx.Request.Headers, strings.TrimPrefix(path, "request.header."))
		case strings.HasPrefix(path, "header."):
			return lookupHeaderValue(pipelineCtx.Request.Headers, strings.TrimPrefix(path, "header."))
		case strings.HasPrefix(path, "response.headers."):
			return lookupHeaderValue(pipelineCtx.Response.Headers, strings.TrimPrefix(path, "response.headers."))
		case strings.HasPrefix(path, "response.trailers."):
			return lookupHeaderValue(pipelineCtx.Response.Trailers, strings.TrimPrefix(path, "response.trailers."))
		}

		switch path {
		case "request.method":
			return pipelineCtx.Request.Method, true
		case "request.path":
			return pipelineCtx.Request.Path, true
		case "request.host":
			return pipelineCtx.Request.Host, true
		case "request.protocol":
			return pipelineCtx.Request.Protocol, true
		case "request.agent_id":
			return pipelineCtx.Request.AgentID, true
		case "request.tenant_id":
			return pipelineCtx.Request.TenantID, true
		case "request.session_id":
			return pipelineCtx.Request.SessionID, true
		case "response.status":
			return pipelineCtx.Response.Status, true
		case "response.bytes_sent":
			return pipelineCtx.Response.BytesSent, true
		case "response.bytes_read":
			return pipelineCtx.Response.BytesRead, true
		case "session.total_tokens_in":
			return pipelineCtx.Session.TotalTokensIn, true
		case "session.total_tokens_out":
			return pipelineCtx.Session.TotalTokensOut, true
		case "session.estimated_cost_usd":
			return pipelineCtx.Session.EstimatedCostUSD, true
		case "security.blocked":
			return pipelineCtx.Security.Blocked, true
		case "security.block_reason":
			return pipelineCtx.Security.BlockReason, true
		case "pipeline.id":
			if pipelineCtx.Pipeline != nil {
				return pipelineCtx.Pipeline.ID, true
			}
		case "pipeline.agent_id":
			if pipelineCtx.Pipeline != nil {
				return pipelineCtx.Pipeline.AgentID, true
			}
		case "pipeline.protocol":
			if pipelineCtx.Pipeline != nil {
				return pipelineCtx.Pipeline.Protocol, true
			}
		case "pipeline.version":
			if pipelineCtx.Pipeline != nil {
				return pipelineCtx.Pipeline.Version, true
			}
		}

		return nil, false
	}
}

func lookupVariable(vars map[string]any, key string) (any, bool) {
	if vars == nil {
		return nil, false
	}
	value, ok := vars[key]
	return value, ok
}

func lookupHeaderValue(headers map[string][]string, key string) (any, bool) {
	if len(headers) == 0 {
		return nil, false
	}
	if values, ok := headers[key]; ok {
		return collapseHeaderValues(values), true
	}
	canonical := textproto.CanonicalMIMEHeaderKey(key)
	if values, ok := headers[canonical]; ok {
		return collapseHeaderValues(values), true
	}
	for headerKey, values := range headers {
		if strings.EqualFold(headerKey, key) {
			return collapseHeaderValues(values), true
		}
	}
	return nil, false
}

func collapseHeaderValues(values []string) any {
	if len(values) == 0 {
		return ""
	}
	if len(values) == 1 {
		return values[0]
	}
	return strings.Join(values, ",")
}

func (e *DAGExecutor) findNode(pipeline *domain.Pipeline, nodeID string) *domain.PipelineNode {
	for i := range pipeline.Nodes {
		if pipeline.Nodes[i].ID == nodeID {
			return &pipeline.Nodes[i]
		}
	}
	return nil
}

func resolveTimeout(pipeline *domain.Pipeline, node *domain.PipelineNode) (time.Duration, []timeoutCandidate) {
	var candidates []timeoutCandidate
	if pipeline != nil && pipeline.Defaults.TimeoutMS > 0 {
		candidates = append(candidates, timeoutCandidate{
			source: "pipeline.defaults.timeoutMs",
			ms:     pipeline.Defaults.TimeoutMS,
		})
	}
	if node != nil {
		if node.Governance.TimeoutMS > 0 {
			candidates = append(candidates, timeoutCandidate{
				source: fmt.Sprintf("node.%s.governance.timeoutMs", node.ID),
				ms:     node.Governance.TimeoutMS,
			})
		}
		if cfgTimeout, cfgSource := timeoutFromConfig(node.Config); cfgTimeout > 0 {
			candidates = append(candidates, timeoutCandidate{source: cfgSource, ms: cfgTimeout})
		}
	}
	return pickTimeout(candidates)
}

func timeoutFromConfig(config map[string]interface{}) (int, string) {
	if config == nil {
		return 0, ""
	}

	// Check direct keys first (timeout_ms, timeoutMs)
	for _, key := range []string{"timeout_ms", "timeoutMs"} {
		if value, ok := config[key]; ok {
			if ms, ok := convertToInt(value); ok && ms > 0 {
				return ms, fmt.Sprintf("node.config.%s", key)
			}
		}
	}

	// Some configs may nest spec fields
	if spec, ok := config["spec"].(map[string]interface{}); ok {
		for _, key := range []string{"timeout_ms", "timeoutMs"} {
			if value, ok := spec[key]; ok {
				if ms, ok := convertToInt(value); ok && ms > 0 {
					return ms, fmt.Sprintf("node.config.spec.%s", key)
				}
			}
		}
	}

	return 0, ""
}

func pickTimeout(candidates []timeoutCandidate) (time.Duration, []timeoutCandidate) {
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

func convertToInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		if bits.UintSize == 32 && (v > int64(math.MaxInt32) || v < int64(math.MinInt32)) {
			return 0, false
		}
		return int(v), true
	case uint:
		if bits.UintSize == 32 && v > uint(math.MaxInt32) {
			return 0, false
		}
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		if bits.UintSize == 32 && v > math.MaxInt32 {
			return 0, false
		}
		return int(v), true
	case uint64:
		if v > uint64(math.MaxInt) {
			return 0, false
		}
		return int(v), true
	case float64:
		if v > float64(math.MaxInt) || v < float64(math.MinInt) {
			return 0, false
		}
		return int(v), true
	case float32:
		if v > float32(math.MaxInt) || v < float32(math.MinInt) {
			return 0, false
		}
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

func buildRetryPolicy(pipeline *domain.Pipeline, node *domain.PipelineNode) *governance.RetryPolicy {
	cfg := governance.DefaultRetryConfig()
	configured := false

	if pipeline != nil && pipeline.Defaults.Retries.MaxAttempts > 1 {
		cfg = applyRetrySpec(cfg, pipeline.Defaults.Retries)
		configured = true
	}

	if node != nil && node.Governance.Retries != nil {
		cfg = applyRetrySpec(cfg, *node.Governance.Retries)
		configured = true
	}

	if !configured || cfg.MaxRetries <= 0 {
		return nil
	}

	return governance.NewRetryPolicy(cfg)
}

func applyRetrySpec(cfg governance.RetryConfig, spec domain.PipelineRetryConfig) governance.RetryConfig {
	if spec.MaxAttempts > 0 {
		if spec.MaxAttempts <= 1 {
			cfg.MaxRetries = 0
		} else {
			cfg.MaxRetries = spec.MaxAttempts - 1
		}
	}
	if spec.BaseMS > 0 {
		cfg.InitialBackoff = time.Duration(spec.BaseMS) * time.Millisecond
	}
	if spec.MaxMS > 0 {
		cfg.MaxBackoff = time.Duration(spec.MaxMS) * time.Millisecond
	}
	if spec.Backoff != "" {
		switch strings.ToLower(spec.Backoff) {
		case "fixed", "linear":
			cfg.BackoffMultiplier = 1.0
		default:
			cfg.BackoffMultiplier = 2.0
		}
	}
	cfg.Jitter = true
	return cfg
}

func (e *DAGExecutor) resolveCircuitBreaker(pipeline *domain.Pipeline, node *domain.PipelineNode, meta handlerMetadata) (*governance.CircuitBreaker, bool) {
	if node == nil {
		return nil, false
	}
	cbSpec := node.Governance.CircuitBreaker
	if cbSpec == nil {
		return nil, false
	}

	cfg := governance.DefaultCircuitBreakerConfig()

	clampPercent := func(p int) float64 {
		switch {
		case p < 0:
			return 0
		case p > 100:
			return 100
		default:
			return float64(p)
		}
	}

	if cbSpec.Window != "" {
		if window, err := time.ParseDuration(cbSpec.Window); err == nil && window > 0 {
			cfg.Window = window
		} else if err != nil {
			e.logger.Warn("invalid circuit breaker window configured; using default", "node_id", node.ID, "value", cbSpec.Window, "error", err)
		}
	}

	if cbSpec.FailureRateThreshold > 0 {
		cfg.FailureRateThreshold = clampPercent(cbSpec.FailureRateThreshold)
		cfg.MaxFailures = 0
	}

	if cbSpec.SlowCallDurationMS > 0 {
		cfg.SlowCallDuration = time.Duration(cbSpec.SlowCallDurationMS) * time.Millisecond
	}

	if cbSpec.SlowCallRateThreshold > 0 {
		if cfg.SlowCallDuration > 0 {
			cfg.SlowCallRateThreshold = clampPercent(cbSpec.SlowCallRateThreshold)
		} else {
			e.logger.Warn("slow call rate threshold provided without duration; ignoring", "node_id", node.ID)
		}
	}

	key := circuitBreakerKey(pipeline, node, meta)
	signature := fmt.Sprintf("%d|%s|%d|%s|%.2f|%s|%.2f|%d|%d",
		cfg.MaxFailures,
		cfg.Timeout.String(),
		cfg.MaxHalfOpenRequests,
		cfg.Window.String(),
		cfg.FailureRateThreshold,
		cfg.SlowCallDuration.String(),
		cfg.SlowCallRateThreshold,
		cfg.MinSamples,
		cfg.BucketCount,
	)
	if prev, ok := e.breakerConfigs[key]; !ok || prev != signature {
		e.breakerManager.Configure(key, cfg)
		e.breakerConfigs[key] = signature
	}

	return e.breakerManager.Get(key), true
}

func circuitBreakerKey(pipeline *domain.Pipeline, node *domain.PipelineNode, meta handlerMetadata) string {
	if pipeline == nil {
		return fmt.Sprintf("anonymous:%s:%s", meta.Canonical, node.ID)
	}
	return fmt.Sprintf("%s:%s:%s", pipeline.AgentID, pipeline.ID, node.ID)
}

func parseNodeType(raw string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(raw), "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

func canonicalKey(kind, version string) string {
	kind = strings.TrimSpace(kind)
	version = strings.TrimSpace(version)
	if version == "" {
		return kind
	}
	return kind + "@" + version
}

func versionFromKey(key string) string {
	_, version := parseNodeType(key)
	return version
}

func (r *handlerRegistry) register(kind, version string, handler runtime.NodeHandler, aliases ...string) {
	canonical := canonicalKey(kind, version)
	r.handlers[canonical] = handler
	for _, alias := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		r.aliases[alias] = canonical
	}
	if _, exists := r.aliases[kind]; !exists {
		r.aliases[kind] = canonical
	}
}

func (r *handlerRegistry) resolve(raw string) (runtime.NodeHandler, handlerMetadata, bool) {
	kind, version := parseNodeType(raw)
	canonical := canonicalKey(kind, version)
	if handler, ok := r.handlers[canonical]; ok {
		return handler, handlerMetadata{Kind: kind, Version: version, Canonical: canonical}, true
	}
	if alias, ok := r.aliases[raw]; ok {
		if handler, ok := r.handlers[alias]; ok {
			return handler, handlerMetadata{Kind: kind, Version: versionFromKey(alias), Canonical: alias}, true
		}
	}
	if version == "" {
		if alias, ok := r.aliases[kind]; ok {
			if handler, ok := r.handlers[alias]; ok {
				return handler, handlerMetadata{Kind: kind, Version: versionFromKey(alias), Canonical: alias}, true
			}
		}
	}
	return nil, handlerMetadata{}, false
}

func newHandlerRegistry() *handlerRegistry {
	return &handlerRegistry{
		handlers: make(map[string]runtime.NodeHandler),
		aliases:  make(map[string]string),
	}
}

// registerDefaultHandlers registers node handlers for production use.
func (e *DAGExecutor) registerDefaultHandlers() {
	passthroughHandler := &PassthroughNodeHandler{logger: e.logger}
	headersHandler := handlers.NewHeadersHandler(e.logger)
	headerTransformHandler := handlers.NewHeaderTransformHandler(e.logger)
	httpEgressHandler := handlers.NewEgressHTTPHandler(e.logger)
	wafHandler := handlers.NewWAFHandler(e.logger)
	dlpHandler := handlers.NewDLPHandler(e.logger)
	policyHandler := handlers.NewPolicyHandler(e.logger)
	allowHandler := &TerminalAllowHandler{logger: e.logger}

	e.handlers.register("auth.jwt.validate", "v1", passthroughHandler, "auth.jwt.validate", "auth", "auth.passthrough")
	e.handlers.register("headers.strip", "v1", headersHandler, "headers.strip", "auth.header.strip")
	e.handlers.register("transform.headers", "v1", headerTransformHandler,
		"transform.headers",
		"transform.headers.remove",
		"transform.headers.add",
		"transform.headers.set",
		"transform.headers.rename",
	)
	e.handlers.register("egress.http", "v2", httpEgressHandler, "egress.http", "egress")
	e.handlers.register("auth.egress.token", "v1", passthroughHandler)
	e.handlers.register("egress.token.inject", "v1", passthroughHandler, "egress.token.inject")
	e.handlers.register("policy.opa", "v1", policyHandler, "policy.opa", "policy", "policy.passthrough")
	e.handlers.register("decision.condition", "v1", passthroughHandler, "decision.condition")
	e.handlers.register("waf.inspect", "v1", wafHandler, "waf.inspect", "waf", "policy.waf")
	e.handlers.register("dlp.inspect", "v1", dlpHandler, "dlp.inspect", "dlp", "policy.dlp")
	e.handlers.register("terminal.deny", "v1", &TerminalDenyHandler{logger: e.logger}, "terminal.deny", "terminal_deny")
	e.handlers.register("terminal.error", "v1", &TerminalErrorHandler{logger: e.logger}, "terminal.error", "terminal_error")
	e.handlers.register("terminal.allow", "v1", allowHandler, "terminal.allow", "terminal_allow", "allow")
	e.handlers.register("passthrough", "v1", passthroughHandler, "passthrough")
}

// RegisterHandler adds or replaces a handler for a specific node type.
func (e *DAGExecutor) RegisterHandler(nodeType string, handler runtime.NodeHandler) {
	e.handlers.register(nodeType, "", handler)
}
