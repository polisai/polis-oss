package domain

import (
	"sync"
	"time"
)

// Pipeline represents a per-agent DAG of processing nodes.
type Pipeline struct {
	ID            string
	Version       int
	AgentID       string
	Protocol      string // http, grpc, ws, mcp, etc.
	Triggers      []Trigger
	Variables     map[string]interface{}
	Defaults      PipelineDefaults
	Nodes         []PipelineNode
	Edges         []PipelineEdge
	EngineContext *PipelineEngineContext // Pre-initialized engines
}

// Trigger defines when a pipeline should be activated.
type Trigger struct {
	Type  string                 // session.start, http.request, grpc.call, ws.frame, mcp.event
	Match map[string]interface{} // Protocol-specific matchers
}

// PipelineDefaults holds default timeout and retry settings.
type PipelineDefaults struct {
	TimeoutMS          int
	Retries            PipelineRetryConfig
	EnableConditionals bool
}

// PipelineRetryConfig defines retry behavior for pipelines (simplified from RetryConfig).
type PipelineRetryConfig struct {
	MaxAttempts int
	Backoff     string // exponential, linear, fixed
	BaseMS      int
	MaxMS       int
}

// PipelineNode represents a processing step in the pipeline DAG.
type PipelineNode struct {
	ID         string
	Type       string                   // auth.jwt.validate, policy.opa, egress.http, etc.
	Config     map[string]interface{}   // Node-specific configuration
	When       []ConditionalBranch      // CEL-based conditional execution
	Posture    string                   // fail-open, fail-closed
	Governance PipelineGovernanceConfig // Per-node governance overrides
	On         NodeHandlers             // Success/failure handlers
}

// ConditionalBranch represents a CEL-based condition for node execution.
type ConditionalBranch struct {
	If   string // CEL expression
	Then string // Target node ID
}

// PipelineGovernanceConfig holds per-node governance settings (pipeline-specific).
type PipelineGovernanceConfig struct {
	TimeoutMS      int
	Retries        *PipelineRetryConfig
	CircuitBreaker *PipelineCircuitBreakerConfig
}

// PipelineCircuitBreakerConfig defines circuit breaker thresholds for pipelines.
type PipelineCircuitBreakerConfig struct {
	Window                string // Duration string (e.g., "10s")
	FailureRateThreshold  int    // Percentage 0-100
	SlowCallDurationMS    int    // Optional slow call threshold
	SlowCallRateThreshold int    // Optional slow call rate percentage
}

// NodeHandlers define node outcome routing.
type NodeHandlers struct {
	Success     string // Node ID to execute on success
	Failure     string // Node ID to execute on failure
	Timeout     string // Node ID to execute on timeout
	RateLimited string // Node ID to execute on rate limit
	CircuitOpen string // Node ID to execute on circuit open
	Else        string // Default handler
}

// PipelineEdge represents a conditional transition between nodes.
type PipelineEdge struct {
	From string // Source node ID
	To   string // Target node ID
	If   string // CEL expression (optional)
}

// PipelineEngineContext holds pre-initialized engines for a pipeline.
// Uses any to avoid circular imports (policy -> domain -> policy).
type PipelineEngineContext struct {
	PolicyEngines map[string]any // Node ID → policy.Engine (stored as any to break import cycle)
	mu            sync.RWMutex
}

// GetPolicyEngine retrieves a policy engine for the given node ID.
// Returns the engine as any - caller must type assert to *policy.Engine.
func (ctx *PipelineEngineContext) GetPolicyEngine(nodeID string) (any, bool) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	engine, ok := ctx.PolicyEngines[nodeID]
	return engine, ok
}

// Close shuts down all engines.
// Calls FlushCache() on each engine if it has that method (duck typing).
func (ctx *PipelineEngineContext) Close() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	for _, engine := range ctx.PolicyEngines {
		if engine != nil {
			// Type assert to interface with FlushCache method
			type cacheFlush interface {
				FlushCache()
			}
			if cf, ok := engine.(cacheFlush); ok {
				cf.FlushCache()
			}
		}
	}
	return nil
}

// PipelineContext holds runtime state during pipeline execution.
type PipelineContext struct {
	Pipeline  *Pipeline // Reference to executing pipeline
	Request   RequestContext
	Response  ResponseContext
	Session   SessionContext
	Variables map[string]interface{} // Mutable working variables
	Budgets   BudgetContext
	Security  SecurityContext
	Telemetry TelemetryContext
}

// RequestContext holds read-only request metadata.
type RequestContext struct {
	Method        string
	Path          string
	Host          string
	Headers       map[string][]string
	Protocol      string
	AgentID       string
	TenantID      string
	SessionID     string
	Streaming     bool
	StreamingMode string
	TriggerType   string
	TriggerIndex  int
	TLS           *TLSContext `json:"tls,omitempty"` // TLS connection information
}

// SessionContext holds session-level aggregates.
type SessionContext struct {
	TotalTokensIn    int
	TotalTokensOut   int
	EstimatedCostUSD float64
}

// ResponseContext captures response metadata for telemetry and enforcement.
type ResponseContext struct {
	Status    int
	Headers   map[string][]string
	Trailers  map[string][]string
	BytesSent int64
	BytesRead int64
}

// SecurityContext aggregates security-related findings during execution.
type SecurityContext struct {
	Findings    []SecurityFinding
	Violations  []Violation
	Blocked     bool
	BlockReason string
}

// SecurityFinding represents a single WAF/DLP or policy finding.
type SecurityFinding struct {
	Source   string
	RuleID   string
	Severity string
	Action   string
	Summary  string
	Metadata map[string]interface{}
}

// TelemetryContext tracks taints and redactions applied before export.
type TelemetryContext struct {
	Taints     map[string]TelemetryTaint
	Redactions []TelemetryRedaction
}

// TelemetryTaint marks an attribute as sensitive, triggering redaction.
type TelemetryTaint struct {
	Attribute string
	Reason    string
	Severity  string
	Source    string
}

// TelemetryRedaction records a performed redaction for auditing.
type TelemetryRedaction struct {
	Attribute string
	Strategy  string
	Reason    string
	Source    string
}

// TLSContext holds TLS connection information for pipeline processing
type TLSContext struct {
	Version            string        `json:"version"`
	CipherSuite        string        `json:"cipher_suite"`
	ServerName         string        `json:"server_name,omitempty"`
	PeerCertificates   []string      `json:"peer_certificates,omitempty"`
	NegotiatedProtocol string        `json:"negotiated_protocol,omitempty"`
	HandshakeDuration  time.Duration `json:"handshake_duration"`
	ClientAuth         bool          `json:"client_auth"`
}

// BudgetContext holds session/goal budget limits.
type BudgetContext struct {
	TimeMS           *int
	Tokens           *int
	Requests         *int
	EstimatedCostUSD *float64
}

// PipelineSelector selects the appropriate pipeline for a request.
type PipelineSelector interface {
	// SelectPipeline returns the pipeline for the given agent and protocol.
	SelectPipeline(agentID, protocol string) (*Pipeline, error)

	// UpdatePipelines atomically updates the pipeline registry.
	UpdatePipelines(pipelines []Pipeline) error
}

// PipelineExecutor executes a pipeline DAG for a request.
type PipelineExecutor interface {
	// Execute runs the pipeline for the given context.
	Execute(pipeline *Pipeline, ctx *PipelineContext) error
}

// ================================
// Simulation Types
// ================================

// SimulationRequest represents a request to simulate pipeline execution.
type SimulationRequest struct {
	AgentID    string                 `json:"agentId"`
	PipelineID string                 `json:"pipelineId"`
	Request    MockRequest            `json:"request"`
	Context    map[string]interface{} `json:"context"`
}

// MockRequest represents a simulated HTTP request.
type MockRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// SimulationResponse represents the result of a pipeline simulation.
type SimulationResponse struct {
	Response     MockResponse `json:"response"`
	FinalContext interface{}  `json:"finalContext"`
	Trace        []TraceEntry `json:"trace"`
}

// MockResponse represents a simulated HTTP response.
type MockResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// TraceEntry represents a single step in the execution trace.
type TraceEntry struct {
	NodeID    string                 `json:"nodeId"`
	NodeType  string                 `json:"nodeType"`
	Outcome   string                 `json:"outcome"`
	EdgeTaken string                 `json:"edgeTaken,omitempty"`
	Duration  string                 `json:"duration,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
