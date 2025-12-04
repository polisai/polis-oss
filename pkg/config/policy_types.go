package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/polisai/polis-oss/pkg/policy"
)

// PolicyArtifacts describes how a policy references bundle artifacts for various subsystems.
type PolicyArtifacts struct {
	OPA        OPAArtifacts        `json:"opa" yaml:"opa"`
	DLP        []string            `json:"dlp" yaml:"dlp"`
	WAF        []string            `json:"waf" yaml:"waf"`
	Governance GovernanceArtifacts `json:"governance" yaml:"governance"`
}

// OPAArtifacts declares the entrypoints and bundle artifact names for the policy engine.
type OPAArtifacts struct {
	Bundle             string `json:"bundle" yaml:"bundle"`
	RequestEntrypoint  string `json:"requestEntrypoint" yaml:"requestEntrypoint"`
	ResponseEntrypoint string `json:"responseEntrypoint" yaml:"responseEntrypoint"`
}

// GovernanceArtifacts references bundle artifacts that configure governance modules.
type GovernanceArtifacts struct {
	RateLimits     string `json:"rateLimits" yaml:"rateLimits"`
	CircuitBreaker string `json:"circuitBreaker" yaml:"circuitBreaker"`
	Timeouts       string `json:"timeouts" yaml:"timeouts"`
}

// Normalize validates and canonicalises artifact references.
func (a *PolicyArtifacts) Normalize() error {
	if a == nil {
		return nil
	}

	a.OPA.Bundle = strings.TrimSpace(a.OPA.Bundle)
	a.OPA.RequestEntrypoint = strings.TrimSpace(a.OPA.RequestEntrypoint)
	a.OPA.ResponseEntrypoint = strings.TrimSpace(a.OPA.ResponseEntrypoint)
	// When a bundle is referenced ensure entrypoint defaults are set.
	if a.OPA.Bundle != "" {
		if a.OPA.RequestEntrypoint == "" {
			a.OPA.RequestEntrypoint = "policy/request"
		}
		if a.OPA.ResponseEntrypoint == "" {
			a.OPA.ResponseEntrypoint = "policy/response"
		}
	}

	a.DLP = normalizeArtifactList(a.DLP)
	a.WAF = normalizeArtifactList(a.WAF)

	a.Governance.RateLimits = strings.TrimSpace(a.Governance.RateLimits)
	a.Governance.CircuitBreaker = strings.TrimSpace(a.Governance.CircuitBreaker)
	a.Governance.Timeouts = strings.TrimSpace(a.Governance.Timeouts)

	return nil
}

// Clone returns a deep copy of the artifact references.
func (a PolicyArtifacts) Clone() PolicyArtifacts {
	clone := PolicyArtifacts{
		OPA: OPAArtifacts{
			Bundle:             a.OPA.Bundle,
			RequestEntrypoint:  a.OPA.RequestEntrypoint,
			ResponseEntrypoint: a.OPA.ResponseEntrypoint,
		},
		Governance: GovernanceArtifacts{
			RateLimits:     a.Governance.RateLimits,
			CircuitBreaker: a.Governance.CircuitBreaker,
			Timeouts:       a.Governance.Timeouts,
		},
	}
	if len(a.DLP) > 0 {
		clone.DLP = append([]string(nil), a.DLP...)
	}
	if len(a.WAF) > 0 {
		clone.WAF = append([]string(nil), a.WAF...)
	}
	return clone
}

// PolicySpec represents a decoded policy entry from the control plane snapshot.
type PolicySpec struct {
	ID               string            `json:"id" yaml:"id"`
	Version          int               `json:"version" yaml:"version"`
	Name             string            `json:"name" yaml:"name"`
	Description      string            `json:"description" yaml:"description"`
	RequireAuth      *bool             `json:"requireAuth" yaml:"requireAuth"` // If nil, defaults to true
	FailureOverrides map[string]string `json:"failurePosture" yaml:"failurePosture"`
	RawMTLS          RawMTLS           `json:"mtls" yaml:"mtls"`
	BundleRef        string            `json:"bundleRef" yaml:"bundleRef"`
	BundleVersion    int               `json:"bundleVersion" yaml:"bundleVersion"`
	Artifacts        PolicyArtifacts   `json:"artifacts" yaml:"artifacts"`

	FailurePosture      policy.PostureSet `json:"-" yaml:"-"`
	MTLS                EffectiveMTLS     `json:"-" yaml:"-"`
	ResolvedRequireAuth bool              `json:"-" yaml:"-"` // Normalized auth requirement (default: true)
}

// Normalize applies defaults and validates references.
func (p *PolicySpec) Normalize() error {
	if p.ID == "" {
		return errors.New("policy id is required")
	}

	p.BundleRef = strings.TrimSpace(p.BundleRef)
	if p.BundleRef != "" && p.BundleVersion <= 0 {
		return fmt.Errorf("policy %s requires a bundleVersion when bundleRef is set", p.ID)
	}
	if err := p.Artifacts.Normalize(); err != nil {
		return fmt.Errorf("policy %s artifacts: %w", p.ID, err)
	}

	// Normalize auth requirement (default to true - authentication required)
	if p.RequireAuth == nil {
		p.ResolvedRequireAuth = true
	} else {
		p.ResolvedRequireAuth = *p.RequireAuth
	}

	defaults := policy.DefaultPostureSet()
	if err := defaults.ApplyOverrideStrings(p.FailureOverrides); err != nil {
		return fmt.Errorf("policy %s failure posture: %w", p.ID, err)
	}
	p.FailurePosture = defaults

	effective, err := p.RawMTLS.ToEffective()
	if err != nil {
		return fmt.Errorf("policy %s mtls: %w", p.ID, err)
	}
	p.MTLS = effective
	return nil
}

// Clone provides a deep copy suitable for immutable snapshots.
func (p PolicySpec) Clone() PolicySpec {
	var requireAuthClone *bool
	if p.RequireAuth != nil {
		val := *p.RequireAuth
		requireAuthClone = &val
	}

	clone := PolicySpec{
		ID:                  p.ID,
		Version:             p.Version,
		Name:                p.Name,
		Description:         p.Description,
		RequireAuth:         requireAuthClone,
		FailureOverrides:    copyStringMap(p.FailureOverrides),
		RawMTLS:             p.RawMTLS.Clone(),
		BundleRef:           p.BundleRef,
		BundleVersion:       p.BundleVersion,
		Artifacts:           p.Artifacts.Clone(),
		FailurePosture:      p.FailurePosture.Clone(),
		MTLS:                p.MTLS,
		ResolvedRequireAuth: p.ResolvedRequireAuth,
	}
	return clone
}

// PipelineSpec encodes a DAG-based pipeline configuration.
type PipelineSpec struct {
	ID        string                 `json:"id" yaml:"id"`
	Version   int                    `json:"version" yaml:"version"`
	AgentID   string                 `json:"agentId" yaml:"agentId"`
	Protocol  string                 `json:"protocol" yaml:"protocol"`
	Triggers  []TriggerSpec          `json:"triggers,omitempty" yaml:"triggers,omitempty"`
	Variables map[string]interface{} `json:"variables,omitempty" yaml:"variables,omitempty"`
	Defaults  PipelineDefaultsSpec   `json:"defaults,omitempty" yaml:"defaults,omitempty"`
	Nodes     []PipelineNodeSpec     `json:"nodes" yaml:"nodes"`
	Edges     []PipelineEdgeSpec     `json:"edges,omitempty" yaml:"edges,omitempty"`
}

// TriggerSpec defines when a pipeline should be activated.
type TriggerSpec struct {
	Type  string                 `json:"type" yaml:"type"`
	Match map[string]interface{} `json:"match,omitempty" yaml:"match,omitempty"`
}

// PipelineDefaultsSpec holds default timeout and retry settings.
type PipelineDefaultsSpec struct {
	TimeoutMS          int                     `json:"timeoutMs,omitempty" yaml:"timeoutMs,omitempty"`
	Retries            PipelineRetryConfigSpec `json:"retries,omitempty" yaml:"retries,omitempty"`
	EnableConditionals bool                    `json:"enableConditionals,omitempty" yaml:"enableConditionals,omitempty"`
}

// PipelineRetryConfigSpec defines retry behavior.
type PipelineRetryConfigSpec struct {
	MaxAttempts int    `json:"maxAttempts,omitempty" yaml:"maxAttempts,omitempty"`
	Backoff     string `json:"backoff,omitempty" yaml:"backoff,omitempty"`
	BaseMS      int    `json:"baseMs,omitempty" yaml:"baseMs,omitempty"`
	MaxMS       int    `json:"maxMs,omitempty" yaml:"maxMs,omitempty"`
}

// PipelineNodeSpec represents a processing step in the pipeline.
type PipelineNodeSpec struct {
	ID         string                       `json:"id" yaml:"id"`
	Type       string                       `json:"type" yaml:"type"`
	Config     map[string]interface{}       `json:"config,omitempty" yaml:"config,omitempty"`
	When       []ConditionalBranchSpec      `json:"when,omitempty" yaml:"when,omitempty"`
	Posture    string                       `json:"posture,omitempty" yaml:"posture,omitempty"`
	Governance PipelineGovernanceConfigSpec `json:"governance,omitempty" yaml:"governance,omitempty"`
	On         NodeHandlersSpec             `json:"on" yaml:"on"`
}

// ConditionalBranchSpec represents a CEL-based condition.
type ConditionalBranchSpec struct {
	If   string `json:"if" yaml:"if"`
	Then string `json:"then" yaml:"then"`
}

// PipelineGovernanceConfigSpec holds per-node governance settings.
type PipelineGovernanceConfigSpec struct {
	TimeoutMS      int                               `json:"timeoutMs,omitempty" yaml:"timeoutMs,omitempty"`
	Retries        *PipelineRetryConfigSpec          `json:"retries,omitempty" yaml:"retries,omitempty"`
	CircuitBreaker *PipelineCircuitBreakerConfigSpec `json:"circuitBreaker,omitempty" yaml:"circuitBreaker,omitempty"`
}

// PipelineCircuitBreakerConfigSpec defines circuit breaker thresholds.
type PipelineCircuitBreakerConfigSpec struct {
	Window                string `json:"window,omitempty" yaml:"window,omitempty"`
	FailureRateThreshold  int    `json:"failureRateThreshold,omitempty" yaml:"failureRateThreshold,omitempty"`
	SlowCallDurationMS    int    `json:"slowCallDurationMs,omitempty" yaml:"slowCallDurationMs,omitempty"`
	SlowCallRateThreshold int    `json:"slowCallRateThreshold,omitempty" yaml:"slowCallRateThreshold,omitempty"`
}

// NodeHandlersSpec defines node outcome routing.
type NodeHandlersSpec struct {
	Success     string `json:"success,omitempty" yaml:"success,omitempty"`
	Failure     string `json:"failure,omitempty" yaml:"failure,omitempty"`
	Timeout     string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	RateLimited string `json:"rateLimited,omitempty" yaml:"rateLimited,omitempty"`
	CircuitOpen string `json:"circuitOpen,omitempty" yaml:"circuitOpen,omitempty"`
	Else        string `json:"else,omitempty" yaml:"else,omitempty"`
}

// PipelineEdgeSpec represents a conditional transition between nodes.
type PipelineEdgeSpec struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`
	If   string `json:"if,omitempty" yaml:"if,omitempty"`
}
