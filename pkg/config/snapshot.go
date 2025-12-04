package config

import (
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
)

// PolicySummary surfaces key policy metadata for administration endpoints.
type PolicySummary struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	AttachedRoutes int    `json:"attachedRoutes"`
}

// GovernanceSummary carries rate limiting and circuit breaker state summaries.
type GovernanceSummary struct {
	RateLimits      map[string]any `json:"rateLimits"`
	CircuitBreakers map[string]any `json:"circuitBreakers"`
}

// Snapshot is the immutable representation of the current configuration (DTO).
type Snapshot struct {
	Generation       int64                    `json:"generation" yaml:"generation"`
	ReceivedAt       time.Time                `json:"receivedAt" yaml:"-"`
	RawPolicies      []PolicySpec             `json:"policies" yaml:"policies"`
	Pipelines        []PipelineSpec           `json:"pipelines" yaml:"pipelines"`
	PolicyBundles    []PolicyBundleDescriptor `json:"policyBundles" yaml:"policyBundles"`
	TrustBundles     map[string]*TrustBundle  `json:"trustBundles" yaml:"trustBundles"`
	Governance       GovernanceSummary        `json:"governance" yaml:"governance"`
	GovernanceConfig *domain.GovernanceConfig `json:"governanceConfig" yaml:"governanceConfig"`

	Policies          []PolicySummary                   `json:"-" yaml:"-"`
	PolicyIndex       map[string]PolicySpec             `json:"-" yaml:"-"`
	PolicyBundleIndex map[string]PolicyBundleDescriptor `json:"-" yaml:"-"`
}
