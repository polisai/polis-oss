package domain

import "time"

// Snapshot represents a point-in-time configuration state.
type Snapshot struct {
	Generation    string
	Policies      []Policy
	Pipelines     []Pipeline
	PolicyBundles []PolicyBundleDescriptor
	Governance    GovernanceConfig
	Timestamp     time.Time
}

// PolicyBundleDescriptor describes how to obtain a policy bundle.
type PolicyBundleDescriptor struct {
	ID        string                     `json:"id" yaml:"id"`
	Name      string                     `json:"name" yaml:"name"`
	Version   int                        `json:"version" yaml:"version"`
	Revision  string                     `json:"revision" yaml:"revision"`
	Path      string                     `json:"path" yaml:"path"`
	SizeLimit int64                      `json:"sizeLimit" yaml:"sizeLimit"`
	Labels    map[string]string          `json:"labels" yaml:"labels"`
	Artifacts []BundleArtifactDescriptor `json:"artifacts" yaml:"artifacts"`
}

// BundleArtifactDescriptor declares how to retrieve an artifact within a bundle.
type BundleArtifactDescriptor struct {
	Name        string            `json:"name" yaml:"name"`
	Path        string            `json:"path" yaml:"path"`
	Type        string            `json:"type" yaml:"type"`
	MediaType   string            `json:"mediaType" yaml:"mediaType"`
	Encoding    string            `json:"encoding" yaml:"encoding"`
	Compression string            `json:"compression" yaml:"compression"`
	SHA256      string            `json:"sha256" yaml:"sha256"`
	Metadata    map[string]string `json:"metadata" yaml:"metadata"`
}

// GovernanceConfig holds governance policy configuration.
type GovernanceConfig struct {
	RateLimits      []RateLimitConfig
	CircuitBreakers []CircuitBreakerConfig
	Timeouts        []TimeoutConfig
	Retries         []RetryConfig
}

// RateLimitConfig defines rate limiting parameters.
type RateLimitConfig struct {
	ID                string
	RequestsPerSecond float64
	BurstSize         int
	Scope             string // "global", "route", "user"
}

// CircuitBreakerConfig defines circuit breaker parameters.
type CircuitBreakerConfig struct {
	ID               string
	FailureThreshold int
	SuccessThreshold int
	Timeout          time.Duration
	HalfOpenMaxCalls int
}

// TimeoutConfig defines timeout parameters.
type TimeoutConfig struct {
	ID              string
	RequestTimeout  time.Duration
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
}

// RetryConfig defines retry parameters.
type RetryConfig struct {
	ID           string
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       bool
}

// ConfigService defines the interface for configuration management.
type ConfigService interface {
	// CurrentSnapshot returns the current configuration.
	CurrentSnapshot() Snapshot

	// UpdateSnapshot atomically updates configuration.
	UpdateSnapshot(snapshot Snapshot) error

	// Subscribe to configuration changes.
	Subscribe() <-chan Snapshot
}
