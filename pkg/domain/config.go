package domain

import "time"

// Snapshot represents a point-in-time configuration state.
type Snapshot struct {
	Generation string
	Policies   []Policy
	Pipelines  []Pipeline
	Governance GovernanceConfig
	Timestamp  time.Time
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
