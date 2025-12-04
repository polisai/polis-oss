package governance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

var (
	// ErrCircuitOpen is returned when the circuit breaker is in the open state.
	ErrCircuitOpen = errors.New("circuit breaker is open")
)

// CircuitBreakerState represents the state of a circuit breaker.
type CircuitBreakerState string

const (
	// StateClosed indicates the circuit is closed and requests are allowed.
	StateClosed CircuitBreakerState = "closed"
	// StateOpen indicates the circuit is open and requests are rejected.
	StateOpen CircuitBreakerState = "open"
	// StateHalfOpen indicates the circuit is testing if the service has recovered.
	StateHalfOpen CircuitBreakerState = "half-open"
)

// CircuitBreakerConfig defines thresholds for circuit breaking.
type CircuitBreakerConfig struct {
	// MaxFailures defines the legacy consecutive failure threshold before opening.
	// When FailureRateThreshold is zero, this fallback is used.
	MaxFailures int
	// Timeout is how long the circuit stays open before transitioning to half-open.
	Timeout time.Duration
	// MaxHalfOpenRequests is the number of test requests allowed in half-open state
	// before forcing a decision (close on success, open on failure).
	MaxHalfOpenRequests int
	// Window controls the look-back duration for rolling failure/slow-call analysis.
	Window time.Duration
	// BucketCount is the number of time buckets used to approximate the rolling window.
	BucketCount int
	// FailureRateThreshold is the percentage (0-100) of failures within the rolling window
	// that will open the circuit. Values <=0 disable rate-based evaluation.
	FailureRateThreshold float64
	// SlowCallDuration marks calls taking longer than this duration as "slow".
	SlowCallDuration time.Duration
	// SlowCallRateThreshold is the percentage (0-100) of slow calls in the rolling window
	// that will open the circuit. Values <=0 disable slow-call evaluation.
	SlowCallRateThreshold float64
	// MinSamples is the minimum number of calls observed within the rolling window
	// before applying rate-based evaluation. Values <=0 disable the guard.
	MinSamples int
}

// DefaultCircuitBreakerConfig returns sensible defaults.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:           5,
		Timeout:               30 * time.Second,
		MaxHalfOpenRequests:   3,
		Window:                30 * time.Second,
		BucketCount:           10,
		FailureRateThreshold:  50, // percent
		SlowCallDuration:      0,
		SlowCallRateThreshold: 0,
		MinSamples:            5,
	}
}

// CircuitBreaker implements the circuit breaker pattern for upstream services.
type CircuitBreaker struct {
	mu      sync.RWMutex
	state   CircuitBreakerState
	config  CircuitBreakerConfig
	metrics circuitMetrics
}

type circuitMetrics struct {
	// rolling window accounting
	buckets            []bucketMetrics
	bucketDuration     time.Duration
	currentBucketIdx   int
	currentBucketStart time.Time
	// totals
	totalFailures  int
	totalSuccesses int
	// consecutive counters for legacy / half-open behaviour
	consecutiveFailures  int
	consecutiveSuccesses int
	halfOpenRequests     int
	lastStateChange      time.Time
	openUntil            time.Time
}

type bucketMetrics struct {
	start     time.Time
	requests  int
	failures  int
	slowCalls int
}

// NewCircuitBreaker creates a circuit breaker with the provided configuration.
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	if config.MaxFailures < 0 {
		config.MaxFailures = 0
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxHalfOpenRequests <= 0 {
		config.MaxHalfOpenRequests = 3
	}
	if config.Window <= 0 {
		config.Window = 30 * time.Second
	}
	if config.BucketCount <= 0 {
		config.BucketCount = 10
	}
	if config.FailureRateThreshold < 0 {
		config.FailureRateThreshold = 0
	}
	if config.SlowCallRateThreshold < 0 {
		config.SlowCallRateThreshold = 0
	}
	if config.MinSamples < 0 {
		config.MinSamples = 0
	}
	// Derive a reasonable default for MinSamples when not provided explicitly.
	if config.MinSamples == 0 {
		if config.MaxFailures > 0 {
			config.MinSamples = config.MaxFailures
		}
		if config.MinSamples < 5 {
			config.MinSamples = 5
		}
	}

	bucketDuration := config.Window / time.Duration(config.BucketCount)
	if bucketDuration <= 0 {
		bucketDuration = time.Second
	}

	return &CircuitBreaker{
		state:  StateClosed,
		config: config,
		metrics: circuitMetrics{
			buckets:            make([]bucketMetrics, config.BucketCount),
			bucketDuration:     bucketDuration,
			currentBucketIdx:   0,
			currentBucketStart: time.Time{},
			lastStateChange:    time.Now(),
		},
	}
}

// Execute wraps a function call with circuit breaker protection.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	start := time.Now()
	err := fn()
	duration := time.Since(start)
	cb.afterRequest(duration, err)
	return err
}

// ExecuteContext wraps a function call with circuit breaker and context support.
func (cb *CircuitBreaker) ExecuteContext(ctx context.Context, fn func(context.Context) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := cb.beforeRequest(); err != nil {
		return err
	}

	start := time.Now()
	err := fn(ctx)
	duration := time.Since(start)
	cb.afterRequest(duration, err)
	return err
}

// beforeRequest checks if the request should be allowed.
func (cb *CircuitBreaker) beforeRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		return nil
	case StateOpen:
		if !cb.metrics.openUntil.IsZero() && now.After(cb.metrics.openUntil) {
			cb.transitionToLocked(StateHalfOpen, now)
			cb.metrics.halfOpenRequests++
			return nil
		}
		return ErrCircuitOpen
	case StateHalfOpen:
		if cb.metrics.halfOpenRequests < cb.config.MaxHalfOpenRequests {
			cb.metrics.halfOpenRequests++
			return nil
		}
		return ErrCircuitOpen
	default:
		return fmt.Errorf("unknown circuit breaker state: %s", cb.state)
	}
}

// afterRequest records the result of a request.
func (cb *CircuitBreaker) afterRequest(duration time.Duration, err error) {
	now := time.Now()
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.rotateBucketsLocked(now)
	cb.recordCallLocked(now, duration, err)
}

func (cb *CircuitBreaker) recordCallLocked(now time.Time, duration time.Duration, err error) {
	bucket := &cb.metrics.buckets[cb.metrics.currentBucketIdx]
	bucket.requests++

	if cb.config.SlowCallDuration > 0 && duration >= cb.config.SlowCallDuration {
		bucket.slowCalls++
	}

	if err == nil {
		cb.metrics.totalSuccesses++
		cb.metrics.consecutiveSuccesses++
		cb.metrics.consecutiveFailures = 0
	} else {
		bucket.failures++
		cb.metrics.totalFailures++
		cb.metrics.consecutiveFailures++
		cb.metrics.consecutiveSuccesses = 0
	}

	switch cb.state {
	case StateHalfOpen:
		if err != nil {
			cb.transitionToLocked(StateOpen, now)
			return
		}
		if cb.metrics.consecutiveSuccesses >= cb.config.MaxHalfOpenRequests {
			cb.transitionToLocked(StateClosed, now)
		}
	case StateClosed:
		if err != nil && cb.config.MaxFailures > 0 && cb.metrics.consecutiveFailures >= cb.config.MaxFailures {
			cb.transitionToLocked(StateOpen, now)
			return
		}
		cb.evaluateWindowLocked(now)
	}
}

func (cb *CircuitBreaker) evaluateWindowLocked(now time.Time) {
	if cb.config.FailureRateThreshold <= 0 && (cb.config.SlowCallRateThreshold <= 0 || cb.config.SlowCallDuration <= 0) {
		return
	}

	requests, failures, slowCalls := cb.aggregateWindowLocked(now)
	if requests == 0 {
		return
	}

	if cb.config.MinSamples > 0 && requests < cb.config.MinSamples {
		return
	}

	if cb.config.FailureRateThreshold > 0 {
		failureRate := (float64(failures) / float64(requests)) * 100
		if failureRate >= cb.config.FailureRateThreshold {
			cb.transitionToLocked(StateOpen, now)
			return
		}
	}

	if cb.config.SlowCallRateThreshold > 0 && cb.config.SlowCallDuration > 0 {
		slowRate := (float64(slowCalls) / float64(requests)) * 100
		if slowRate >= cb.config.SlowCallRateThreshold {
			cb.transitionToLocked(StateOpen, now)
		}
	}
}

func (cb *CircuitBreaker) aggregateWindowLocked(now time.Time) (requests int, failures int, slowCalls int) {
	window := cb.config.Window
	if window <= 0 {
		window = cb.metrics.bucketDuration * time.Duration(len(cb.metrics.buckets))
	}

	for _, bucket := range cb.metrics.buckets {
		if bucket.requests == 0 {
			continue
		}
		if bucket.start.IsZero() {
			continue
		}
		if now.Sub(bucket.start) > window {
			continue
		}
		requests += bucket.requests
		failures += bucket.failures
		slowCalls += bucket.slowCalls
	}

	return
}

func (cb *CircuitBreaker) rotateBucketsLocked(now time.Time) {
	if len(cb.metrics.buckets) == 0 {
		return
	}

	if cb.metrics.currentBucketStart.IsZero() {
		cb.metrics.currentBucketStart = now.Truncate(cb.metrics.bucketDuration)
		cb.metrics.buckets[cb.metrics.currentBucketIdx].start = cb.metrics.currentBucketStart
		return
	}

	if now.Before(cb.metrics.currentBucketStart) {
		return
	}

	elapsed := now.Sub(cb.metrics.currentBucketStart)
	if elapsed < cb.metrics.bucketDuration {
		return
	}

	steps := int(math.Floor(float64(elapsed) / float64(cb.metrics.bucketDuration)))
	// When traffic gap exceeds window duration (steps >= buckets), reset all buckets
	// to avoid stale data influencing circuit state. This ensures circuit breaker
	// reacts to current traffic conditions after prolonged idle periods.
	if steps > 0 {
		// Only rotate up to the number of buckets to avoid unnecessary resets.
		rotate := steps
		if rotate > len(cb.metrics.buckets) {
			rotate = len(cb.metrics.buckets)
		}
		for i := 0; i < rotate; i++ {
			cb.metrics.currentBucketIdx = (cb.metrics.currentBucketIdx + 1) % len(cb.metrics.buckets)
			cb.metrics.currentBucketStart = cb.metrics.currentBucketStart.Add(cb.metrics.bucketDuration)
			cb.metrics.buckets[cb.metrics.currentBucketIdx] = bucketMetrics{start: cb.metrics.currentBucketStart}
		}
	}
}

func (cb *CircuitBreaker) resetBucketsLocked(now time.Time) {
	for i := range cb.metrics.buckets {
		cb.metrics.buckets[i] = bucketMetrics{}
	}
	cb.metrics.currentBucketIdx = 0
	cb.metrics.currentBucketStart = now.Truncate(cb.metrics.bucketDuration)
	cb.metrics.buckets[0].start = cb.metrics.currentBucketStart
}

func (cb *CircuitBreaker) transitionToLocked(newState CircuitBreakerState, now time.Time) {
	if cb.state == newState {
		return
	}

	cb.state = newState
	cb.metrics.lastStateChange = now
	cb.metrics.consecutiveFailures = 0
	cb.metrics.consecutiveSuccesses = 0
	cb.metrics.halfOpenRequests = 0

	switch newState {
	case StateOpen:
		cb.metrics.openUntil = now.Add(cb.config.Timeout)
		cb.resetBucketsLocked(now)
	case StateHalfOpen:
		cb.metrics.openUntil = time.Time{}
		cb.resetBucketsLocked(now)
	case StateClosed:
		cb.metrics.openUntil = time.Time{}
	}
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Stats returns current circuit breaker statistics.
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	now := time.Now()
	requests, failures, slowCalls := cb.aggregateWindowLocked(now)
	failureRate := 0.0
	slowRate := 0.0
	if requests > 0 {
		failureRate = (float64(failures) / float64(requests)) * 100
		slowRate = (float64(slowCalls) / float64(requests)) * 100
	}

	return CircuitBreakerStats{
		State:               string(cb.state),
		Failures:            cb.metrics.totalFailures,
		Successes:           cb.metrics.totalSuccesses,
		LastStateChange:     cb.metrics.lastStateChange.Format(time.RFC3339),
		FailureRate:         failureRate,
		SlowCallRate:        slowRate,
		Window:              cb.config.Window.String(),
		Timeout:             cb.config.Timeout.String(),
		HalfOpenRequests:    cb.metrics.halfOpenRequests,
		MaxHalfOpenRequests: cb.config.MaxHalfOpenRequests,
	}
}

// CircuitBreakerStats exposes circuit breaker status information.
type CircuitBreakerStats struct {
	State               string  `json:"state"`
	Failures            int     `json:"failures"`
	Successes           int     `json:"successes"`
	LastStateChange     string  `json:"lastStateChange"`
	FailureRate         float64 `json:"failureRate"`
	SlowCallRate        float64 `json:"slowCallRate"`
	Window              string  `json:"window"`
	Timeout             string  `json:"timeout"`
	HalfOpenRequests    int     `json:"halfOpenRequests"`
	MaxHalfOpenRequests int     `json:"maxHalfOpenRequests"`
}

// Reset manually resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	cb.transitionToLocked(StateClosed, now)
	cb.metrics.totalFailures = 0
	cb.metrics.totalSuccesses = 0
	cb.resetBucketsLocked(now)
}

// CircuitBreakerManager manages circuit breakers for multiple services.
type CircuitBreakerManager struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
}

// NewCircuitBreakerManager creates a new circuit breaker manager.
func NewCircuitBreakerManager() *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// Configure adds or updates a circuit breaker for a service.
func (m *CircuitBreakerManager) Configure(serviceID string, config CircuitBreakerConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.breakers[serviceID] = NewCircuitBreaker(config)
}

// Get retrieves the circuit breaker for a service, creating one if needed.
func (m *CircuitBreakerManager) Get(serviceID string) *CircuitBreaker {
	m.mu.RLock()
	cb, exists := m.breakers[serviceID]
	m.mu.RUnlock()

	if exists {
		return cb
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if cb, exists := m.breakers[serviceID]; exists {
		return cb
	}

	cb = NewCircuitBreaker(DefaultCircuitBreakerConfig())
	m.breakers[serviceID] = cb
	return cb
}

// Stats returns statistics for all circuit breakers.
func (m *CircuitBreakerManager) Stats() map[string]CircuitBreakerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]CircuitBreakerStats, len(m.breakers))
	for serviceID, cb := range m.breakers {
		stats[serviceID] = cb.Stats()
	}
	return stats
}

// ResetAll resets all circuit breakers to closed state.
func (m *CircuitBreakerManager) ResetAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cb := range m.breakers {
		cb.Reset()
	}
}
