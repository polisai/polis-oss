package governance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrMaxRetriesExceeded is returned when all retry attempts have been exhausted.
	ErrMaxRetriesExceeded = errors.New("max retries exceeded")
	// ErrRequestTimeout is returned when a request exceeds its timeout.
	ErrRequestTimeout = errors.New("request timeout exceeded")
)

// IdempotentMethods lists HTTP methods that are safe to retry.
var IdempotentMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
	http.MethodOptions: true,
}

// RetryConfig defines retry behavior for upstream requests.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (0 = no retries).
	MaxRetries int
	// InitialBackoff is the initial delay before the first retry.
	InitialBackoff time.Duration
	// MaxBackoff is the maximum delay between retries.
	MaxBackoff time.Duration
	// BackoffMultiplier is the factor by which backoff increases.
	BackoffMultiplier float64
	// Jitter adds randomness to backoff to prevent thundering herd.
	Jitter bool
	// RetryableStatusCodes defines which HTTP status codes should trigger retries.
	RetryableStatusCodes map[int]bool
}

// DefaultRetryConfig returns sensible defaults for retry behavior.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:        3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
		RetryableStatusCodes: map[int]bool{
			http.StatusRequestTimeout:      true, // 408
			http.StatusTooManyRequests:     true, // 429
			http.StatusInternalServerError: true, // 500
			http.StatusBadGateway:          true, // 502
			http.StatusServiceUnavailable:  true, // 503
			http.StatusGatewayTimeout:      true, // 504
		},
	}
}

// TimeoutConfig defines timeout behavior for requests.
type TimeoutConfig struct {
	// RequestTimeout is the maximum duration for a complete request.
	RequestTimeout time.Duration
	// IdleTimeout is the maximum time between bytes during streaming.
	IdleTimeout time.Duration
	// AbsoluteTimeout is the maximum total duration for streaming connections.
	AbsoluteTimeout time.Duration
}

// DefaultTimeoutConfig returns sensible timeout defaults.
func DefaultTimeoutConfig() TimeoutConfig {
	return TimeoutConfig{
		RequestTimeout:  30 * time.Second,
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 15 * time.Minute,
	}
}

// RetryPolicy determines if a request should be retried.
type RetryPolicy struct {
	config RetryConfig
}

// NewRetryPolicy creates a retry policy with the given configuration.
func NewRetryPolicy(config RetryConfig) *RetryPolicy {
	if config.InitialBackoff <= 0 {
		config.InitialBackoff = 100 * time.Millisecond
	}
	if config.MaxBackoff <= 0 {
		config.MaxBackoff = 5 * time.Second
	}
	if config.BackoffMultiplier <= 0 {
		config.BackoffMultiplier = 2.0
	}
	if config.RetryableStatusCodes == nil {
		config.RetryableStatusCodes = DefaultRetryConfig().RetryableStatusCodes
	}

	return &RetryPolicy{config: config}
}

// Config returns a copy of the current retry configuration.
func (rp *RetryPolicy) Config() RetryConfig {
	return rp.config
}

// Configure updates the retry policy configuration atomically.
func (rp *RetryPolicy) Configure(config RetryConfig) error {
	if config.InitialBackoff <= 0 {
		return fmt.Errorf("initial backoff must be positive")
	}
	if config.MaxBackoff <= 0 {
		return fmt.Errorf("max backoff must be positive")
	}
	if config.BackoffMultiplier <= 0 {
		return fmt.Errorf("backoff multiplier must be positive")
	}
	if config.RetryableStatusCodes == nil {
		config.RetryableStatusCodes = DefaultRetryConfig().RetryableStatusCodes
	}

	rp.config = config
	return nil
}

// ShouldRetry determines if a request should be retried based on method and error.
func (rp *RetryPolicy) ShouldRetry(method string, statusCode int, err error, attempt int) bool {
	// Never retry if max attempts reached
	if attempt >= rp.config.MaxRetries {
		return false
	}

	// Only retry idempotent methods by default
	if !IsIdempotent(method) {
		return false
	}

	// Retry on network errors
	if err != nil {
		return true
	}

	// Retry on configured status codes
	if statusCode > 0 {
		return rp.config.RetryableStatusCodes[statusCode]
	}

	return false
}

// CalculateBackoff returns the delay before the next retry attempt.
func (rp *RetryPolicy) CalculateBackoff(attempt int) time.Duration {
	// Calculate exponential backoff
	backoff := time.Duration(float64(rp.config.InitialBackoff) * math.Pow(rp.config.BackoffMultiplier, float64(attempt)))

	// Cap at max backoff
	if backoff > rp.config.MaxBackoff {
		backoff = rp.config.MaxBackoff
	}

	// Add jitter if enabled
	if rp.config.Jitter {
		// Add random jitter of up to 25% of the backoff
		// #nosec G404 - Non-cryptographic random is acceptable for jitter
		jitter := time.Duration(rand.Int63n(int64(backoff / 4)))
		backoff += jitter
	}

	return backoff
}

// ExecuteWithRetry executes a function with retry logic.
func (rp *RetryPolicy) ExecuteWithRetry(
	ctx context.Context,
	method string,
	fn func() (int, error),
) (int, error) {
	var lastErr error
	var statusCode int

	for attempt := 0; attempt <= rp.config.MaxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		// Execute the function
		statusCode, lastErr = fn()

		// Success case - return immediately
		if lastErr == nil && statusCode >= 200 && statusCode < 300 {
			return statusCode, nil
		}

		// Check if we should retry
		if !rp.ShouldRetry(method, statusCode, lastErr, attempt) {
			// No more retries - wrap error
			if lastErr != nil {
				return statusCode, fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
			}
			return statusCode, ErrMaxRetriesExceeded
		}

		// Don't backoff after the last attempt
		if attempt < rp.config.MaxRetries {
			backoff := rp.CalculateBackoff(attempt)

			// Wait with context cancellation support
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	// Exhausted all retries
	if lastErr != nil {
		return statusCode, fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
	}
	return statusCode, ErrMaxRetriesExceeded
}

// TimeoutManager enforces timeout policies on requests.
type TimeoutManager struct {
	config TimeoutConfig
}

// NewTimeoutManager creates a timeout manager with the given configuration.
func NewTimeoutManager(config TimeoutConfig) *TimeoutManager {
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 30 * time.Second
	}
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 5 * time.Minute
	}
	if config.AbsoluteTimeout <= 0 {
		config.AbsoluteTimeout = 15 * time.Minute
	}

	return &TimeoutManager{config: config}
}

// Config returns a copy of the current timeout configuration.
func (tm *TimeoutManager) Config() TimeoutConfig {
	return tm.config
}

// Configure updates the timeout configuration atomically.
func (tm *TimeoutManager) Configure(config TimeoutConfig) error {
	if config.RequestTimeout <= 0 {
		return fmt.Errorf("request timeout must be positive")
	}
	if config.IdleTimeout <= 0 {
		return fmt.Errorf("idle timeout must be positive")
	}
	if config.AbsoluteTimeout <= 0 {
		return fmt.Errorf("absolute timeout must be positive")
	}

	tm.config = config
	return nil
}

// WithRequestTimeout creates a context with request timeout.
func (tm *TimeoutManager) WithRequestTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, tm.config.RequestTimeout)
}

// WithStreamingTimeouts creates a context with streaming-appropriate timeouts.
func (tm *TimeoutManager) WithStreamingTimeouts(ctx context.Context) (context.Context, context.CancelFunc) {
	// For streaming, use the absolute timeout as the deadline
	return context.WithTimeout(ctx, tm.config.AbsoluteTimeout)
}

// IdleTimeoutReader wraps an io.Reader to enforce idle timeouts between reads.
type IdleTimeoutReader struct {
	reader      *http.Response
	idleTimeout time.Duration
	lastRead    time.Time
}

// NewIdleTimeoutReader creates a reader that enforces idle timeout.
func NewIdleTimeoutReader(resp *http.Response, idleTimeout time.Duration) *IdleTimeoutReader {
	return &IdleTimeoutReader{
		reader:      resp,
		idleTimeout: idleTimeout,
		lastRead:    time.Now(),
	}
}

// Read implements io.Reader with idle timeout enforcement.
func (r *IdleTimeoutReader) Read(p []byte) (int, error) {
	// Check if idle timeout exceeded
	if time.Since(r.lastRead) > r.idleTimeout {
		return 0, fmt.Errorf("idle timeout exceeded after %v", r.idleTimeout)
	}

	n, err := r.reader.Body.Read(p)
	if n > 0 {
		r.lastRead = time.Now()
	}

	return n, err
}

// IsIdempotent returns true if the HTTP method is safe to retry.
func IsIdempotent(method string) bool {
	return IdempotentMethods[method]
}

// IsRetryableError determines if an error should trigger a retry.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Network errors are retryable
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check for specific error types that indicate transient failures
	errStr := err.Error()
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"no such host",
		"timeout",
		"temporary failure",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// RouteTimeoutConfig holds per-route timeout and retry configuration.
type RouteTimeoutConfig struct {
	RouteID string
	Timeout TimeoutConfig
	Retry   RetryConfig
}
