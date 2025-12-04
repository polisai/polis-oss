package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/polisai/polis-oss/internal/governance"
)

// TestRateLimiterIntegration validates rate limiting behavior under load.
func TestRateLimiterIntegration(t *testing.T) {
	config := map[string]governance.RateLimiterConfig{
		"test-route": {
			RequestsPerSecond: 10,
			BurstSize:         5,
		},
	}

	rl := governance.NewRateLimiter(config)

	// Burst: first 5 should succeed immediately
	for i := 0; i < 5; i++ {
		if !rl.Allow("test-route") {
			t.Errorf("burst request %d should be allowed", i)
		}
	}

	// Next requests should be rate limited
	rejected := 0
	for i := 0; i < 10; i++ {
		if !rl.Allow("test-route") {
			rejected++
		}
	}

	if rejected == 0 {
		t.Error("expected some requests to be rate limited after burst")
	}

	// Wait for refill and verify recovery
	time.Sleep(200 * time.Millisecond) // Allow ~2 tokens to refill at 10/sec

	allowed := 0
	for i := 0; i < 5; i++ {
		if rl.Allow("test-route") {
			allowed++
		}
	}

	if allowed < 2 {
		t.Errorf("expected at least 2 requests allowed after refill, got %d", allowed)
	}
}

// TestCircuitBreakerIntegration validates circuit breaker state transitions.
func TestCircuitBreakerIntegration(t *testing.T) {
	config := governance.CircuitBreakerConfig{
		MaxFailures:         3,
		Timeout:             100 * time.Millisecond,
		MaxHalfOpenRequests: 2,
	}

	cb := governance.NewCircuitBreaker(config)

	// Phase 1: Closed - failures accumulate
	for i := 0; i < 3; i++ {
		_ = cb.Execute(func() error {
			return errors.New("simulated failure")
		})
	}

	if cb.State() != governance.StateOpen {
		t.Errorf("circuit should be open after %d failures, got %s", 3, cb.State())
	}

	// Phase 2: Open - requests rejected
	err := cb.Execute(func() error {
		t.Error("function should not be called when circuit is open")
		return nil
	})

	if !errors.Is(err, governance.ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}

	// Phase 3: Wait for timeout and transition to half-open
	time.Sleep(150 * time.Millisecond)

	// First request should be allowed (half-open)
	called := false
	err = cb.Execute(func() error {
		called = true
		return nil // Success
	})

	if err != nil {
		t.Errorf("first request after timeout should succeed, got %v", err)
	}

	if !called {
		t.Error("function should have been called in half-open state")
	}

	// After successful half-open requests, circuit should close
	// (need MaxHalfOpenRequests=2 successes)
	_ = cb.Execute(func() error {
		return nil
	})

	if cb.State() != governance.StateClosed {
		t.Errorf("circuit should be closed after successful recovery, got %s", cb.State())
	}
}

// TestRateLimitAndCircuitBreaker validates coordination between rate limiting and circuit breaking.
func TestRateLimitAndCircuitBreaker(t *testing.T) {
	// Setup: upstream that fails after rate limit is hit
	failAfter := 5
	requestCount := 0
	var mu sync.Mutex

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requestCount++
		count := requestCount
		mu.Unlock()

		if count > failAfter {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Configure governance
	rl := governance.NewRateLimiter(map[string]governance.RateLimiterConfig{
		"api": {RequestsPerSecond: 20, BurstSize: 10},
	})

	cb := governance.NewCircuitBreaker(governance.CircuitBreakerConfig{
		MaxFailures:         3,
		Timeout:             200 * time.Millisecond,
		MaxHalfOpenRequests: 2,
	})

	client := &http.Client{Timeout: 2 * time.Second}

	// Execute requests with both rate limit and circuit breaker
	var wg sync.WaitGroup
	results := make([]string, 20)

	for i := 0; i < 20; i++ {
		idx := i
		wg.Go(func() {
			// Check rate limit first
			if !rl.Allow("api") {
				results[idx] = "rate_limited"
				return
			}

			// Then check circuit breaker
			err := cb.Execute(func() error {
				resp, err := client.Get(upstream.URL)
				if err != nil {
					return err
				}
				defer func() {
					_ = resp.Body.Close()
				}()

				if resp.StatusCode >= 500 {
					return errors.New("upstream error")
				}
				return nil
			})

			if err != nil {
				if errors.Is(err, governance.ErrCircuitOpen) {
					results[idx] = "circuit_open"
				} else {
					results[idx] = "upstream_error"
				}
				return
			}

			results[idx] = "success"
		})

		// Small delay between requests
		time.Sleep(10 * time.Millisecond)
	}

	wg.Wait()

	// Analyze results
	stats := make(map[string]int)
	for _, result := range results {
		stats[result]++
	}

	t.Logf("Results: %+v", stats)

	// Validate: should have some successes, then failures trigger circuit breaker
	if stats["success"] == 0 {
		t.Error("expected some successful requests")
	}

	if stats["circuit_open"] == 0 {
		t.Error("expected circuit breaker to open after upstream failures")
	}

	// Verify circuit breaker opened
	if cb.State() != governance.StateOpen {
		t.Errorf("circuit should be open after failures, got %s", cb.State())
	}
}

// TestRetryWithCircuitBreaker validates retry behavior when circuit breaker is engaged.
func TestRetryWithCircuitBreaker(t *testing.T) {
	cb := governance.NewCircuitBreaker(governance.CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             100 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	})

	rp := governance.NewRetryPolicy(governance.RetryConfig{
		MaxRetries:        3,
		InitialBackoff:    10 * time.Millisecond,
		MaxBackoff:        50 * time.Millisecond,
		BackoffMultiplier: 2.0,
		Jitter:            false,
	})

	// Simulate flaky upstream
	attempts := 0
	upstream := func() (int, error) {
		attempts++
		if attempts <= 2 {
			return 503, errors.New("service unavailable")
		}
		return 200, nil // Succeed on retry
	}

	// Execute with retry wrapped in circuit breaker
	ctx := context.Background()
	err := cb.Execute(func() error {
		statusCode, retryErr := rp.ExecuteWithRetry(ctx, http.MethodGet, upstream)
		if retryErr != nil {
			return retryErr
		}
		if statusCode >= 500 {
			return errors.New("upstream error")
		}
		return nil
	})

	if err != nil {
		t.Errorf("retry should eventually succeed, got %v", err)
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts (initial + 2 retries), got %d", attempts)
	}

	// Circuit should still be closed (success path)
	if cb.State() != governance.StateClosed {
		t.Errorf("circuit should remain closed after successful retry, got %s", cb.State())
	}
}

// TestConcurrentGovernance validates thread safety under concurrent load.
func TestConcurrentGovernance(t *testing.T) {
	rl := governance.NewRateLimiter(map[string]governance.RateLimiterConfig{
		"test": {RequestsPerSecond: 100, BurstSize: 50},
	})

	cb := governance.NewCircuitBreaker(governance.DefaultCircuitBreakerConfig())

	var wg sync.WaitGroup
	concurrency := 50
	requestsPerGoroutine := 20

	for i := 0; i < concurrency; i++ {
		id := i
		wg.Go(func() {
			for j := 0; j < requestsPerGoroutine; j++ {
				// Rate limit check
				allowed := rl.Allow("test")

				if allowed {
					// Circuit breaker check
					_ = cb.Execute(func() error {
						// Simulate work
						time.Sleep(time.Microsecond)
						// Most succeed, occasional failure
						if (id+j)%20 == 0 {
							return errors.New("random failure")
						}
						return nil
					})
				}

				// Small delay to avoid overwhelming rate limiter
				time.Sleep(time.Millisecond)
			}
		})
	}

	wg.Wait()

	// Wait for rate limiter to refill
	time.Sleep(100 * time.Millisecond)

	// Verify both components are still functional
	if !rl.Allow("test") {
		t.Error("rate limiter should accept requests after refill period")
	}

	stats := cb.Stats()
	if stats.Successes == 0 {
		t.Error("circuit breaker should have recorded some successes")
	}

	t.Logf("Final state - CB: %+v", stats)
}

// TestTimeoutWithRetry validates timeout enforcement during retries.
func TestTimeoutWithRetry(t *testing.T) {
	tm := governance.NewTimeoutManager(governance.TimeoutConfig{
		RequestTimeout: 100 * time.Millisecond,
	})

	rp := governance.NewRetryPolicy(governance.RetryConfig{
		MaxRetries:        5,
		InitialBackoff:    50 * time.Millisecond,
		MaxBackoff:        200 * time.Millisecond,
		BackoffMultiplier: 2.0,
	})

	ctx, cancel := tm.WithRequestTimeout(context.Background())
	defer cancel()

	start := time.Now()
	attempts := 0

	_, err := rp.ExecuteWithRetry(ctx, http.MethodGet, func() (int, error) {
		attempts++
		time.Sleep(30 * time.Millisecond) // Simulate slow operation
		return 503, nil                   // Keep failing
	})

	elapsed := time.Since(start)

	// Should timeout before completing all retries
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}

	if elapsed > 150*time.Millisecond {
		t.Errorf("should timeout around 100ms, took %v", elapsed)
	}

	if attempts >= 5 {
		t.Errorf("should not complete all retries due to timeout, got %d attempts", attempts)
	}

	t.Logf("Timeout correctly enforced: %d attempts in %v", attempts, elapsed)
}
