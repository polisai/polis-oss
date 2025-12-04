package governance

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimiterConfig defines per-route rate limit settings.
type RateLimiterConfig struct {
	RequestsPerSecond int
	BurstSize         int
}

// RateLimiter implements token bucket rate limiting per route.
type RateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*tokenBucket
	config  map[string]RateLimiterConfig
}

// NewRateLimiter creates a rate limiter with the provided configuration.
func NewRateLimiter(config map[string]RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		config:  make(map[string]RateLimiterConfig),
	}
	rl.Configure(config)
	return rl
}

// Configure updates the rate limiter with new per-route limits.
func (rl *RateLimiter) Configure(config map[string]RateLimiterConfig) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Replace configuration
	rl.config = make(map[string]RateLimiterConfig, len(config))
	for routeID, cfg := range config {
		rl.config[routeID] = cfg
	}

	// Rebuild buckets with new config
	newBuckets := make(map[string]*tokenBucket, len(config))
	for routeID, cfg := range config {
		if bucket, exists := rl.buckets[routeID]; exists {
			// Preserve existing bucket but update config
			bucket.configure(cfg.RequestsPerSecond, cfg.BurstSize)
			newBuckets[routeID] = bucket
		} else {
			newBuckets[routeID] = newTokenBucket(cfg.RequestsPerSecond, cfg.BurstSize)
		}
	}
	rl.buckets = newBuckets
}

// Allow checks if a request for the given route should be allowed.
// Returns true if allowed, false if rate limit exceeded.
func (rl *RateLimiter) Allow(routeID string) bool {
	rl.mu.RLock()
	bucket, exists := rl.buckets[routeID]
	rl.mu.RUnlock()

	if !exists {
		// No rate limit configured for this route - allow
		return true
	}

	return bucket.take()
}

// Stats returns current rate limit statistics for all routes.
func (rl *RateLimiter) Stats() map[string]RateLimitStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := make(map[string]RateLimitStats, len(rl.buckets))
	for routeID, bucket := range rl.buckets {
		stats[routeID] = bucket.stats()
	}
	return stats
}

// RateLimitStats exposes current state of a rate limit bucket.
type RateLimitStats struct {
	Limit          int     `json:"limit"`
	BurstSize      int     `json:"burstSize"`
	Available      float64 `json:"available"`
	LastRefillTime string  `json:"lastRefillTime"`
}

// tokenBucket implements a token bucket algorithm for rate limiting.
type tokenBucket struct {
	mu         sync.Mutex
	rate       float64   // tokens per second
	capacity   float64   // maximum burst size
	tokens     float64   // current available tokens
	lastRefill time.Time // last time tokens were refilled
}

// newTokenBucket creates a token bucket with the specified rate and capacity.
func newTokenBucket(rps, burstSize int) *tokenBucket {
	if rps <= 0 {
		rps = 100 // Default rate
	}
	if burstSize <= 0 {
		burstSize = rps // Default burst = rate
	}

	return &tokenBucket{
		rate:       float64(rps),
		capacity:   float64(burstSize),
		tokens:     float64(burstSize), // Start with full bucket
		lastRefill: time.Now(),
	}
}

// configure updates the bucket's rate and capacity.
func (tb *tokenBucket) configure(rps, burstSize int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if rps <= 0 {
		rps = 100
	}
	if burstSize <= 0 {
		burstSize = rps
	}

	oldCapacity := tb.capacity
	tb.rate = float64(rps)
	tb.capacity = float64(burstSize)

	// If new capacity is higher, grant more tokens proportionally
	if tb.capacity > oldCapacity {
		tokensToAdd := tb.capacity - oldCapacity
		tb.tokens += tokensToAdd
	}

	// Cap tokens at new capacity
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
}

// take attempts to consume one token from the bucket.
// Returns true if a token was available, false otherwise.
func (tb *tokenBucket) take() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}

	return false
}

// refill adds tokens to the bucket based on elapsed time.
func (tb *tokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	// Add tokens based on rate and elapsed time
	tokensToAdd := elapsed * tb.rate
	tb.tokens += tokensToAdd

	// Cap at capacity
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	tb.lastRefill = now
}

// stats returns current statistics for this bucket.
func (tb *tokenBucket) stats() RateLimitStats {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	return RateLimitStats{
		Limit:          int(tb.rate),
		BurstSize:      int(tb.capacity),
		Available:      tb.tokens,
		LastRefillTime: tb.lastRefill.Format(time.RFC3339),
	}
}

// WriteRateLimitHeaders adds rate limit status headers to the response.
func WriteRateLimitHeaders(w http.ResponseWriter, limit, remaining int, resetTime time.Time) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
}

// AllowContext checks if a request is allowed, with context cancellation support.
func (rl *RateLimiter) AllowContext(ctx context.Context, routeID string) bool {
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return false
	default:
	}

	return rl.Allow(routeID)
}
