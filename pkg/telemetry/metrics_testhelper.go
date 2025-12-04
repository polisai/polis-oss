package telemetry

import "sync"

// ResetMetricsForTest clears cached metric instruments so tests can
// reinitialize them against a fresh MeterProvider. This is intended for
// use in test code only.
func ResetMetricsForTest() {
	metricsOnce = sync.Once{}
	metricsInitErr = nil
	nodeExecutionCounter = nil
	nodeRetryCounter = nil
	nodeCircuitOpenCounter = nil
	nodeRateLimitedCounter = nil
	nodeTimeoutCounter = nil
	nodeLatencyHistogram = nil
}
