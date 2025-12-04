// Package telemetry wires OpenTelemetry exporters, meters, and loggers for the
// Secure AI Proxy.
//
// It centralises trace provider setup, applies proxy-specific resource
// attributes, and offers enrichment helpers that attach agent, policy, and
// security metadata to spans and logs so operators can correlate enforcement
// decisions with upstream behaviour.
package telemetry
