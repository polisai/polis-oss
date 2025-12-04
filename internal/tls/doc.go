// Package tls implements policy-driven TLS and mTLS configuration for inbound
// listeners and outbound egress connections.
//
// It provides helpers for building `tls.Config` instances, enforcing trust
// bundles delivered by the control plane, and evaluating per-agent posture so
// that secure defaults remain intact during hot reloads.
package tls
