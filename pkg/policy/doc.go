// Package policy integrates the Open Policy Agent (OPA) engine with the Secure AI
// Proxy, evaluating Rego policies, governance postures, and content filters for
// every request.
//
// The package owns lifecycle management for policy bundles, wraps evaluation
// results in domain-friendly types, and exposes helpers for DLP and WAF
// extensions. It is intentionally decoupled from HTTP concerns so policies can
// be simulated, tested, and hot-reloaded independently of the data plane.
package policy
