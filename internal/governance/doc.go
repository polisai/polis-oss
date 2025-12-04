// Package governance coordinates runtime safety controls such as rate limiting,
// circuit breaking, retries, and timeout enforcement for the Secure AI Proxy.
//
// In addition to the core control loops, the package keeps lightweight admin
// helpers that surface governance metrics and allow zero-downtime configuration
// reloads. The data plane depends on these primitives to protect upstream
// services without introducing extra infrastructure coupling.
package governance
