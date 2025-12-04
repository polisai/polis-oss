// Package domain defines the core business types and interfaces for the Secure AI Proxy.
//
// This package contains pure domain logic with ZERO external dependencies outside the
// Go standard library. All types in this package are:
//
// - Independent of infrastructure (no database, HTTP, gRPC, etc.)
// - Technology-agnostic (no framework coupling)
// - Testable in isolation without mocks
// - Stable and unlikely to change frequently
//
// Other packages (auth, pipeline, policy, etc.) implement the interfaces defined here
// and depend on these types. The dependency direction is always:
//
//	Infrastructure → Domain (CORRECT)
//	Domain → Infrastructure (FORBIDDEN)
//
// This architecture enables:
// - Easy testing through interface mocking
// - Technology swap without domain changes
// - Clear separation of concerns
// - Flexible composition in main.go
package domain
