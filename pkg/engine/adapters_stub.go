package engine

import (
	"errors"
	"fmt"
	"log/slog"
)

// ErrAdapterDisabled indicates that a protocol adapter is disabled by feature flag.
var ErrAdapterDisabled = errors.New("protocol adapter disabled")

// ErrAdapterNotImplemented indicates that a protocol adapter is not yet implemented.
var ErrAdapterNotImplemented = errors.New("protocol adapter not implemented")

// AdapterFeatureFlags controls availability of protocol adapters that are scheduled for
// post-MVP releases. All adapters default to disabled.
type AdapterFeatureFlags struct {
	EnableWebSocket bool
	EnableGRPC      bool
	EnableMCP       bool
}

// AdapterRegistry exposes feature-flag gated access to protocol adapters.
type AdapterRegistry struct {
	flags  AdapterFeatureFlags
	logger *slog.Logger
}

// NewAdapterRegistry constructs a registry for protocol adapters with the provided flags.
func NewAdapterRegistry(flags AdapterFeatureFlags, logger *slog.Logger) *AdapterRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	return &AdapterRegistry{flags: flags, logger: logger}
}

// RequireWebSocket reports whether the WebSocket adapter is enabled and implemented.
func (r *AdapterRegistry) RequireWebSocket() error {
	if !r.flags.EnableWebSocket {
		r.logger.Debug("websocket adapter requested but disabled")
		return ErrAdapterDisabled
	}
	return fmt.Errorf("%w: websocket", ErrAdapterNotImplemented)
}

// RequireGRPC reports whether the gRPC adapter is enabled and implemented.
func (r *AdapterRegistry) RequireGRPC() error {
	if !r.flags.EnableGRPC {
		r.logger.Debug("grpc adapter requested but disabled")
		return ErrAdapterDisabled
	}
	return fmt.Errorf("%w: grpc", ErrAdapterNotImplemented)
}

// RequireMCP reports whether the MCP adapter is enabled and implemented.
func (r *AdapterRegistry) RequireMCP() error {
	if !r.flags.EnableMCP {
		r.logger.Debug("mcp adapter requested but disabled")
		return ErrAdapterDisabled
	}
	return fmt.Errorf("%w: mcp", ErrAdapterNotImplemented)
}
