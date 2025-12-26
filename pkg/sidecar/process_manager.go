package sidecar

import (
	"context"
	"time"
)

// RuntimeType defines the execution provider type
type RuntimeType string

const (
	RuntimeLocal RuntimeType = "local"
	RuntimeE2B   RuntimeType = "e2b"
)

// ProcessConfig holds process startup configuration
type ProcessConfig struct {
	Command []string
	WorkDir string
	Env     []string
	Timeout time.Duration
}

// ProcessManager handles process lifecycle for tool execution
type ProcessManager interface {
	// Start spawns the process/sandbox
	Start(ctx context.Context, config ProcessConfig) error

	// Write sends data to the process stdin
	Write(data []byte) error

	// ReadLoop continuously reads stdout and calls handler
	ReadLoop(handler func([]byte)) error

	// Stop gracefully terminates the process
	Stop(timeout time.Duration) error

	// IsRunning returns true if process is active
	IsRunning() bool

	// ExitCode returns the exit code (valid after exit)
	ExitCode() int

	// Type returns the runtime type
	Type() RuntimeType
}
