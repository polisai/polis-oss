package bridge

import (
	"time"
)

// BridgeConfig holds the configuration for the bridge server
type BridgeConfig struct {
	// ListenAddr is the address to listen on (e.g., ":8090")
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`

	// Command is the command and arguments to execute
	Command []string `yaml:"command" json:"command"`

	// WorkDir is the working directory for the child process
	WorkDir string `yaml:"work_dir" json:"work_dir"`

	// Env contains environment variables for the child process
	Env []string `yaml:"env" json:"env"`

	// ShutdownTimeout is how long to wait for graceful shutdown
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" json:"shutdown_timeout"`

	// BufferSize is the size of the event buffer for reconnection
	BufferSize int `yaml:"buffer_size" json:"buffer_size"`

	// Gateway configuration for connecting to Polis
	Gateway *GatewayConfig `yaml:"gateway,omitempty" json:"gateway,omitempty"`

	// Session configuration
	Session *SessionConfig `yaml:"session,omitempty" json:"session,omitempty"`

	// Metrics configuration
	Metrics *MetricsConfig `yaml:"metrics,omitempty" json:"metrics,omitempty"`

	// Auth configuration
	Auth *AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// AuthConfig holds authentication and security configuration
type AuthConfig struct {
	// EnforceAgentID determines if the X-Agent-ID header is strictly required
	EnforceAgentID bool `yaml:"enforce_agent_id" json:"enforce_agent_id"`

	// DefaultAgentID is the agent ID to use if none is provided and strict mode is off
	DefaultAgentID string `yaml:"default_agent_id" json:"default_agent_id"`
}

// GatewayConfig holds configuration for connecting to the Polis gateway
type GatewayConfig struct {
	// Enabled determines if gateway integration is active
	Enabled bool `yaml:"enabled" json:"enabled"`

	// URL is the Polis gateway endpoint
	URL string `yaml:"url" json:"url"`

	// AgentID is the identifier for this bridge instance
	AgentID string `yaml:"agent_id" json:"agent_id"`
}

// SessionConfig holds session management configuration
type SessionConfig struct {
	// BufferSize is the number of events to buffer per session
	BufferSize int `yaml:"buffer_size" json:"buffer_size"`

	// BufferDuration is how long to keep events in the buffer
	BufferDuration time.Duration `yaml:"buffer_duration" json:"buffer_duration"`

	// SessionTimeout is how long to keep inactive sessions
	SessionTimeout time.Duration `yaml:"session_timeout" json:"session_timeout"`
}

// MetricsConfig holds metrics and observability configuration
type MetricsConfig struct {
	// Enabled determines if metrics collection is active
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Path is the HTTP path for metrics endpoint (default: /metrics)
	Path string `yaml:"path" json:"path"`

	// Tracing configuration
	Tracing *TracingConfig `yaml:"tracing,omitempty" json:"tracing,omitempty"`
}

// TracingConfig holds OpenTelemetry tracing configuration
type TracingConfig struct {
	// Enabled determines if tracing is active
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Endpoint is the OTLP trace endpoint
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// ServiceName is the service name for traces
	ServiceName string `yaml:"service_name" json:"service_name"`
}

// DefaultBridgeConfig returns a configuration with sensible defaults
func DefaultBridgeConfig() *BridgeConfig {
	return &BridgeConfig{
		ListenAddr:      ":8090",
		Command:         []string{},
		WorkDir:         "",
		Env:             []string{},
		ShutdownTimeout: 5 * time.Second,
		BufferSize:      1000,
		Session: &SessionConfig{
			BufferSize:     1000,
			BufferDuration: 60 * time.Second,
			SessionTimeout: 300 * time.Second, // 5 minutes
		},
		Metrics: &MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
			Tracing: &TracingConfig{
				Enabled:     false,
				ServiceName: "polis-bridge",
			},
		},
		Auth: &AuthConfig{
			EnforceAgentID: false,     // Relaxed by default for OSS/Local usability
			DefaultAgentID: "default", // Default context for standard usage
		},
	}
}
