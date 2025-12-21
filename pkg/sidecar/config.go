package sidecar

import "time"

// SidecarConfig represents the complete configuration for the unified sidecar
type SidecarConfig struct {
	Server   ServerConfig   `yaml:"server"`
	Policies PoliciesConfig `yaml:"policies"`
	Tools    []ToolConfig   `yaml:"tools"`
	Metrics  MetricsConfig  `yaml:"metrics"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig defines HTTP server settings
type ServerConfig struct {
	Port            int           `yaml:"port"`
	InterceptorPort int           `yaml:"interceptor_port"` // Optional, if separating ports
	MCPPort         int           `yaml:"mcp_port"`         // Optional
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	TLS             TLSConfig     `yaml:"tls"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// PoliciesConfig defines governance policy settings
type PoliciesConfig struct {
	Bundles []PolicyBundle `yaml:"bundles"`
}

// PolicyBundle defines a source of policy modules
type PolicyBundle struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"` // Local path
	URL  string `yaml:"url"`  // Remote URL (future)
	Type string `yaml:"type"` // e.g., "opa.rego"
}

// ToolConfig defines a tool available for execution
type ToolConfig struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Command     []string          `yaml:"command"`
	Env         map[string]string `yaml:"env"`
	Runtime     RuntimeConfig     `yaml:"runtime"`
}

// RuntimeConfig defines the execution environment for a tool
type RuntimeConfig struct {
	Type    string `yaml:"type"`    // "local", "e2b"
	Timeout string `yaml:"timeout"` // Parsed as duration
	Sandbox string `yaml:"sandbox"` // For E2B
}

// MetricsConfig defines observability settings
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// LoggingConfig defines logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
	Format string `yaml:"format"` // "json", "text"
	Redact bool   `yaml:"redact"` // Redact secrets
}
