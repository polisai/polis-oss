package sidecar

import "time"

// SidecarConfig represents the complete configuration for the unified sidecar
type SidecarConfig struct {
	Server   ServerConfig   `yaml:"server"`
	Policies PoliciesConfig `yaml:"policies"`
	Pipeline PipelineConfig `yaml:"pipeline"`
	Tools    []ToolConfig   `yaml:"tools"`
	Metrics  MetricsConfig  `yaml:"metrics"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig defines HTTP server settings
type ServerConfig struct {
	Port         int                 `yaml:"port"`
	DataAddress  string              `yaml:"data_address"`  // Legacy parity
	AdminAddress string              `yaml:"admin_address"` // Legacy parity
	ReadTimeout  time.Duration       `yaml:"read_timeout"`
	WriteTimeout time.Duration       `yaml:"write_timeout"`
	TLS          *TLSConfig          `yaml:"tls,omitempty"`
	ListenParams []ListenParamConfig `yaml:"listen_params,omitempty"`
}

// ListenParamConfig defines a single listener's settings
type ListenParamConfig struct {
	Address  string     `yaml:"address"`
	Protocol string     `yaml:"protocol"` // "http", "https"
	TLS      *TLSConfig `yaml:"tls,omitempty"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	MinVersion string `yaml:"min_version,omitempty"`
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
	Pretty bool   `yaml:"pretty"` // Console pretty printing
}

// PipelineConfig defines where to load pipelines from
type PipelineConfig struct {
	File string `yaml:"file"`
	Dir  string `yaml:"dir"`
}
