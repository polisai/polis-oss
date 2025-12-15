// Package config provides configuration structures and loading logic for the proxy.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the global configuration for the proxy.
type Config struct {
	Server ServerConfig `yaml:"server"`

	Telemetry    TelemetryConfig    `yaml:"telemetry"`
	ControlPlane ControlPlaneConfig `yaml:"control_plane"`
	Pipeline     PipelineConfig     `yaml:"pipeline"`
	Logging      LoggingConfig      `yaml:"logging"`
}

// ServerConfig holds configuration for the HTTP servers.
type ServerConfig struct {
	AdminAddress string              `yaml:"admin_address"`
	DataAddress  string              `yaml:"data_address"`
	TLS          *TLSConfig          `yaml:"tls,omitempty"`
	ListenParams []ListenParamConfig `yaml:"listen_params,omitempty"`
}

// TelemetryConfig holds configuration for OpenTelemetry.
type TelemetryConfig struct {
	OTLPEndpoint string `yaml:"otlp_endpoint"`
	Insecure     bool   `yaml:"insecure"`
}

// ControlPlaneConfig holds configuration for the control plane client.
type ControlPlaneConfig struct {
	Address     string `yaml:"address"`
	MTLSEnabled bool   `yaml:"mtls_enabled"`
}

// PipelineConfig holds configuration for pipeline loading.
type PipelineConfig struct {
	File string `yaml:"file"`
	Dir  string `yaml:"dir"`
}

// LoggingConfig holds configuration for logging.
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// Load reads configuration from a file and applies environment variable overrides.
func Load(path string) (*Config, error) {
	cfg := &Config{
		// Defaults
		Server: ServerConfig{
			AdminAddress: ":19090",
			DataAddress:  ":8090",
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}

	if path != "" {
		//nolint:gosec // Config file path is controlled by admin/operator
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
		}
	}

	applyEnvOverrides(cfg)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if val := os.Getenv("PROXY_ADMIN_ADDR"); val != "" {
		cfg.Server.AdminAddress = val
	}
	if val := os.Getenv("PROXY_DATA_ADDR"); val != "" {
		cfg.Server.DataAddress = val
	}

	if val := os.Getenv("PROXY_OTLP_ENDPOINT"); val != "" {
		cfg.Telemetry.OTLPEndpoint = val
	}
	if val := os.Getenv("PROXY_OTLP_INSECURE"); val == "true" {
		cfg.Telemetry.Insecure = true
	}

	if val := os.Getenv("PROXY_CONTROL_PLANE"); val != "" {
		cfg.ControlPlane.Address = val
	}
	if val := os.Getenv("MTLS_ENABLED"); val == "true" {
		cfg.ControlPlane.MTLSEnabled = true
	}

	if val := os.Getenv("PROXY_PIPELINE_FILE"); val != "" {
		cfg.Pipeline.File = val
	}
	if val := os.Getenv("PROXY_PIPELINE_DIR"); val != "" {
		cfg.Pipeline.Dir = val
	}

	if val := os.Getenv("PROXY_LOG_LEVEL"); val != "" {
		cfg.Logging.Level = val
	}

	// TLS environment overrides
	if val := os.Getenv("PROXY_TLS_ENABLED"); val == "true" {
		if cfg.Server.TLS == nil {
			cfg.Server.TLS = &TLSConfig{}
		}
		cfg.Server.TLS.Enabled = true
	}
	if val := os.Getenv("PROXY_TLS_CERT_FILE"); val != "" {
		if cfg.Server.TLS == nil {
			cfg.Server.TLS = &TLSConfig{}
		}
		cfg.Server.TLS.CertFile = val
	}
	if val := os.Getenv("PROXY_TLS_KEY_FILE"); val != "" {
		if cfg.Server.TLS == nil {
			cfg.Server.TLS = &TLSConfig{}
		}
		cfg.Server.TLS.KeyFile = val
	}
	if val := os.Getenv("PROXY_TLS_MIN_VERSION"); val != "" {
		if cfg.Server.TLS == nil {
			cfg.Server.TLS = &TLSConfig{}
		}
		cfg.Server.TLS.MinVersion = val
	}

	// Support for multiple listeners via environment variables
	if val := os.Getenv("PROXY_LISTEN_PARAMS"); val != "" {
		// Parse comma-separated list of address:protocol pairs
		// Format: "address1:protocol1,address2:protocol2"
		// Example: ":8080:http,:8443:https"
		pairs := strings.Split(val, ",")
		cfg.Server.ListenParams = make([]ListenParamConfig, 0, len(pairs))

		for _, pair := range pairs {
			parts := strings.Split(strings.TrimSpace(pair), ":")
			if len(parts) >= 3 { // :port:protocol
				address := ":" + parts[1]
				protocol := parts[2]

				param := ListenParamConfig{
					Address:  address,
					Protocol: protocol,
				}

				// If HTTPS, create basic TLS config from environment
				if protocol == "https" && cfg.Server.TLS != nil {
					param.TLS = &TLSConfig{
						Enabled:    cfg.Server.TLS.Enabled,
						CertFile:   cfg.Server.TLS.CertFile,
						KeyFile:    cfg.Server.TLS.KeyFile,
						MinVersion: cfg.Server.TLS.MinVersion,
					}
				}

				cfg.Server.ListenParams = append(cfg.Server.ListenParams, param)
			}
		}
	}
}

// Validate performs comprehensive validation of the entire configuration
func (c *Config) Validate() error {
	if err := c.Server.Validate(); err != nil {
		return fmt.Errorf("server configuration: %w", err)
	}

	if err := c.Telemetry.Validate(); err != nil {
		return fmt.Errorf("telemetry configuration: %w", err)
	}

	if err := c.ControlPlane.Validate(); err != nil {
		return fmt.Errorf("control plane configuration: %w", err)
	}

	if err := c.Pipeline.Validate(); err != nil {
		return fmt.Errorf("pipeline configuration: %w", err)
	}

	if err := c.Logging.Validate(); err != nil {
		return fmt.Errorf("logging configuration: %w", err)
	}

	return nil
}

// Validate performs validation of server configuration
func (c *ServerConfig) Validate() error {
	// Set defaults if not provided
	if strings.TrimSpace(c.AdminAddress) == "" {
		c.AdminAddress = ":19090"
	}

	if strings.TrimSpace(c.DataAddress) == "" {
		c.DataAddress = ":8090"
	}

	// Validate TLS configuration if present
	if c.TLS != nil {
		if err := c.TLS.Validate(); err != nil {
			return fmt.Errorf("TLS configuration: %w", err)
		}
	}

	// Validate listen parameters if present
	for i, param := range c.ListenParams {
		if err := param.Validate(); err != nil {
			return fmt.Errorf("listen parameter %d: %w", i, err)
		}
	}

	// Validate that listen parameters don't conflict with legacy addresses
	if len(c.ListenParams) > 0 {
		addressMap := make(map[string]bool)

		for i, param := range c.ListenParams {
			// Check for duplicate addresses
			if addressMap[param.Address] {
				return fmt.Errorf("duplicate listen parameter address %q", param.Address)
			}
			addressMap[param.Address] = true

			// Check conflicts with admin address
			if param.Address == c.AdminAddress {
				return fmt.Errorf("listen parameter %d address %q conflicts with admin_address", i, param.Address)
			}

			// Check conflicts with legacy data address
			if param.Address == c.DataAddress {
				return fmt.Errorf("listen parameter %d address %q conflicts with data_address", i, param.Address)
			}
		}

		// Validate TLS configuration consistency
		if err := c.validateTLSConsistency(); err != nil {
			return fmt.Errorf("TLS configuration consistency: %w", err)
		}
	}

	return nil
}

// validateTLSConsistency ensures TLS configuration is consistent across server and listen parameters
func (c *ServerConfig) validateTLSConsistency() error {
	hasServerTLS := c.TLS != nil && c.TLS.Enabled
	hasHTTPSListeners := false

	// Check if any listen parameters use HTTPS
	for _, param := range c.ListenParams {
		if param.Protocol == "https" {
			hasHTTPSListeners = true

			// HTTPS listeners must have TLS configuration
			if param.TLS == nil || !param.TLS.Enabled {
				return fmt.Errorf("HTTPS listener at %q requires TLS configuration", param.Address)
			}
		}
	}

	// If server-level TLS is enabled but no HTTPS listeners are configured,
	// this is valid (TLS server will use default port)
	if hasServerTLS && !hasHTTPSListeners {
		// This is acceptable - server-level TLS will use default HTTPS port
	}

	// If HTTPS listeners are configured but no server-level TLS,
	// ensure each HTTPS listener has its own TLS config
	if hasHTTPSListeners && !hasServerTLS {
		for _, param := range c.ListenParams {
			if param.Protocol == "https" && (param.TLS == nil || !param.TLS.Enabled) {
				return fmt.Errorf("HTTPS listener at %q requires TLS configuration when server-level TLS is not enabled", param.Address)
			}
		}
	}

	return nil
}

// Validate performs validation of telemetry configuration
func (c *TelemetryConfig) Validate() error {
	// Basic validation - OTLP endpoint format could be validated more strictly
	return nil
}

// Validate performs validation of control plane configuration
func (c *ControlPlaneConfig) Validate() error {
	// Basic validation - address format could be validated more strictly
	return nil
}

// Validate performs validation of pipeline configuration
func (c *PipelineConfig) Validate() error {
	// Pipeline configuration is optional - pipelines can be provided inline in the config
	// or loaded from files/directories. If neither file nor dir is specified,
	// the system will look for inline pipeline configuration.
	return nil
}

// Validate performs validation of logging configuration
func (c *LoggingConfig) Validate() error {
	// Set default log level if not provided
	if strings.TrimSpace(c.Level) == "" {
		c.Level = "info"
	}

	level := strings.TrimSpace(strings.ToLower(c.Level))
	switch level {
	case "debug", "info", "warn", "error":
		c.Level = level // Normalize to lowercase
		return nil
	default:
		return fmt.Errorf("invalid log level %q, supported levels: debug, info, warn, error", c.Level)
	}
}
