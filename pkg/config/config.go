// Package config provides configuration structures and loading logic for the proxy.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the global configuration for the proxy.
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Redis        RedisConfig        `yaml:"redis"`
	Telemetry    TelemetryConfig    `yaml:"telemetry"`
	ControlPlane ControlPlaneConfig `yaml:"control_plane"`
	Pipeline     PipelineConfig     `yaml:"pipeline"`
	Logging      LoggingConfig      `yaml:"logging"`
}

// ServerConfig holds configuration for the HTTP servers.
type ServerConfig struct {
	AdminAddress string `yaml:"admin_address"`
	DataAddress  string `yaml:"data_address"`
}

// RedisConfig holds configuration for Redis connection.
type RedisConfig struct {
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
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

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if val := os.Getenv("PROXY_ADMIN_ADDR"); val != "" {
		cfg.Server.AdminAddress = val
	}
	if val := os.Getenv("PROXY_DATA_ADDR"); val != "" {
		cfg.Server.DataAddress = val
	}

	if val := os.Getenv("PROXY_REDIS_ADDR"); val != "" {
		cfg.Redis.Address = val
	}
	if val := os.Getenv("PROXY_REDIS_PASSWORD"); val != "" {
		cfg.Redis.Password = val
	}
	// Note: Redis DB override is skipped for simplicity unless needed, parsing int required.

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
}
