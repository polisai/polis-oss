package bridge

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"pgregory.net/rapid"
)

// **Feature: mcp-expansion, Property 11: Configuration Hot Reload Atomicity**
// **Validates: Requirements 9.1, 9.2, 9.3**
func TestConfigReloadAtomicityProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate random valid configuration for initial state
		initialConfig := generateValidConfig(rt)
		
		// Generate random configuration for reload (may be valid or invalid)
		newConfig := generateRandomConfig(rt)
		
		// Create temporary config file
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "config.yaml")
		
		// Write initial config
		writeConfigToFile(rt, configPath, initialConfig)
		
		// Create bridge with initial config
		bridge := NewBridge(initialConfig, slog.Default())
		
		// Capture the actual initial configuration after defaults are applied
		bridge.mu.RLock()
		actualInitialConfig := bridge.config
		bridge.mu.RUnlock()
		
		// Create config reloader
		reloader := NewConfigReloader(bridge, configPath, slog.Default())
		
		// Write new config to file
		writeConfigToFile(rt, configPath, newConfig)
		
		// Attempt to reload configuration
		err := reloader.ReloadConfig(configPath)
		
		// Property: Either the new configuration is fully applied, or the previous configuration remains in effect
		// No partial configuration states should occur
		bridge.mu.RLock()
		currentConfig := bridge.config
		bridge.mu.RUnlock()
		
		if err != nil {
			// If reload failed, configuration should remain unchanged from the actual initial state
			assertConfigEqual(rt, actualInitialConfig, currentConfig, "Configuration should remain unchanged on reload failure")
		} else {
			// If reload succeeded, we verify atomicity by checking that:
			// 1. The config is internally consistent (not a mix of old and new)
			// 2. The config matches what we'd get from loading the file fresh
			
			// Load the config fresh to get expected state
			expectedConfig, loadErr := loadConfigFromFile(configPath)
			if loadErr != nil {
				rt.Fatalf("Failed to load config for verification: %v", loadErr)
			}
			
			assertConfigEqual(rt, expectedConfig, currentConfig, "Configuration should be fully updated on reload success")
		}
		
		// Additional atomicity check: verify session manager config consistency
		if bridge.sessions != nil {
			if sm, ok := bridge.sessions.(*DefaultSessionManager); ok {
				sm.mu.RLock()
				sessionConfig := sm.config
				sm.mu.RUnlock()
				
				// Session manager config should match bridge config
				// Note: Bridge always has a session config (defaults are applied)
				expectedSessionConfig := currentConfig.Session
				if expectedSessionConfig != nil {
					assertSessionConfigEqual(rt, expectedSessionConfig, sessionConfig, "Session config should match bridge config")
				}
			}
		}
	})
}

// generateValidConfig creates a random but always valid bridge configuration
// This is used for the initial config that must be valid
func generateValidConfig(rt *rapid.T) *BridgeConfig {
	config := &BridgeConfig{
		ListenAddr:      rapid.StringMatching(`:[0-9]{4,5}`).Draw(rt, "valid_listen_addr"),
		Command:         []string{}, // Empty command is valid
		WorkDir:         "",         // Empty workdir is valid (current directory)
		Env:             []string{}, // Empty env is valid
		ShutdownTimeout: time.Duration(rapid.Int64Range(1, 30).Draw(rt, "valid_shutdown_timeout_seconds")) * time.Second,
		BufferSize:      rapid.IntRange(100, 10000).Draw(rt, "valid_buffer_size"),
	}
	
	// Always include valid session config
	config.Session = &SessionConfig{
		BufferSize:     rapid.IntRange(100, 5000).Draw(rt, "valid_session_buffer_size"),
		BufferDuration: time.Duration(rapid.Int64Range(30, 300).Draw(rt, "valid_buffer_duration_seconds")) * time.Second,
		SessionTimeout: time.Duration(rapid.Int64Range(60, 600).Draw(rt, "valid_session_timeout_seconds")) * time.Second,
	}
	
	// Optionally include valid gateway config
	if rapid.Bool().Draw(rt, "valid_has_gateway_config") {
		config.Gateway = &GatewayConfig{
			Enabled: rapid.Bool().Draw(rt, "valid_gateway_enabled"),
			URL:     "http://localhost:8085",
			AgentID: "test-agent",
		}
	}
	
	// Optionally include valid metrics config
	if rapid.Bool().Draw(rt, "valid_has_metrics_config") {
		config.Metrics = &MetricsConfig{
			Enabled: rapid.Bool().Draw(rt, "valid_metrics_enabled"),
			Path:    "/metrics",
		}
	}
	
	return config
}

// generateRandomConfig creates a random bridge configuration that may or may not be valid
// This is used for the new config to test both success and failure cases
func generateRandomConfig(rt *rapid.T) *BridgeConfig {
	config := &BridgeConfig{
		ListenAddr:      rapid.StringMatching(`:[0-9]{4,5}`).Draw(rt, "listen_addr"),
		Command:         []string{}, // Keep command simple to avoid YAML issues
		WorkDir:         "",         // Keep workdir simple
		Env:             []string{}, // Keep env simple
		ShutdownTimeout: time.Duration(rapid.Int64Range(1, 30).Draw(rt, "shutdown_timeout_seconds")) * time.Second,
		BufferSize:      rapid.IntRange(100, 10000).Draw(rt, "buffer_size"),
	}
	
	// Generate session config
	if rapid.Bool().Draw(rt, "has_session_config") {
		config.Session = &SessionConfig{
			BufferSize:     rapid.IntRange(100, 5000).Draw(rt, "session_buffer_size"),
			BufferDuration: time.Duration(rapid.Int64Range(30, 300).Draw(rt, "buffer_duration_seconds")) * time.Second,
			SessionTimeout: time.Duration(rapid.Int64Range(60, 600).Draw(rt, "session_timeout_seconds")) * time.Second,
		}
	}
	
	// Generate gateway config - may be invalid (empty URL/AgentID when enabled)
	if rapid.Bool().Draw(rt, "has_gateway_config") {
		config.Gateway = &GatewayConfig{
			Enabled: rapid.Bool().Draw(rt, "gateway_enabled"),
			URL:     rapid.OneOf(rapid.Just(""), rapid.Just("http://localhost:8085")).Draw(rt, "gateway_url"),
			AgentID: rapid.OneOf(rapid.Just(""), rapid.Just("test-agent")).Draw(rt, "agent_id"),
		}
	}
	
	// Generate metrics config
	if rapid.Bool().Draw(rt, "has_metrics_config") {
		config.Metrics = &MetricsConfig{
			Enabled: rapid.Bool().Draw(rt, "metrics_enabled"),
			Path:    rapid.StringMatching(`/[a-zA-Z0-9/_-]*`).Draw(rt, "metrics_path"),
		}
		
		if rapid.Bool().Draw(rt, "has_tracing_config") {
			config.Metrics.Tracing = &TracingConfig{
				Enabled:     rapid.Bool().Draw(rt, "tracing_enabled"),
				Endpoint:    rapid.OneOf(rapid.Just(""), rapid.Just("http://localhost:4317")).Draw(rt, "tracing_endpoint"),
				ServiceName: rapid.OneOf(rapid.Just(""), rapid.Just("test-service")).Draw(rt, "service_name"),
			}
		}
	}
	
	return config
}

// loadConfigFromFile loads and validates a configuration from a file
// This is used to get the expected state after a successful reload
// It mirrors what loadAndValidateConfig does in the config reloader
func loadConfigFromFile(configPath string) (*BridgeConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	
	config := DefaultBridgeConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}
	
	// Apply the same validation defaults that validateConfiguration applies
	if config.Metrics != nil && config.Metrics.Enabled {
		if config.Metrics.Path == "" {
			config.Metrics.Path = "/metrics"
		}
		
		if config.Metrics.Tracing != nil && config.Metrics.Tracing.Enabled {
			if config.Metrics.Tracing.ServiceName == "" {
				config.Metrics.Tracing.ServiceName = "polis-bridge"
			}
		}
	}
	
	return config, nil
}



// writeConfigToFile writes a configuration to a YAML file
func writeConfigToFile(rt *rapid.T, path string, config *BridgeConfig) {
	data, err := yaml.Marshal(config)
	if err != nil {
		rt.Fatalf("Failed to marshal config to YAML: %v", err)
	}
	
	err = os.WriteFile(path, data, 0644)
	if err != nil {
		rt.Fatalf("Failed to write config file: %v", err)
	}
}

// assertConfigEqual compares two bridge configurations for equality
func assertConfigEqual(rt *rapid.T, expected, actual *BridgeConfig, msgAndArgs ...interface{}) {
	if expected.ListenAddr != actual.ListenAddr {
		rt.Fatalf("ListenAddr mismatch: expected %s, got %s", expected.ListenAddr, actual.ListenAddr)
	}
	if len(expected.Command) != len(actual.Command) {
		rt.Fatalf("Command length mismatch: expected %d, got %d", len(expected.Command), len(actual.Command))
	}
	for i, cmd := range expected.Command {
		if i >= len(actual.Command) || cmd != actual.Command[i] {
			rt.Fatalf("Command[%d] mismatch: expected %s, got %s", i, cmd, actual.Command[i])
		}
	}
	if expected.WorkDir != actual.WorkDir {
		rt.Fatalf("WorkDir mismatch: expected %s, got %s", expected.WorkDir, actual.WorkDir)
	}
	if len(expected.Env) != len(actual.Env) {
		rt.Fatalf("Env length mismatch: expected %d, got %d", len(expected.Env), len(actual.Env))
	}
	for i, env := range expected.Env {
		if i >= len(actual.Env) || env != actual.Env[i] {
			rt.Fatalf("Env[%d] mismatch: expected %s, got %s", i, env, actual.Env[i])
		}
	}
	if expected.ShutdownTimeout != actual.ShutdownTimeout {
		rt.Fatalf("ShutdownTimeout mismatch: expected %v, got %v", expected.ShutdownTimeout, actual.ShutdownTimeout)
	}
	if expected.BufferSize != actual.BufferSize {
		rt.Fatalf("BufferSize mismatch: expected %d, got %d", expected.BufferSize, actual.BufferSize)
	}
	
	// Compare session config
	if expected.Session == nil {
		if actual.Session != nil {
			rt.Fatalf("Session config mismatch: expected nil, got %+v", actual.Session)
		}
	} else {
		if actual.Session == nil {
			rt.Fatalf("Session config mismatch: expected %+v, got nil", expected.Session)
		}
		assertSessionConfigEqual(rt, expected.Session, actual.Session, msgAndArgs...)
	}
	
	// Compare gateway config
	if expected.Gateway == nil {
		if actual.Gateway != nil {
			rt.Fatalf("Gateway config mismatch: expected nil, got %+v", actual.Gateway)
		}
	} else {
		if actual.Gateway == nil {
			rt.Fatalf("Gateway config mismatch: expected %+v, got nil", expected.Gateway)
		}
		if expected.Gateway.Enabled != actual.Gateway.Enabled {
			rt.Fatalf("Gateway.Enabled mismatch: expected %v, got %v", expected.Gateway.Enabled, actual.Gateway.Enabled)
		}
		if expected.Gateway.URL != actual.Gateway.URL {
			rt.Fatalf("Gateway.URL mismatch: expected %s, got %s", expected.Gateway.URL, actual.Gateway.URL)
		}
		if expected.Gateway.AgentID != actual.Gateway.AgentID {
			rt.Fatalf("Gateway.AgentID mismatch: expected %s, got %s", expected.Gateway.AgentID, actual.Gateway.AgentID)
		}
	}
	
	// Compare metrics config
	if expected.Metrics == nil {
		if actual.Metrics != nil {
			rt.Fatalf("Metrics config mismatch: expected nil, got %+v", actual.Metrics)
		}
	} else {
		if actual.Metrics == nil {
			rt.Fatalf("Metrics config mismatch: expected %+v, got nil", expected.Metrics)
		}
		if expected.Metrics.Enabled != actual.Metrics.Enabled {
			rt.Fatalf("Metrics.Enabled mismatch: expected %v, got %v", expected.Metrics.Enabled, actual.Metrics.Enabled)
		}
		if expected.Metrics.Path != actual.Metrics.Path {
			rt.Fatalf("Metrics.Path mismatch: expected %s, got %s", expected.Metrics.Path, actual.Metrics.Path)
		}
		
		// Compare tracing config
		if expected.Metrics.Tracing == nil {
			if actual.Metrics.Tracing != nil {
				rt.Fatalf("Tracing config mismatch: expected nil, got %+v", actual.Metrics.Tracing)
			}
		} else {
			if actual.Metrics.Tracing == nil {
				rt.Fatalf("Tracing config mismatch: expected %+v, got nil", expected.Metrics.Tracing)
			}
			if expected.Metrics.Tracing.Enabled != actual.Metrics.Tracing.Enabled {
				rt.Fatalf("Tracing.Enabled mismatch: expected %v, got %v", expected.Metrics.Tracing.Enabled, actual.Metrics.Tracing.Enabled)
			}
			if expected.Metrics.Tracing.Endpoint != actual.Metrics.Tracing.Endpoint {
				rt.Fatalf("Tracing.Endpoint mismatch: expected %s, got %s", expected.Metrics.Tracing.Endpoint, actual.Metrics.Tracing.Endpoint)
			}
			if expected.Metrics.Tracing.ServiceName != actual.Metrics.Tracing.ServiceName {
				rt.Fatalf("Tracing.ServiceName mismatch: expected %s, got %s", expected.Metrics.Tracing.ServiceName, actual.Metrics.Tracing.ServiceName)
			}
		}
	}
}

// assertSessionConfigEqual compares two session configurations for equality
func assertSessionConfigEqual(rt *rapid.T, expected, actual *SessionConfig, msgAndArgs ...interface{}) {
	if expected.BufferSize != actual.BufferSize {
		rt.Fatalf("Session.BufferSize mismatch: expected %d, got %d", expected.BufferSize, actual.BufferSize)
	}
	if expected.BufferDuration != actual.BufferDuration {
		rt.Fatalf("Session.BufferDuration mismatch: expected %v, got %v", expected.BufferDuration, actual.BufferDuration)
	}
	if expected.SessionTimeout != actual.SessionTimeout {
		rt.Fatalf("Session.SessionTimeout mismatch: expected %v, got %v", expected.SessionTimeout, actual.SessionTimeout)
	}
}

// Unit tests for configuration reloader

func TestConfigReloaderValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *BridgeConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &BridgeConfig{
				ListenAddr:      ":8090",
				ShutdownTimeout: 5 * time.Second,
				BufferSize:      1000,
				Session: &SessionConfig{
					BufferSize:     1000,
					BufferDuration: 60 * time.Second,
					SessionTimeout: 300 * time.Second,
				},
			},
			expectError: false,
		},
		{
			name: "empty listen address",
			config: &BridgeConfig{
				ListenAddr:      "",
				ShutdownTimeout: 5 * time.Second,
				BufferSize:      1000,
			},
			expectError: true,
			errorMsg:    "listen_addr cannot be empty",
		},
		{
			name: "negative shutdown timeout",
			config: &BridgeConfig{
				ListenAddr:      ":8090",
				ShutdownTimeout: -1 * time.Second,
				BufferSize:      1000,
			},
			expectError: true,
			errorMsg:    "shutdown_timeout must be positive",
		},
		{
			name: "zero buffer size",
			config: &BridgeConfig{
				ListenAddr:      ":8090",
				ShutdownTimeout: 5 * time.Second,
				BufferSize:      0,
			},
			expectError: true,
			errorMsg:    "buffer_size must be positive",
		},
		{
			name: "invalid session config",
			config: &BridgeConfig{
				ListenAddr:      ":8090",
				ShutdownTimeout: 5 * time.Second,
				BufferSize:      1000,
				Session: &SessionConfig{
					BufferSize:     0,
					BufferDuration: 60 * time.Second,
					SessionTimeout: 300 * time.Second,
				},
			},
			expectError: true,
			errorMsg:    "session.buffer_size must be positive",
		},
		{
			name: "invalid gateway config",
			config: &BridgeConfig{
				ListenAddr:      ":8090",
				ShutdownTimeout: 5 * time.Second,
				BufferSize:      1000,
				Gateway: &GatewayConfig{
					Enabled: true,
					URL:     "",
					AgentID: "test",
				},
			},
			expectError: true,
			errorMsg:    "gateway.url cannot be empty when gateway is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bridge := NewBridge(DefaultBridgeConfig(), slog.Default())
			reloader := NewConfigReloader(bridge, "", slog.Default())

			err := reloader.validateConfiguration(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigReloaderRequiresRestart(t *testing.T) {
	reloader := &ConfigReloader{}

	tests := []struct {
		name           string
		oldConfig      *BridgeConfig
		newConfig      *BridgeConfig
		expectsRestart bool
	}{
		{
			name: "no changes",
			oldConfig: &BridgeConfig{
				ListenAddr: ":8090",
				Command:    []string{"echo", "test"},
				WorkDir:    "/tmp",
				Env:        []string{"VAR=value"},
			},
			newConfig: &BridgeConfig{
				ListenAddr: ":8090",
				Command:    []string{"echo", "test"},
				WorkDir:    "/tmp",
				Env:        []string{"VAR=value"},
			},
			expectsRestart: false,
		},
		{
			name: "listen address change",
			oldConfig: &BridgeConfig{
				ListenAddr: ":8090",
				Command:    []string{"echo", "test"},
			},
			newConfig: &BridgeConfig{
				ListenAddr: ":8091",
				Command:    []string{"echo", "test"},
			},
			expectsRestart: true,
		},
		{
			name: "command change",
			oldConfig: &BridgeConfig{
				ListenAddr: ":8090",
				Command:    []string{"echo", "test"},
			},
			newConfig: &BridgeConfig{
				ListenAddr: ":8090",
				Command:    []string{"echo", "different"},
			},
			expectsRestart: true,
		},
		{
			name: "work directory change",
			oldConfig: &BridgeConfig{
				ListenAddr: ":8090",
				WorkDir:    "/tmp",
			},
			newConfig: &BridgeConfig{
				ListenAddr: ":8090",
				WorkDir:    "/var/tmp",
			},
			expectsRestart: true,
		},
		{
			name: "environment change",
			oldConfig: &BridgeConfig{
				ListenAddr: ":8090",
				Env:        []string{"VAR=value"},
			},
			newConfig: &BridgeConfig{
				ListenAddr: ":8090",
				Env:        []string{"VAR=different"},
			},
			expectsRestart: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reloader.requiresRestart(tt.newConfig, tt.oldConfig)
			assert.Equal(t, tt.expectsRestart, result)
		})
	}
}

func TestConfigReloaderStats(t *testing.T) {
	bridge := NewBridge(DefaultBridgeConfig(), slog.Default())
	reloader := NewConfigReloader(bridge, "", slog.Default())

	// Initial stats should be zero
	count, lastReload := reloader.GetReloadStats()
	assert.Equal(t, int64(0), count)
	assert.True(t, lastReload.IsZero())

	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	
	config := DefaultBridgeConfig()
	data, err := yaml.Marshal(config)
	require.NoError(t, err)
	
	err = os.WriteFile(configPath, data, 0644)
	require.NoError(t, err)

	// Perform a reload
	err = reloader.ReloadConfig(configPath)
	assert.NoError(t, err)

	// Stats should be updated
	count, lastReload = reloader.GetReloadStats()
	assert.Equal(t, int64(1), count)
	assert.False(t, lastReload.IsZero())
}