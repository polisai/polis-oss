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
		// Generate random initial configuration
		initialConfig := generateRandomConfig(rt)
		
		// Generate random new configuration
		newConfig := generateRandomConfig(rt)
		
		// Create temporary config file
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "config.yaml")
		
		// Write initial config
		writeConfigToFile(rt, configPath, initialConfig)
		
		// Create bridge with initial config
		// Note: Bridge constructor applies defaults, so we need to capture the actual initial state
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
			// If reload succeeded, configuration should be fully updated
			// But we need to account for defaults that might be applied by validation
			expectedConfig := applyValidationDefaults(newConfig)
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

// generateRandomConfig creates a random but valid bridge configuration
func generateRandomConfig(rt *rapid.T) *BridgeConfig {
	config := &BridgeConfig{
		ListenAddr:      rapid.StringMatching(`:[0-9]{4,5}`).Draw(rt, "listen_addr"),
		Command:         rapid.SliceOf(rapid.String()).Draw(rt, "command"),
		WorkDir:         rapid.String().Draw(rt, "work_dir"),
		Env:             rapid.SliceOf(rapid.String()).Draw(rt, "env"),
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
	
	// Generate gateway config
	if rapid.Bool().Draw(rt, "has_gateway_config") {
		config.Gateway = &GatewayConfig{
			Enabled: rapid.Bool().Draw(rt, "gateway_enabled"),
			URL:     rapid.StringMatching(`https?://[a-zA-Z0-9.-]+:[0-9]+`).Draw(rt, "gateway_url"),
			AgentID: rapid.String().Draw(rt, "agent_id"),
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
				Endpoint:    rapid.StringMatching(`https?://[a-zA-Z0-9.-]+:[0-9]+`).Draw(rt, "tracing_endpoint"),
				ServiceName: rapid.String().Draw(rt, "service_name"),
			}
		}
	}
	
	return config
}

// applyValidationDefaults applies the same defaults that the validation code applies
func applyValidationDefaults(config *BridgeConfig) *BridgeConfig {
	// Create a deep copy to avoid modifying the original
	result := *config
	
	// Deep copy session config if present
	if config.Session != nil {
		sessionCopy := *config.Session
		result.Session = &sessionCopy
	}
	
	// Deep copy metrics config if present
	if config.Metrics != nil {
		metricsCopy := *config.Metrics
		result.Metrics = &metricsCopy
		
		// Deep copy tracing config if present
		if config.Metrics.Tracing != nil {
			tracingCopy := *config.Metrics.Tracing
			result.Metrics.Tracing = &tracingCopy
		}
	}
	
	// The validation code starts with DefaultBridgeConfig() and then applies YAML overrides
	// So we need to start with defaults and then apply the input config on top
	
	// Start with default config (this is what loadAndValidateConfig does)
	defaultConfig := DefaultBridgeConfig()
	
	// Apply the input config values on top of defaults
	// This simulates what yaml.Unmarshal does when unmarshaling into defaultConfig
	if config.ListenAddr != "" {
		result.ListenAddr = config.ListenAddr
	} else {
		result.ListenAddr = defaultConfig.ListenAddr
	}
	
	if len(config.Command) > 0 {
		result.Command = config.Command
	} else {
		result.Command = defaultConfig.Command
	}
	
	if config.WorkDir != "" {
		result.WorkDir = config.WorkDir
	} else {
		result.WorkDir = defaultConfig.WorkDir
	}
	
	if len(config.Env) > 0 {
		result.Env = config.Env
	} else {
		result.Env = defaultConfig.Env
	}
	
	if config.ShutdownTimeout != 0 {
		result.ShutdownTimeout = config.ShutdownTimeout
	} else {
		result.ShutdownTimeout = defaultConfig.ShutdownTimeout
	}
	
	if config.BufferSize != 0 {
		result.BufferSize = config.BufferSize
	} else {
		result.BufferSize = defaultConfig.BufferSize
	}
	
	// Handle session config
	if config.Session != nil {
		result.Session = config.Session
	} else {
		result.Session = defaultConfig.Session
	}
	
	// Handle metrics config
	if config.Metrics != nil {
		result.Metrics = config.Metrics
	} else {
		result.Metrics = defaultConfig.Metrics
	}
	
	// Handle gateway config
	if config.Gateway != nil {
		result.Gateway = config.Gateway
	} else {
		result.Gateway = defaultConfig.Gateway
	}
	
	// Apply validation defaults (this is what validateConfiguration does)
	if result.Metrics != nil && result.Metrics.Enabled {
		if result.Metrics.Path == "" {
			result.Metrics.Path = "/metrics"
		}
		
		if result.Metrics.Tracing != nil && result.Metrics.Tracing.Enabled {
			if result.Metrics.Tracing.ServiceName == "" {
				result.Metrics.Tracing.ServiceName = "polis-bridge"
			}
		}
	}
	
	return &result
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