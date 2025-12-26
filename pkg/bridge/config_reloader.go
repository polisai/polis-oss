package bridge

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigReloader handles atomic configuration reloading for the bridge
type ConfigReloader struct {
	bridge       *Bridge
	currentPath  string
	logger       *slog.Logger
	mu           sync.RWMutex
	reloadCount  int64
	lastReload   time.Time
	metrics      *Metrics
}

// NewConfigReloader creates a new configuration reloader
func NewConfigReloader(bridge *Bridge, configPath string, logger *slog.Logger) *ConfigReloader {
	if logger == nil {
		logger = slog.Default()
	}

	return &ConfigReloader{
		bridge:      bridge,
		currentPath: configPath,
		logger:      logger,
	}
}

// SetMetrics sets the metrics instance for recording reload events
func (cr *ConfigReloader) SetMetrics(metrics *Metrics) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.metrics = metrics
}

// ReloadConfig atomically reloads the configuration from the specified file
func (cr *ConfigReloader) ReloadConfig(configPath string) error {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	start := time.Now()
	cr.logger.Info("Starting configuration reload", "config_path", configPath)

	// Step 1: Load and validate new configuration
	newConfig, err := cr.loadAndValidateConfig(configPath)
	if err != nil {
		cr.logger.Error("Configuration validation failed", "error", err)
		if cr.metrics != nil {
			cr.metrics.RecordConfigReload("validation_failed")
		}
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Step 2: Get current configuration for rollback
	cr.bridge.mu.RLock()
	previousConfig := cr.bridge.config
	cr.bridge.mu.RUnlock()

	// Step 3: Apply new configuration atomically
	if err := cr.applyConfigurationAtomically(newConfig, previousConfig); err != nil {
		cr.logger.Error("Configuration application failed", "error", err)
		if cr.metrics != nil {
			cr.metrics.RecordConfigReload("application_failed")
		}
		return fmt.Errorf("configuration application failed: %w", err)
	}

	// Step 4: Update reload statistics
	cr.reloadCount++
	cr.lastReload = time.Now()
	duration := time.Since(start)

	cr.logger.Info("Configuration reload completed successfully", 
		"duration", duration,
		"reload_count", cr.reloadCount)

	if cr.metrics != nil {
		cr.metrics.RecordConfigReload("success")
	}

	return nil
}

// loadAndValidateConfig loads configuration from file and validates it
func (cr *ConfigReloader) loadAndValidateConfig(configPath string) (*BridgeConfig, error) {
	// Read configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Start with default configuration
	config := DefaultBridgeConfig()

	// Parse YAML configuration
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	// Validate configuration
	if err := cr.validateConfiguration(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// validateConfiguration performs validation checks on the configuration
func (cr *ConfigReloader) validateConfiguration(config *BridgeConfig) error {
	// Validate listen address
	if config.ListenAddr == "" {
		return fmt.Errorf("listen_addr cannot be empty")
	}

	// Validate shutdown timeout
	if config.ShutdownTimeout <= 0 {
		return fmt.Errorf("shutdown_timeout must be positive")
	}

	// Validate buffer size
	if config.BufferSize <= 0 {
		return fmt.Errorf("buffer_size must be positive")
	}

	// Validate session configuration if present
	if config.Session != nil {
		if config.Session.BufferSize <= 0 {
			return fmt.Errorf("session.buffer_size must be positive")
		}
		if config.Session.BufferDuration <= 0 {
			return fmt.Errorf("session.buffer_duration must be positive")
		}
		if config.Session.SessionTimeout <= 0 {
			return fmt.Errorf("session.session_timeout must be positive")
		}
	}

	// Validate gateway configuration if present
	if config.Gateway != nil && config.Gateway.Enabled {
		if config.Gateway.URL == "" {
			return fmt.Errorf("gateway.url cannot be empty when gateway is enabled")
		}
		if config.Gateway.AgentID == "" {
			return fmt.Errorf("gateway.agent_id cannot be empty when gateway is enabled")
		}
	}

	// Validate metrics configuration if present
	if config.Metrics != nil && config.Metrics.Enabled {
		if config.Metrics.Path == "" {
			config.Metrics.Path = "/metrics" // Set default
		}
		
		// Validate tracing configuration if present
		if config.Metrics.Tracing != nil && config.Metrics.Tracing.Enabled {
			if config.Metrics.Tracing.ServiceName == "" {
				config.Metrics.Tracing.ServiceName = "polis-bridge" // Set default
			}
		}
	}

	return nil
}

// applyConfigurationAtomically applies the new configuration atomically
func (cr *ConfigReloader) applyConfigurationAtomically(newConfig, previousConfig *BridgeConfig) error {
	// Lock the bridge for configuration update
	cr.bridge.mu.Lock()
	defer cr.bridge.mu.Unlock()

	// Apply configuration changes that can be done without restart
	cr.bridge.config = newConfig

	// Update session manager configuration if it exists
	if cr.bridge.sessions != nil {
		if sm, ok := cr.bridge.sessions.(*DefaultSessionManager); ok {
			if err := sm.UpdateConfig(newConfig.Session); err != nil {
				// Rollback configuration on failure
				cr.bridge.config = previousConfig
				return fmt.Errorf("failed to update session manager config: %w", err)
			}
		}
	}

	// Update metrics configuration if it exists
	if cr.bridge.metrics != nil && newConfig.Metrics != nil {
		// Metrics configuration changes don't require restart
		// The metrics instance will pick up new settings on next use
	}

	// Update tracing configuration if it exists
	if cr.bridge.tracing != nil && newConfig.Metrics != nil && newConfig.Metrics.Tracing != nil {
		// Tracing configuration changes may require restart of tracing
		// For now, we'll log that tracing config changed
		if previousConfig.Metrics == nil || 
		   previousConfig.Metrics.Tracing == nil ||
		   previousConfig.Metrics.Tracing.Endpoint != newConfig.Metrics.Tracing.Endpoint ||
		   previousConfig.Metrics.Tracing.ServiceName != newConfig.Metrics.Tracing.ServiceName {
			cr.logger.Warn("Tracing configuration changed - restart may be required for full effect")
		}
	}

	// Log configuration changes that require restart
	if cr.requiresRestart(newConfig, previousConfig) {
		cr.logger.Warn("Some configuration changes require bridge restart to take full effect",
			"changes", cr.getRestartRequiredChanges(newConfig, previousConfig))
	}

	return nil
}

// requiresRestart checks if configuration changes require a bridge restart
func (cr *ConfigReloader) requiresRestart(newConfig, oldConfig *BridgeConfig) bool {
	// Listen address change requires restart
	if newConfig.ListenAddr != oldConfig.ListenAddr {
		return true
	}

	// Command change requires restart
	if len(newConfig.Command) != len(oldConfig.Command) {
		return true
	}
	for i, cmd := range newConfig.Command {
		if i >= len(oldConfig.Command) || cmd != oldConfig.Command[i] {
			return true
		}
	}

	// Working directory change requires restart
	if newConfig.WorkDir != oldConfig.WorkDir {
		return true
	}

	// Environment variables change requires restart
	if len(newConfig.Env) != len(oldConfig.Env) {
		return true
	}
	for i, env := range newConfig.Env {
		if i >= len(oldConfig.Env) || env != oldConfig.Env[i] {
			return true
		}
	}

	return false
}

// getRestartRequiredChanges returns a list of changes that require restart
func (cr *ConfigReloader) getRestartRequiredChanges(newConfig, oldConfig *BridgeConfig) []string {
	var changes []string

	if newConfig.ListenAddr != oldConfig.ListenAddr {
		changes = append(changes, "listen_addr")
	}

	if len(newConfig.Command) != len(oldConfig.Command) {
		changes = append(changes, "command")
	} else {
		for i, cmd := range newConfig.Command {
			if i >= len(oldConfig.Command) || cmd != oldConfig.Command[i] {
				changes = append(changes, "command")
				break
			}
		}
	}

	if newConfig.WorkDir != oldConfig.WorkDir {
		changes = append(changes, "work_dir")
	}

	if len(newConfig.Env) != len(oldConfig.Env) {
		changes = append(changes, "env")
	} else {
		for i, env := range newConfig.Env {
			if i >= len(oldConfig.Env) || env != oldConfig.Env[i] {
				changes = append(changes, "env")
				break
			}
		}
	}

	return changes
}

// GetReloadStats returns statistics about configuration reloads
func (cr *ConfigReloader) GetReloadStats() (int64, time.Time) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.reloadCount, cr.lastReload
}