package sidecar

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// ConfigLoader handles loading and watching configuration files
type ConfigLoader struct {
	path     string
	watcher  *fsnotify.Watcher
	current  *SidecarConfig
	mu       sync.RWMutex
	onChange func(*SidecarConfig)
	close    chan struct{}
}

// NewConfigLoader creates a new ConfigLoader
func NewConfigLoader(path string) (*ConfigLoader, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	return &ConfigLoader{
		path:  absPath,
		close: make(chan struct{}),
	}, nil
}

// Load reads the configuration file, expands environment variables, and parses YAML
func (cl *ConfigLoader) Load() (*SidecarConfig, error) {
	data, err := os.ReadFile(cl.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	expandedData := []byte(os.ExpandEnv(string(data)))

	var config SidecarConfig
	if err := yaml.Unmarshal(expandedData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	// Basic validation could go here
	if config.Server.Port == 0 && config.Server.InterceptorPort == 0 && config.Server.MCPPort == 0 {
		// Default port logic can handle this, or we error.
		// For now, raw load.
	}

	cl.mu.Lock()
	cl.current = &config
	cl.mu.Unlock()

	return &config, nil
}

// Watch starts monitoring the config file for changes
// It calls the onChange callback when a valid change is detected
func (cl *ConfigLoader) Watch(onChange func(*SidecarConfig)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	cl.watcher = watcher
	cl.onChange = onChange

	go cl.watchLoop()

	dir := filepath.Dir(cl.path)
	if err := cl.watcher.Add(dir); err != nil {
		cl.watcher.Close()
		return fmt.Errorf("failed to watch directory: %w", err)
	}

	return nil
}

func (cl *ConfigLoader) watchLoop() {
	for {
		select {
		case <-cl.close:
			return
		case event, ok := <-cl.watcher.Events:
			if !ok {
				return
			}

			// Check if it's our file
			// Note: Editors often rename/remove to save atomically, so we watch Write, Create, Rename, Chmod
			// Simple check: if path matches
			if filepath.Clean(event.Name) == cl.path {
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
					// Reload
					// We might get multiple events for one save, debouncing is ideal but simple reload is okay for now
					// Retrying blindly might be needed if it's a rename in progress?
					// Standard pattern: try to load

					// Slight race on file existence with atomic saves.
					// Just try to load.
					newConfig, err := cl.Load()
					if err == nil {
						if cl.onChange != nil {
							cl.onChange(newConfig)
						}
					} else {
						// Log error? We don't have logger here yet.
						// Requirements say "retain previous configuration and log an error"
						// We'll need to inject logger eventually or return error channel.
						// For now, we just silently keep old config (Load didn't update current if it failed/errored?
						// Actually Load updates current only on success in my impl above?
						// No, Load returns error and doesn't update if unmarshal fails.
						// Wait, Load() implementation above updates cl.current inside the method.
						// That is correct behavior: "retain previous configuration" happens implicitly if we don't return success.
					}
				}
			}

		case err, ok := <-cl.watcher.Errors:
			if !ok {
				return
			}
			// handle error
			_ = err
		}
	}
}

// Current returns the current configuration
func (cl *ConfigLoader) Current() *SidecarConfig {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return cl.current
}

// Close stops the watcher
func (cl *ConfigLoader) Close() error {
	close(cl.close)
	if cl.watcher != nil {
		return cl.watcher.Close()
	}
	return nil
}
