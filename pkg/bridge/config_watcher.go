package bridge

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ConfigWatcher watches configuration files for changes and triggers reload callbacks
type ConfigWatcher struct {
	configPath   string
	watcher      *fsnotify.Watcher
	reloadFunc   func(string) error
	logger       *slog.Logger
	mu           sync.RWMutex
	running      bool
	stopCh       chan struct{}
	debounceTime time.Duration
}

// NewConfigWatcher creates a new configuration file watcher
func NewConfigWatcher(configPath string, reloadFunc func(string) error, logger *slog.Logger) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &ConfigWatcher{
		configPath:   configPath,
		watcher:      watcher,
		reloadFunc:   reloadFunc,
		logger:       logger,
		stopCh:       make(chan struct{}),
		debounceTime: 1 * time.Second, // Debounce multiple rapid changes
	}, nil
}

// Start begins watching the configuration file for changes
func (cw *ConfigWatcher) Start(ctx context.Context) error {
	cw.mu.Lock()
	if cw.running {
		cw.mu.Unlock()
		return nil
	}
	cw.running = true
	cw.mu.Unlock()

	// Add the config file directory to the watcher
	// We watch the directory because some editors create temp files and rename them
	configDir := filepath.Dir(cw.configPath)
	if err := cw.watcher.Add(configDir); err != nil {
		cw.mu.Lock()
		cw.running = false
		cw.mu.Unlock()
		return err
	}

	cw.logger.Info("Config watcher started", "config_path", cw.configPath)

	go cw.watchLoop(ctx)
	return nil
}

// Stop stops the configuration file watcher
func (cw *ConfigWatcher) Stop() error {
	cw.mu.Lock()
	if !cw.running {
		cw.mu.Unlock()
		return nil
	}
	cw.running = false
	cw.mu.Unlock()

	close(cw.stopCh)
	return cw.watcher.Close()
}

// watchLoop is the main event loop for file watching
func (cw *ConfigWatcher) watchLoop(ctx context.Context) {
	var debounceTimer *time.Timer
	var pendingReload bool

	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()

	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}

			// Only process events for our specific config file
			if !cw.isConfigFileEvent(event) {
				continue
			}

			cw.logger.Debug("Config file event detected", 
				"event", event.Op.String(), 
				"file", event.Name)

			// Check if this is a modification or creation event
			if event.Op&fsnotify.Write == fsnotify.Write || 
			   event.Op&fsnotify.Create == fsnotify.Create {
				
				// Debounce rapid changes
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				
				pendingReload = true
				debounceTimer = time.AfterFunc(cw.debounceTime, func() {
					if pendingReload {
						cw.triggerReload()
						pendingReload = false
					}
				})
			}

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			cw.logger.Error("Config watcher error", "error", err)

		case <-cw.stopCh:
			cw.logger.Info("Config watcher stopped")
			return

		case <-ctx.Done():
			cw.logger.Info("Config watcher context cancelled")
			return
		}
	}
}

// isConfigFileEvent checks if the event is for our configuration file
func (cw *ConfigWatcher) isConfigFileEvent(event fsnotify.Event) bool {
	// Get absolute paths for comparison
	eventPath, err := filepath.Abs(event.Name)
	if err != nil {
		return false
	}
	
	configPath, err := filepath.Abs(cw.configPath)
	if err != nil {
		return false
	}
	
	return eventPath == configPath
}

// triggerReload triggers the configuration reload callback
func (cw *ConfigWatcher) triggerReload() {
	cw.logger.Info("Config file changed, triggering reload", "config_path", cw.configPath)
	
	start := time.Now()
	if err := cw.reloadFunc(cw.configPath); err != nil {
		cw.logger.Error("Config reload failed", 
			"error", err, 
			"duration", time.Since(start))
	} else {
		cw.logger.Info("Config reload completed successfully", 
			"duration", time.Since(start))
	}
}

// IsRunning returns whether the watcher is currently running
func (cw *ConfigWatcher) IsRunning() bool {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.running
}