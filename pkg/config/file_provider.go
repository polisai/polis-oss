package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/polisai/polis-oss/pkg/domain"
	"gopkg.in/yaml.v3"
)

// FileConfigProvider implements domain.ConfigService using a local file.
type FileConfigProvider struct {
	path        string
	mu          sync.RWMutex
	snapshot    domain.Snapshot
	subscribers []chan domain.Snapshot
	watcher     *fsnotify.Watcher
	cancel      context.CancelFunc
}

// NewFileConfigProvider creates a new provider watching the specified file.
func NewFileConfigProvider(path string) (*FileConfigProvider, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &FileConfigProvider{
		path:    absPath,
		watcher: watcher,
		cancel:  cancel,
	}

	// Initial load
	if err := p.load(); err != nil {
		// If file doesn't exist yet, we start with empty config but still watch
		log.Printf("Warning: initial config load failed: %v", err)
	}

	// Start watching
	if err := watcher.Add(filepath.Dir(absPath)); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("failed to watch directory: %w", err)
	}

	go p.watchLoop(ctx)

	return p, nil
}

// CurrentSnapshot returns the current configuration.
func (p *FileConfigProvider) CurrentSnapshot() domain.Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.snapshot
}

// UpdateSnapshot updates the configuration (not supported for file provider).
func (p *FileConfigProvider) UpdateSnapshot(_ domain.Snapshot) error {
	return fmt.Errorf("UpdateSnapshot not supported by FileConfigProvider (edit the file instead)")
}

// Subscribe returns a channel that receives configuration updates.
func (p *FileConfigProvider) Subscribe() <-chan domain.Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch := make(chan domain.Snapshot, 1)
	p.subscribers = append(p.subscribers, ch)
	// Send current state immediately
	ch <- p.snapshot
	return ch
}

// GetConfig returns the current configuration parsed from the file
func (p *FileConfigProvider) GetConfig() (*Config, error) {
	// #nosec G304 -- File path is configured at startup
	data, err := os.ReadFile(p.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		if jsonErr := json.Unmarshal(data, &cfg); jsonErr != nil {
			return nil, fmt.Errorf("failed to parse config file: %v", err)
		}
	}

	// Apply environment variable overrides
	applyEnvOverrides(&cfg)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// Close stops the watcher and cleans up resources.
func (p *FileConfigProvider) Close() error {
	p.cancel()
	return p.watcher.Close()
}

func (p *FileConfigProvider) watchLoop(ctx context.Context) {
	var debounceTimer *time.Timer
	debounceDuration := 100 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-p.watcher.Events:
			if !ok {
				return
			}

			// We only care about our specific file
			// Note: fsnotify events might use different path separators or relative paths
			cleanEventName := filepath.Clean(event.Name)
			if cleanEventName != p.path {
				continue
			}

			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Chmod) {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounceDuration, func() {
					if err := p.load(); err != nil {
						log.Printf("Error reloading config: %v", err)
					} else {
						log.Printf("Configuration reloaded from %s", p.path)
					}
				})
			}
		case err, ok := <-p.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (p *FileConfigProvider) load() error {
	// #nosec G304 -- File path is configured at startup
	data, err := os.ReadFile(p.path)
	if err != nil {
		return err
	}

	var snapshot Snapshot
	if err := yaml.Unmarshal(data, &snapshot); err != nil {
		if jsonErr := json.Unmarshal(data, &snapshot); jsonErr != nil {
			return fmt.Errorf("failed to parse config file: %v", err)
		}
	}

	domainSnapshot, err := snapshot.ToDomain()
	if err != nil {
		return fmt.Errorf("failed to convert to domain snapshot: %w", err)
	}

	p.mu.Lock()
	p.snapshot = domainSnapshot
	subscribers := make([]chan domain.Snapshot, len(p.subscribers))
	copy(subscribers, p.subscribers)
	p.mu.Unlock()

	// Notify subscribers
	for _, ch := range subscribers {
		select {
		case ch <- domainSnapshot:
		default:
			// Skip if channel is full (slow consumer)
		}
	}

	return nil
}
