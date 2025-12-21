package sidecar

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigLoader_Load(t *testing.T) {
	// Create temp config
	content := `
server:
  port: 8090
tools:
  - name: test-tool
    command: ["echo", "hello"]
    env:
      KEY: ${TEST_ENV_VAR}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	// Set env var
	os.Setenv("TEST_ENV_VAR", "expanded_value")
	defer os.Unsetenv("TEST_ENV_VAR")

	loader, err := NewConfigLoader(tmpFile)
	require.NoError(t, err)

	config, err := loader.Load()
	require.NoError(t, err)

	assert.Equal(t, 8090, config.Server.Port)
	require.Len(t, config.Tools, 1)
	assert.Equal(t, "expanded_value", config.Tools[0].Env["KEY"])
}

func TestConfigLoader_Watch(t *testing.T) {
	// Skip on CI or non-local if fsnotify is flaky? usually fine.

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")

	// Initial content
	initial := `
server:
  port: 8090
`
	err := os.WriteFile(tmpFile, []byte(initial), 0644)
	require.NoError(t, err)

	loader, err := NewConfigLoader(tmpFile)
	require.NoError(t, err)

	_, err = loader.Load()
	require.NoError(t, err)

	updated := make(chan *SidecarConfig, 1)
	err = loader.Watch(func(c *SidecarConfig) {
		updated <- c
	})
	require.NoError(t, err)
	defer loader.Close()

	// Update file
	newContent := `
server:
  port: 9090
`
	// Wait a bit for watcher to be ready (debounce issues sometimes)
	time.Sleep(50 * time.Millisecond)

	err = os.WriteFile(tmpFile, []byte(newContent), 0644)
	require.NoError(t, err)

	select {
	case cfg := <-updated:
		assert.Equal(t, 9090, cfg.Server.Port)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for config update")
	}
}

func TestConfigLoader_ValidationFailure(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(tmpFile, []byte("server: { port: 8090 }"), 0644)
	require.NoError(t, err)

	loader, err := NewConfigLoader(tmpFile)
	require.NoError(t, err)

	_, err = loader.Load()
	require.NoError(t, err)

	// Watch
	updated := make(chan *SidecarConfig, 1)
	loader.Watch(func(c *SidecarConfig) {
		updated <- c
	})
	defer loader.Close()

	// Write invalid YAML
	err = os.WriteFile(tmpFile, []byte("server: [ invalid yaml"), 0644)
	require.NoError(t, err)

	select {
	case <-updated:
		t.Fatal("Should not have received update for invalid config")
	case <-time.After(500 * time.Millisecond):
		// Success: no update
	}

	// Verify current config is still old valid one
	current := loader.Current()
	assert.Equal(t, 8090, current.Server.Port)
}

// Assuming we want Property tests?
// Rapid is great, but creating valid/invalid YAML randomly is tricky.
// We can property test the ExpandEnv logic if we isolated it?
// Or test that any valid YAML structure parses correctly.
// For now, unit tests cover the main requirements (env expansion, hot reload, error handling).
