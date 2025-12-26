package sidecar

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalProcessManager_Lifecycle(t *testing.T) {
	cmd := []string{"cmd", "/c", "echo hello"}
	// Simple cross-platform check (not perfect but works for common shells)
	if _, err := os.Stat("/bin/sh"); err == nil {
		cmd = []string{"echo", "hello"}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pm := NewLocalProcessManager(logger, &mockMetrics{}, &mockTracer{})

	ctx := context.Background()
	config := ProcessConfig{
		Command: cmd,
	}

	// Test Start
	err := pm.Start(ctx, config)
	require.NoError(t, err)
	assert.True(t, pm.IsRunning())

	// Test ReadLoop (Wait for output)
	done := make(chan struct{})
	var output []byte
	go func() {
		err := pm.ReadLoop(func(data []byte) {
			output = append(output, data...)
		})
		// ReadLoop returns nil on EOF (process exit)
		assert.NoError(t, err)
		close(done)
	}()

	// Wait for completion (echo is fast)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for process output")
	}

	assert.False(t, pm.IsRunning())
	assert.Contains(t, string(output), "hello")
	assert.Equal(t, 0, pm.ExitCode())
}

func TestLocalProcessManager_Stop(t *testing.T) {
	// Use a long running command
	cmd := []string{"cmd", "/c", "timeout 10"}
	if _, err := os.Stat("/bin/sh"); err == nil {
		cmd = []string{"sleep", "10"}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pm := NewLocalProcessManager(logger, &mockMetrics{}, &mockTracer{})

	err := pm.Start(context.Background(), ProcessConfig{Command: cmd})
	require.NoError(t, err)
	assert.True(t, pm.IsRunning())

	// Stop it
	err = pm.Stop(1 * time.Second)
	require.NoError(t, err)
	assert.False(t, pm.IsRunning())
}

func TestLocalProcessManager_Write(t *testing.T) {
	// Use a command that reads stdin
	cmd := []string{"findstr", "foo"}
	if _, err := os.Stat("/bin/grep"); err == nil || os.PathSeparator == '/' {
		cmd = []string{"grep", "foo"}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pm := NewLocalProcessManager(logger, &mockMetrics{}, &mockTracer{})

	err := pm.Start(context.Background(), ProcessConfig{Command: cmd})
	require.NoError(t, err)

	// Start reading
	outputCh := make(chan string)
	go func() {
		pm.ReadLoop(func(data []byte) {
			outputCh <- string(data)
		})
	}()

	// Write Input
	err = pm.Write([]byte("bar\nfoo\nbaz\n"))
	assert.NoError(t, err)

	// Close stdin to finish grep/findstr via Stop (or close stdin explicitly if exposed? Stop does it)
	// We wait a bit to ensure grep processes the input
	time.Sleep(500 * time.Millisecond)
	pm.Stop(1 * time.Second)

	// Collect output
	var result string
	timeout := time.After(2 * time.Second)
Loop:
	for {
		select {
		case chunk := <-outputCh:
			result += chunk
		case <-timeout:
			break Loop
		}
		if strings.Contains(result, "foo") {
			break
		}
	}

	assert.Contains(t, result, "foo")
	assert.NotContains(t, result, "bar")
}
