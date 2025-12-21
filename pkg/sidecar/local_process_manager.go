package sidecar

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// ProcessMetrics defines the metrics interface needed by ProcessManager
type ProcessMetrics interface {
	UpdateProcessStatus(command string, running bool)
}

// ProcessTracer defines the tracing interface needed by ProcessManager
type ProcessTracer interface {
	InjectProcessEnv(ctx context.Context, env []string) []string
}

// LocalProcessManager implements ProcessManager for local execution
type LocalProcessManager struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	done     chan struct{}
	exitCode int
	mu       sync.RWMutex
	logger   *slog.Logger
	metrics  ProcessMetrics
	tracing  ProcessTracer
	running  bool
	command  []string
}

// NewLocalProcessManager creates a new local process manager instance
func NewLocalProcessManager(logger *slog.Logger, metrics ProcessMetrics, tracing ProcessTracer) *LocalProcessManager {
	if logger == nil {
		logger = slog.Default()
	}

	return &LocalProcessManager{
		logger:   logger,
		metrics:  metrics,
		tracing:  tracing,
		exitCode: -1,
		done:     make(chan struct{}),
	}
}

// Start spawns the child process with the given configuration
func (pm *LocalProcessManager) Start(ctx context.Context, config ProcessConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.running {
		return fmt.Errorf("process is already running")
	}

	if len(config.Command) == 0 {
		return fmt.Errorf("command cannot be empty")
	}

	// Reset state for new run
	pm.done = make(chan struct{})
	pm.exitCode = -1

	// Create the command
	pm.cmd = exec.CommandContext(ctx, config.Command[0], config.Command[1:]...)

	// Set working directory if specified
	if config.WorkDir != "" {
		pm.cmd.Dir = config.WorkDir
	}

	// Set environment variables
	processEnv := config.Env
	if len(config.Env) == 0 {
		processEnv = os.Environ()
	} else {
		processEnv = append(os.Environ(), config.Env...)
	}

	// Inject trace context
	if pm.tracing != nil {
		processEnv = pm.tracing.InjectProcessEnv(ctx, processEnv)
	}

	pm.cmd.Env = processEnv

	// Create pipes
	var err error
	pm.stdin, err = pm.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	pm.stdout, err = pm.cmd.StdoutPipe()
	if err != nil {
		pm.stdin.Close()
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	pm.stderr, err = pm.cmd.StderrPipe()
	if err != nil {
		pm.stdin.Close()
		pm.stdout.Close()
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the process
	if err := pm.cmd.Start(); err != nil {
		pm.stdin.Close()
		pm.stdout.Close()
		pm.stderr.Close()
		return fmt.Errorf("failed to start process: %w", err)
	}

	pm.running = true
	pm.command = config.Command
	pm.logger.Info("Process started", "pid", pm.cmd.Process.Pid, "command", config.Command)

	if pm.metrics != nil {
		pm.metrics.UpdateProcessStatus(config.Command[0], true)
	}

	// Start monitoring goroutines
	go pm.monitorProcess()
	go pm.handleStderr()

	return nil
}

// Write sends data to the child process's stdin
func (pm *LocalProcessManager) Write(data []byte) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.running || pm.stdin == nil {
		return fmt.Errorf("process is not running")
	}

	_, err := pm.stdin.Write(data)
	if err != nil {
		pm.logger.Error("Failed to write to process stdin", "error", err)
		return fmt.Errorf("failed to write to stdin: %w", err)
	}

	return nil
}

// ReadLoop continuously reads from stdout and calls the handler
func (pm *LocalProcessManager) ReadLoop(handler func([]byte)) error {
	pm.mu.RLock()
	stdout := pm.stdout
	running := pm.running
	pm.mu.RUnlock()

	if !running || stdout == nil {
		return fmt.Errorf("process is not running")
	}

	scanner := bufio.NewScanner(stdout)
	const maxMessageSize = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxMessageSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) > 0 {
			data := make([]byte, len(line))
			copy(data, line)
			handler(data)
		}
	}

	if err := scanner.Err(); err != nil {
		if err == io.EOF {
			return nil
		}
		pm.logger.Error("Error reading from process stdout", "error", err)
		return fmt.Errorf("failed to read from stdout: %w", err)
	}

	return nil
}

// Stop gracefully terminates the child process
func (pm *LocalProcessManager) Stop(timeout time.Duration) error {
	pm.mu.Lock()
	if !pm.running || pm.cmd == nil || pm.cmd.Process == nil {
		pm.mu.Unlock()
		return nil
	}

	pm.logger.Info("Stopping process", "pid", pm.cmd.Process.Pid, "timeout", timeout)

	// Close stdin
	if pm.stdin != nil {
		pm.stdin.Close()
		pm.stdin = nil
	}

	process := pm.cmd.Process
	// Capture done channel to wait on it
	done := pm.done
	pm.mu.Unlock()

	// Send SIGTERM
	if err := process.Signal(syscall.SIGTERM); err != nil {
		pm.logger.Warn("Failed to send SIGTERM", "error", err)
	}

	// Wait for monitorProcess to signal done
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		pm.logger.Warn("Process timeout, forcing kill", "pid", process.Pid)
		_ = process.Kill()

		// Wait again for kill to take effect
		select {
		case <-done:
			return nil
		case <-time.After(1 * time.Second):
			return fmt.Errorf("process stuck after kill")
		}
	}
}

// monitorProcess calls Wait() and handles exit.
// Note: In Stop(), we also might want to wait.
// Standard pattern: monitorProcess does the Waiting. Stop() just signals and waits on a 'done' channel or similar.
// In DefaultProcessManager, Stop waits on cmd.Wait() inside a goroutine?
// Actually DefaultProcessManager Stop() launches `go func() { done <- cmd.Wait() }`.
// BUT monitorProcess ALSO calls `err := pm.cmd.Wait()`.
// exec.Cmd.Wait() expects to be called only once.
// We need to fix this if the original code was buggy, or replicate it if I misunderstood.
// The original code:
// func (pm *DefaultProcessManager) monitorProcess() { ... err := pm.cmd.Wait(); pm.handleProcessExit(err) }
// func (pm) Stop() { ... go func() { done <- cmd.Wait() }() ... }
// This is definitely a RACE CONDITION in the original code if both run!
// Wait() panics if called twice.
// I will fix this in LocalProcessManager. I'll use a `waitDone` channel populated by monitorProcess.

func (pm *LocalProcessManager) monitorProcess() {
	if pm.cmd == nil {
		return
	}
	err := pm.cmd.Wait() // This blocks until exit
	pm.handleProcessExit(err)
}

func (pm *LocalProcessManager) handleProcessExit(err error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.running {
		return
	}
	pm.running = false

	if pm.cmd != nil && pm.cmd.ProcessState != nil {
		pm.exitCode = pm.cmd.ProcessState.ExitCode()
	}

	// Close stdin if not already closed (to ensure cleanup if process exit wasn't triggered by Stop)
	if pm.stdin != nil {
		pm.stdin.Close()
		pm.stdin = nil
	}
	// stdout/stderr are closed by cmd.Wait(), so we don't close them here to avoid races with ReadLoop
	pm.stdout = nil
	pm.stderr = nil

	if pm.metrics != nil && len(pm.command) > 0 {
		pm.metrics.UpdateProcessStatus(pm.command[0], false)
	}

	if err != nil {
		pm.logger.Error("Process exited with error", "error", err, "exit_code", pm.exitCode)
	} else {
		pm.logger.Info("Process exited normally", "exit_code", pm.exitCode)
	}

	close(pm.done)
}

// IsRunning checks running status
func (pm *LocalProcessManager) IsRunning() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.running
}

// ExitCode returns exit code
func (pm *LocalProcessManager) ExitCode() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.exitCode
}

// Type returns RuntimeLocal
func (pm *LocalProcessManager) Type() RuntimeType {
	return RuntimeLocal
}

func (pm *LocalProcessManager) handleStderr() {
	pm.mu.RLock()
	stderr := pm.stderr
	pm.mu.RUnlock()

	if stderr == nil {
		return
	}

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			pm.logger.Warn("Process stderr", "output", line)
		}
	}
}
