package bridge

import (
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

// DefaultProcessManager implements the ProcessManager interface
type DefaultProcessManager struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	done     chan struct{}
	exitCode int
	mu       sync.RWMutex
	logger   *slog.Logger
	metrics  *Metrics
	tracing  *TracingManager
	running  bool
	command  []string // Store command for metrics
}

// NewProcessManager creates a new process manager instance
func NewProcessManager(logger *slog.Logger) *DefaultProcessManager {
	if logger == nil {
		logger = slog.Default()
	}
	
	return &DefaultProcessManager{
		logger:   logger,
		exitCode: -1,
		done:     make(chan struct{}),
	}
}

// SetMetrics sets the metrics instance for recording process metrics
func (pm *DefaultProcessManager) SetMetrics(metrics *Metrics) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.metrics = metrics
}

// SetTracing sets the tracing manager for trace propagation
func (pm *DefaultProcessManager) SetTracing(tracing *TracingManager) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.tracing = tracing
}

// Start spawns the child process with the given command and arguments
func (pm *DefaultProcessManager) Start(ctx context.Context, command []string, workDir string, env []string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if pm.running {
		return fmt.Errorf("process is already running")
	}
	
	if len(command) == 0 {
		return fmt.Errorf("command cannot be empty")
	}
	
	// Create the command
	pm.cmd = exec.CommandContext(ctx, command[0], command[1:]...)
	
	// Set working directory if specified
	if workDir != "" {
		pm.cmd.Dir = workDir
	}
	
	// Set environment variables
	processEnv := env
	if len(env) > 0 {
		processEnv = append(os.Environ(), env...)
	} else {
		processEnv = os.Environ()
	}
	
	// Inject trace context into environment variables if tracing is enabled
	if pm.tracing != nil {
		processEnv = pm.tracing.InjectProcessEnv(ctx, processEnv)
	}
	
	pm.cmd.Env = processEnv
	
	// Create pipes for stdin, stdout, and stderr
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
	pm.command = command
	pm.logger.Info("Process started", "pid", pm.cmd.Process.Pid, "command", command)
	
	// Update process status metrics
	if pm.metrics != nil {
		pm.metrics.UpdateProcessStatus(command[0], true)
	}
	
	// Start goroutine to monitor process exit
	go pm.monitorProcess()
	
	// Start goroutine to handle stderr
	go pm.handleStderr()
	
	return nil
}

// Write sends data to the child process's stdin
func (pm *DefaultProcessManager) Write(data []byte) error {
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

// ReadLoop continuously reads from stdout and calls the handler for each message
func (pm *DefaultProcessManager) ReadLoop(handler func([]byte)) error {
	pm.mu.RLock()
	stdout := pm.stdout
	running := pm.running
	pm.mu.RUnlock()
	
	if !running || stdout == nil {
		return fmt.Errorf("process is not running")
	}
	
	buffer := make([]byte, 4096)
	for {
		n, err := stdout.Read(buffer)
		if err != nil {
			if err == io.EOF {
				pm.logger.Debug("Process stdout closed")
				return nil
			}
			pm.logger.Error("Error reading from process stdout", "error", err)
			return fmt.Errorf("failed to read from stdout: %w", err)
		}
		
		if n > 0 {
			// Make a copy of the data to pass to the handler
			data := make([]byte, n)
			copy(data, buffer[:n])
			handler(data)
		}
	}
}

// Stop gracefully terminates the child process within the given timeout
func (pm *DefaultProcessManager) Stop(timeout time.Duration) error {
	pm.mu.Lock()
	
	if !pm.running || pm.cmd == nil || pm.cmd.Process == nil {
		pm.mu.Unlock()
		return nil // Already stopped
	}
	
	pm.logger.Info("Stopping process", "pid", pm.cmd.Process.Pid, "timeout", timeout)
	
	// First, try graceful shutdown by closing stdin
	if pm.stdin != nil {
		pm.stdin.Close()
		pm.stdin = nil
	}
	
	process := pm.cmd.Process
	cmd := pm.cmd
	pm.mu.Unlock()
	
	// Send SIGTERM for graceful shutdown
	if err := process.Signal(syscall.SIGTERM); err != nil {
		pm.logger.Warn("Failed to send SIGTERM", "error", err)
	}
	
	// Wait for graceful shutdown with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	
	select {
	case err := <-done:
		pm.handleProcessExit(err)
		return nil
	case <-time.After(timeout):
		// Timeout reached, force kill
		pm.logger.Warn("Process did not exit gracefully, forcing kill", "pid", process.Pid)
		if err := process.Kill(); err != nil {
			pm.logger.Error("Failed to kill process", "error", err)
			return fmt.Errorf("failed to kill process: %w", err)
		}
		
		// Wait for the kill to complete
		select {
		case err := <-done:
			pm.handleProcessExit(err)
			return nil
		case <-time.After(5 * time.Second):
			return fmt.Errorf("process did not exit after kill signal")
		}
	}
}

// IsRunning returns true if the child process is currently running
func (pm *DefaultProcessManager) IsRunning() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.running
}

// ExitCode returns the exit code of the process (only valid after process exits)
func (pm *DefaultProcessManager) ExitCode() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.exitCode
}

// monitorProcess monitors the process and handles exit
func (pm *DefaultProcessManager) monitorProcess() {
	if pm.cmd == nil {
		return
	}
	
	err := pm.cmd.Wait()
	pm.handleProcessExit(err)
}

// handleProcessExit handles process exit and cleanup
func (pm *DefaultProcessManager) handleProcessExit(err error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if !pm.running {
		return // Already handled
	}
	
	pm.running = false
	
	// Get exit code
	if pm.cmd != nil && pm.cmd.ProcessState != nil {
		pm.exitCode = pm.cmd.ProcessState.ExitCode()
	}
	
	// Close pipes
	if pm.stdin != nil {
		pm.stdin.Close()
		pm.stdin = nil
	}
	if pm.stdout != nil {
		pm.stdout.Close()
		pm.stdout = nil
	}
	if pm.stderr != nil {
		pm.stderr.Close()
		pm.stderr = nil
	}
	
	// Update process status metrics
	if pm.metrics != nil && len(pm.command) > 0 {
		pm.metrics.UpdateProcessStatus(pm.command[0], false)
	}
	
	// Log exit
	if err != nil {
		pm.logger.Error("Process exited with error", "error", err, "exit_code", pm.exitCode)
	} else {
		pm.logger.Info("Process exited normally", "exit_code", pm.exitCode)
	}
	
	// Signal completion (only close if not already closed)
	select {
	case <-pm.done:
		// Already closed
	default:
		close(pm.done)
	}
}

// handleStderr reads and logs stderr output
func (pm *DefaultProcessManager) handleStderr() {
	pm.mu.RLock()
	stderr := pm.stderr
	pm.mu.RUnlock()
	
	if stderr == nil {
		return
	}
	
	buffer := make([]byte, 4096)
	for {
		n, err := stderr.Read(buffer)
		if err != nil {
			if err == io.EOF {
				pm.logger.Debug("Process stderr closed")
				return
			}
			pm.logger.Error("Error reading from process stderr", "error", err)
			return
		}
		
		if n > 0 {
			// Log stderr output
			pm.logger.Warn("Process stderr", "output", string(buffer[:n]))
		}
	}
}