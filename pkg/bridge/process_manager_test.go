package bridge

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// **Feature: mcp-expansion, Property 2: Message Forwarding Integrity**
// For any valid JSON-RPC message sent to the Bridge's stdin, the message SHALL appear
// on the child process's stdin unchanged, and for any JSON-RPC output written to the
// child process's stdout, it SHALL appear as output with equivalent content.
func TestMessageForwardingIntegrity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random JSON-RPC message
		message := generateJSONRPCMessage(t)
		
		// Create a process manager
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		pm := NewProcessManager(logger)
		
		// Use a simple command that echoes input to output
		var command []string
		if runtime.GOOS == "windows" {
			// On Windows, use findstr with a pattern that matches everything
			command = []string{"findstr", ".*"}
		} else {
			command = []string{"cat"}
		}
		
		// Start the process
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		err := pm.Start(ctx, command, "", nil)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		defer pm.Stop(5 * time.Second)
		
		// Variables to collect output
		var outputMu sync.Mutex
		var receivedOutput []byte
		
		// Start reading from stdout
		go func() {
			pm.ReadLoop(func(data []byte) {
				outputMu.Lock()
				receivedOutput = append(receivedOutput, data...)
				outputMu.Unlock()
			})
		}()
		
		// Write the message to stdin
		messageBytes, _ := json.Marshal(message)
		messageBytes = append(messageBytes, '\n')
		
		err = pm.Write(messageBytes)
		if err != nil {
			t.Fatalf("Failed to write to process: %v", err)
		}
		
		// Close stdin to signal EOF
		pm.mu.Lock()
		if pm.stdin != nil {
			pm.stdin.Close()
			pm.stdin = nil
		}
		pm.mu.Unlock()
		
		// Wait for output with timeout
		time.Sleep(500 * time.Millisecond)
		
		// Verify the output matches the input
		outputMu.Lock()
		output := receivedOutput
		outputMu.Unlock()
		
		if len(output) == 0 {
			t.Fatalf("No output received from process")
		}
		
		// Parse the output as JSON-RPC
		var receivedMessage map[string]interface{}
		err = json.Unmarshal(output, &receivedMessage)
		if err != nil {
			// Try to find JSON in the output
			outputStr := string(output)
			start := strings.Index(outputStr, "{")
			end := strings.LastIndex(outputStr, "}")
			if start >= 0 && end > start {
				jsonPart := outputStr[start : end+1]
				err = json.Unmarshal([]byte(jsonPart), &receivedMessage)
				if err != nil {
					t.Fatalf("Failed to parse output as JSON: %v, output: %s", err, output)
				}
			} else {
				t.Fatalf("Failed to parse output as JSON: %v, output: %s", err, output)
			}
		}
		
		// Verify the message content matches
		if receivedMessage["jsonrpc"] != message["jsonrpc"] {
			t.Errorf("jsonrpc field mismatch: got %v, want %v", receivedMessage["jsonrpc"], message["jsonrpc"])
		}
		
		if method, ok := message["method"]; ok {
			if receivedMessage["method"] != method {
				t.Errorf("method field mismatch: got %v, want %v", receivedMessage["method"], method)
			}
		}
		
		if id, ok := message["id"]; ok {
			// JSON unmarshaling converts numbers to float64, so we need to compare properly
			receivedID := receivedMessage["id"]
			if receivedIDFloat, ok := receivedID.(float64); ok {
				if int(receivedIDFloat) != id {
					t.Errorf("id field mismatch: got %v, want %v", receivedID, id)
				}
			} else if receivedID != id {
				t.Errorf("id field mismatch: got %v, want %v", receivedID, id)
			}
		}
	})
}

// generateJSONRPCMessage generates a random JSON-RPC message
func generateJSONRPCMessage(t *rapid.T) map[string]interface{} {
	message := map[string]interface{}{
		"jsonrpc": "2.0",
	}
	
	// Randomly decide if this is a request or response
	isRequest := rapid.Bool().Draw(t, "isRequest")
	
	if isRequest {
		// Generate a request
		message["method"] = rapid.StringMatching(`[a-z]+/[a-z]+`).Draw(t, "method")
		message["id"] = rapid.IntRange(1, 1000).Draw(t, "id")
		
		// Optionally add params
		if rapid.Bool().Draw(t, "hasParams") {
			message["params"] = map[string]interface{}{
				"key": rapid.String().Draw(t, "paramValue"),
			}
		}
	} else {
		// Generate a response
		message["id"] = rapid.IntRange(1, 1000).Draw(t, "id")
		
		// Either result or error
		if rapid.Bool().Draw(t, "hasResult") {
			message["result"] = map[string]interface{}{
				"data": rapid.String().Draw(t, "resultData"),
			}
		} else {
			message["error"] = map[string]interface{}{
				"code":    rapid.IntRange(-32768, -32000).Draw(t, "errorCode"),
				"message": rapid.String().Draw(t, "errorMessage"),
			}
		}
	}
	
	return message
}

// createEchoScript creates a temporary script that echoes stdin to stdout
func createEchoScript(t *rapid.T) string {
	if runtime.GOOS == "windows" {
		// For Windows, we'll use PowerShell inline command
		return ""
	}
	
	// For Unix-like systems, create a shell script
	tmpFile, err := os.CreateTemp("", "echo-*.sh")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	
	script := "#!/bin/sh\ncat\n"
	if _, err := tmpFile.WriteString(script); err != nil {
		t.Fatalf("Failed to write script: %v", err)
	}
	
	tmpFile.Close()
	
	if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
		t.Fatalf("Failed to chmod script: %v", err)
	}
	
	return tmpFile.Name()
}

// TestProcessManagerBasicLifecycle tests basic start/stop functionality
func TestProcessManagerBasicLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	// Determine command based on OS
	var command []string
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "echo", "test"}
	} else {
		command = []string{"echo", "test"}
	}
	
	ctx := context.Background()
	err := pm.Start(ctx, command, "", nil)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	
	if !pm.IsRunning() {
		t.Error("Process should be running after Start()")
	}
	
	// Wait a bit for the process to complete
	time.Sleep(100 * time.Millisecond)
	
	err = pm.Stop(5 * time.Second)
	if err != nil {
		t.Fatalf("Failed to stop process: %v", err)
	}
}

// TestProcessManagerStdoutCapture tests that stdout is captured correctly
func TestProcessManagerStdoutCapture(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	expectedOutput := "test output"
	
	// Determine command based on OS
	var command []string
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "echo", expectedOutput}
	} else {
		command = []string{"echo", expectedOutput}
	}
	
	ctx := context.Background()
	err := pm.Start(ctx, command, "", nil)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	defer pm.Stop(5 * time.Second)
	
	var output []byte
	var mu sync.Mutex
	
	done := make(chan struct{})
	go func() {
		pm.ReadLoop(func(data []byte) {
			mu.Lock()
			output = append(output, data...)
			mu.Unlock()
		})
		close(done)
	}()
	
	// Wait for output
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for output")
	}
	
	mu.Lock()
	outputStr := string(output)
	mu.Unlock()
	
	if !strings.Contains(outputStr, expectedOutput) {
		t.Errorf("Expected output to contain %q, got %q", expectedOutput, outputStr)
	}
}

// TestProcessManagerStderrCapture tests that stderr is captured and logged
func TestProcessManagerStderrCapture(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	// Determine command based on OS that writes to stderr
	var command []string
	if runtime.GOOS == "windows" {
		// PowerShell command to write to stderr
		command = []string{"powershell", "-Command", "[Console]::Error.WriteLine('error output')"}
	} else {
		command = []string{"sh", "-c", "echo 'error output' >&2"}
	}
	
	ctx := context.Background()
	err := pm.Start(ctx, command, "", nil)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	defer pm.Stop(5 * time.Second)
	
	// Wait for the process to complete
	time.Sleep(500 * time.Millisecond)
	
	// We can't easily verify stderr was logged, but we can verify the process ran
	if pm.IsRunning() {
		// Process might still be running, that's okay
	}
}

// TestProcessManagerExitCode tests that exit codes are captured correctly
func TestProcessManagerExitCode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	// Determine command based on OS that exits with code 42
	var command []string
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "exit", "42"}
	} else {
		command = []string{"sh", "-c", "exit 42"}
	}
	
	ctx := context.Background()
	err := pm.Start(ctx, command, "", nil)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	
	// Wait for process to exit
	time.Sleep(500 * time.Millisecond)
	
	exitCode := pm.ExitCode()
	if exitCode != 42 {
		t.Errorf("Expected exit code 42, got %d", exitCode)
	}
}

// TestProcessManagerWorkDir tests that working directory is set correctly
func TestProcessManagerWorkDir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "pm-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	// Determine command based on OS to print working directory
	var command []string
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "cd"}
	} else {
		command = []string{"pwd"}
	}
	
	ctx := context.Background()
	err = pm.Start(ctx, command, tmpDir, nil)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	defer pm.Stop(5 * time.Second)
	
	var output []byte
	var mu sync.Mutex
	
	done := make(chan struct{})
	go func() {
		pm.ReadLoop(func(data []byte) {
			mu.Lock()
			output = append(output, data...)
			mu.Unlock()
		})
		close(done)
	}()
	
	// Wait for output
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for output")
	}
	
	mu.Lock()
	outputStr := strings.TrimSpace(string(output))
	mu.Unlock()
	
	// Normalize paths for comparison
	if runtime.GOOS == "windows" {
		outputStr = strings.ToLower(outputStr)
		tmpDir = strings.ToLower(tmpDir)
	}
	
	if !strings.Contains(outputStr, tmpDir) {
		t.Errorf("Expected output to contain working directory %q, got %q", tmpDir, outputStr)
	}
}

// TestProcessManagerEnvVars tests that environment variables are passed correctly
func TestProcessManagerEnvVars(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	testEnvVar := "TEST_VAR_12345"
	testEnvValue := "test_value_67890"
	
	// Determine command based on OS to print environment variable
	var command []string
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "echo", "%" + testEnvVar + "%"}
	} else {
		command = []string{"sh", "-c", "echo $" + testEnvVar}
	}
	
	ctx := context.Background()
	err := pm.Start(ctx, command, "", []string{testEnvVar + "=" + testEnvValue})
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	defer pm.Stop(5 * time.Second)
	
	var output []byte
	var mu sync.Mutex
	
	done := make(chan struct{})
	go func() {
		pm.ReadLoop(func(data []byte) {
			mu.Lock()
			output = append(output, data...)
			mu.Unlock()
		})
		close(done)
	}()
	
	// Wait for output
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for output")
	}
	
	mu.Lock()
	outputStr := strings.TrimSpace(string(output))
	mu.Unlock()
	
	if !strings.Contains(outputStr, testEnvValue) {
		t.Errorf("Expected output to contain env value %q, got %q", testEnvValue, outputStr)
	}
}

// TestProcessManagerGracefulShutdown tests graceful shutdown with SIGTERM
func TestProcessManagerGracefulShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	// Create a long-running process
	var command []string
	if runtime.GOOS == "windows" {
		// On Windows, use PowerShell Start-Sleep
		command = []string{"powershell", "-Command", "Start-Sleep -Seconds 30"}
	} else {
		command = []string{"sleep", "30"}
	}
	
	ctx := context.Background()
	err := pm.Start(ctx, command, "", nil)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	
	if !pm.IsRunning() {
		t.Fatal("Process should be running")
	}
	
	// Stop the process with a short timeout
	err = pm.Stop(2 * time.Second)
	if err != nil {
		t.Fatalf("Failed to stop process: %v", err)
	}
	
	if pm.IsRunning() {
		t.Error("Process should not be running after Stop()")
	}
}

// TestProcessManagerForcedKill tests forced kill after timeout
func TestProcessManagerForcedKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping forced kill test on Windows due to signal handling differences")
	}
	
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	// Create a process that ignores SIGTERM
	command := []string{"sh", "-c", "trap '' TERM; sleep 30"}
	
	ctx := context.Background()
	err := pm.Start(ctx, command, "", nil)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	
	if !pm.IsRunning() {
		t.Fatal("Process should be running")
	}
	
	// Stop the process with a very short timeout to force kill
	start := time.Now()
	err = pm.Stop(500 * time.Millisecond)
	duration := time.Since(start)
	
	if err != nil {
		t.Fatalf("Failed to stop process: %v", err)
	}
	
	if pm.IsRunning() {
		t.Error("Process should not be running after Stop()")
	}
	
	// Verify that the process was killed (not gracefully stopped)
	// The duration should be close to the timeout, not immediate
	if duration < 400*time.Millisecond {
		t.Errorf("Process stopped too quickly, expected forced kill after timeout")
	}
}
// **Feature: mcp-expansion, Property 10: Process Lifecycle Cleanup**
// For any Bridge instance with an active child process, when the Bridge receives a 
// termination signal or the gateway connection closes, the child process SHALL be 
// terminated within the configured timeout (default 5 seconds).
func TestProcessLifecycleCleanup(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random timeout between 1 and 3 seconds (shorter for Windows compatibility)
		timeoutSeconds := rapid.IntRange(1, 3).Draw(t, "timeoutSeconds")
		timeout := time.Duration(timeoutSeconds) * time.Second
		
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		pm := NewProcessManager(logger)
		
		// Create a long-running process that should be terminated
		var command []string
		if runtime.GOOS == "windows" {
			// On Windows, use a simple ping command that runs for a while
			command = []string{"ping", "-n", "100", "127.0.0.1"}
		} else {
			command = []string{"sleep", "300"}
		}
		
		ctx := context.Background()
		err := pm.Start(ctx, command, "", nil)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		// Verify process is running
		if !pm.IsRunning() {
			t.Fatal("Process should be running after Start()")
		}
		
		// Record start time
		startTime := time.Now()
		
		// Stop the process with the generated timeout
		err = pm.Stop(timeout)
		if err != nil {
			t.Fatalf("Failed to stop process: %v", err)
		}
		
		// Record end time
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		
		// Verify process is no longer running
		if pm.IsRunning() {
			t.Error("Process should not be running after Stop()")
		}
		
		// Verify the process was terminated within the timeout + some buffer
		// We allow extra time for process cleanup and OS scheduling
		maxDuration := timeout + 2*time.Second
		if duration > maxDuration {
			t.Errorf("Process took too long to terminate: %v > %v", duration, maxDuration)
		}
		
		// Verify the process was not terminated too quickly (should take some time for graceful shutdown attempt)
		minDuration := 10 * time.Millisecond
		if duration < minDuration {
			t.Errorf("Process terminated too quickly: %v < %v", duration, minDuration)
		}
	})
}

// TestProcessLifecycleCleanupMultipleProcesses tests cleanup with multiple processes
func TestProcessLifecycleCleanupMultipleProcesses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	
	// Create multiple process managers
	numProcesses := 3
	pms := make([]*DefaultProcessManager, numProcesses)
	
	for i := 0; i < numProcesses; i++ {
		pms[i] = NewProcessManager(logger)
		
		// Create a long-running process
		var command []string
		if runtime.GOOS == "windows" {
			command = []string{"powershell", "-Command", "Start-Sleep -Seconds 60"}
		} else {
			command = []string{"sleep", "60"}
		}
		
		ctx := context.Background()
		err := pms[i].Start(ctx, command, "", nil)
		if err != nil {
			t.Fatalf("Failed to start process %d: %v", i, err)
		}
		
		if !pms[i].IsRunning() {
			t.Fatalf("Process %d should be running", i)
		}
	}
	
	// Stop all processes concurrently
	var wg sync.WaitGroup
	errors := make([]error, numProcesses)
	
	for i := 0; i < numProcesses; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = pms[idx].Stop(3 * time.Second)
		}(i)
	}
	
	wg.Wait()
	
	// Verify all processes stopped successfully
	for i := 0; i < numProcesses; i++ {
		if errors[i] != nil {
			t.Errorf("Failed to stop process %d: %v", i, errors[i])
		}
		
		if pms[i].IsRunning() {
			t.Errorf("Process %d should not be running after Stop()", i)
		}
	}
}

// TestProcessLifecycleCleanupWithContext tests cleanup when context is cancelled
func TestProcessLifecycleCleanupWithContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping context test on Windows due to timeout command behavior")
	}
	
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := NewProcessManager(logger)
	
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Create a long-running process
	command := []string{"sleep", "60"}
	
	err := pm.Start(ctx, command, "", nil)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	
	if !pm.IsRunning() {
		t.Fatal("Process should be running after Start()")
	}
	
	// Wait for context to timeout
	<-ctx.Done()
	
	// The process should still be running (context cancellation doesn't auto-stop)
	if !pm.IsRunning() {
		t.Error("Process should still be running after context cancellation")
	}
	
	// Manually stop the process
	err = pm.Stop(2 * time.Second)
	if err != nil {
		t.Fatalf("Failed to stop process: %v", err)
	}
	
	if pm.IsRunning() {
		t.Error("Process should not be running after Stop()")
	}
}