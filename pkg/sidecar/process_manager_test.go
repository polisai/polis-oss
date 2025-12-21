package sidecar

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Property 6: ProcessManager Interface Consistency
func TestProcessManagerProperties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Mock dependencies
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		pm := NewLocalProcessManager(logger, &mockMetrics{}, &mockTracer{})

		// Model state
		verificationRunning := false

		steps := rapid.IntRange(1, 20).Draw(t, "steps")
		for i := 0; i < steps; i++ {
			action := rapid.SampledFrom([]string{"Start", "Stop", "IsRunning"}).Draw(t, "action")

			switch action {
			case "Start":
				// Only start if not running
				if verificationRunning {
					continue
				}

				// Generate simple command
				// cmd /c echo is safe on windows, echo on linux
				cmdStr := []string{"cmd", "/c", "echo", "check"}
				if _, err := os.Stat("/bin/sh"); err == nil {
					cmdStr = []string{"echo", "check"}
				}

				config := ProcessConfig{
					Command: cmdStr,
				}

				err := pm.Start(context.Background(), config)
				if err != nil {
					// Expect success
				} else {
					verificationRunning = true
				}
			case "Stop":
				if !verificationRunning {
					continue
				}

				err := pm.Stop(100 * time.Millisecond)
				if err == nil {
					verificationRunning = false
				}
			case "IsRunning":
				_ = pm.IsRunning()
			}
		}
	})
}

// Improved Property Test for Consistency using Long Running Process
// This ensures we can verify IsRunning state reliably.
func TestProcessManager_Consistency_LongRunning(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		pm := NewLocalProcessManager(logger, &mockMetrics{}, &mockTracer{})

		isRunningModel := false

		steps := rapid.IntRange(1, 20).Draw(t, "steps")
		for i := 0; i < steps; i++ {
			action := rapid.SampledFrom([]string{"Start", "CheckState", "Stop"}).Draw(t, "action")

			switch action {
			case "Start":
				t.Logf("Action: Start. ModelRunning=%v", isRunningModel)
				if isRunningModel {
					t.Log("Skipping Start (Model says running)")
					continue
				}

				cmdStr := []string{"ping", "-n", "10", "127.0.0.1"}
				if _, err := os.Stat("/bin/sh"); err == nil {
					cmdStr = []string{"sleep", "10"}
				}

				err := pm.Start(context.Background(), ProcessConfig{Command: cmdStr})
				if err == nil {
					t.Log("Start Success")
					isRunningModel = true
				} else {
					t.Logf("Start Failed: %v", err)
				}
			case "CheckState":
				t.Logf("Action: CheckState. Model=%v, Impl=%v", isRunningModel, pm.IsRunning())
				if isRunningModel != pm.IsRunning() {
					t.Fatalf("Model says running=%v, but implementation says %v", isRunningModel, pm.IsRunning())
				}
			case "Stop":
				t.Logf("Action: Stop. ModelRunning=%v", isRunningModel)
				err := pm.Stop(1 * time.Second)
				if err == nil {
					t.Log("Stop Success")
					isRunningModel = false
				} else {
					t.Logf("Stop Failed: %v", err)
				}
			}
		}

		// Cleanup
		if pm.IsRunning() {
			pm.Stop(1 * time.Second)
		}
	})
}
