package tls

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewDegradationManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)

	assert.NotNil(t, dm)
	assert.Equal(t, DegradationNone, dm.GetCurrentState().Level)
	assert.NotEmpty(t, dm.errorThresholds)
	assert.NotEmpty(t, dm.timeWindows)
}

func TestDegradationLevel_String(t *testing.T) {
	tests := []struct {
		level    DegradationLevel
		expected string
	}{
		{DegradationNone, "none"},
		{DegradationWarning, "warning"},
		{DegradationPartial, "partial"},
		{DegradationSevere, "severe"},
		{DegradationCritical, "critical"},
		{DegradationLevel(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDegradationManager_RecordError_CertificateExpired(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)
	ctx := context.Background()

	// Certificate expired errors should immediately trigger critical degradation
	err := NewCertificateExpiredError("/cert.pem", "2023-01-01")
	dm.RecordError(ctx, ReasonCertificateExpired, err)

	state := dm.GetCurrentState()
	assert.Equal(t, DegradationCritical, state.Level)
	assert.Equal(t, ReasonCertificateExpired, state.Reason)
	assert.NotEmpty(t, state.Suggestions)
}

func TestDegradationManager_RecordError_HandshakeFailures(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)
	ctx := context.Background()

	// Record multiple handshake failures to trigger degradation
	err := NewHandshakeFailureError("test failure", fmt.Errorf("test"))

	// Record errors up to threshold
	threshold := dm.errorThresholds[ReasonHandshakeFailures]
	for i := 0; i < threshold; i++ {
		dm.RecordError(ctx, ReasonHandshakeFailures, err)
	}

	state := dm.GetCurrentState()
	assert.Equal(t, DegradationWarning, state.Level)
	assert.Equal(t, ReasonHandshakeFailures, state.Reason)
}

func TestDegradationManager_RecordError_TimeWindow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)

	// Set a very short time window for testing
	dm.SetThreshold(ReasonHandshakeFailures, 3, 100*time.Millisecond)

	ctx := context.Background()
	err := NewHandshakeFailureError("test failure", fmt.Errorf("test"))

	// Record 2 errors
	dm.RecordError(ctx, ReasonHandshakeFailures, err)
	dm.RecordError(ctx, ReasonHandshakeFailures, err)

	// Should not trigger degradation yet
	state := dm.GetCurrentState()
	assert.Equal(t, DegradationNone, state.Level)

	// Wait for time window to pass
	time.Sleep(150 * time.Millisecond)

	// Record another error - should not trigger because old errors expired
	dm.RecordError(ctx, ReasonHandshakeFailures, err)
	state = dm.GetCurrentState()
	assert.Equal(t, DegradationNone, state.Level)

	// Record 3 errors quickly
	dm.RecordError(ctx, ReasonHandshakeFailures, err)
	dm.RecordError(ctx, ReasonHandshakeFailures, err)
	dm.RecordError(ctx, ReasonHandshakeFailures, err)

	// Should trigger degradation
	state = dm.GetCurrentState()
	assert.Equal(t, DegradationWarning, state.Level)
}

func TestDegradationManager_AddCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)
	ctx := context.Background()

	callbackCalled := false
	var oldState, newState *DegradationState

	dm.AddCallback(func(old, new *DegradationState) {
		callbackCalled = true
		oldState = old
		newState = new
	})

	// Trigger degradation
	err := NewCertificateExpiredError("/cert.pem", "2023-01-01")
	dm.RecordError(ctx, ReasonCertificateExpired, err)

	assert.True(t, callbackCalled)
	assert.NotNil(t, oldState)
	assert.NotNil(t, newState)
	assert.Equal(t, DegradationNone, oldState.Level)
	assert.Equal(t, DegradationCritical, newState.Level)
}

func TestDegradationManager_CheckRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)

	// Set a short time window for testing
	dm.SetThreshold(ReasonHandshakeFailures, 4, 200*time.Millisecond)

	ctx := context.Background()
	err := NewHandshakeFailureError("test failure", fmt.Errorf("test"))

	// Trigger degradation
	for i := 0; i < 4; i++ {
		dm.RecordError(ctx, ReasonHandshakeFailures, err)
	}

	state := dm.GetCurrentState()
	assert.Equal(t, DegradationWarning, state.Level)

	// Wait for errors to age out
	time.Sleep(250 * time.Millisecond)

	// Check recovery
	dm.CheckRecovery(ctx)

	state = dm.GetCurrentState()
	assert.Equal(t, DegradationNone, state.Level)
}

func TestDegradationManager_SetThreshold(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)

	dm.SetThreshold(ReasonHandshakeFailures, 5, 10*time.Second)

	assert.Equal(t, 5, dm.errorThresholds[ReasonHandshakeFailures])
	assert.Equal(t, 10*time.Second, dm.timeWindows[ReasonHandshakeFailures])
}

func TestDegradationManager_GetCurrentState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)

	state1 := dm.GetCurrentState()
	state2 := dm.GetCurrentState()

	// Should return copies, not the same instance
	assert.NotSame(t, state1, state2)
	assert.Equal(t, state1.Level, state2.Level)
}

func TestDegradationManager_EvaluateDegradation_ConfigurationErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)
	ctx := context.Background()

	err := NewConfigValidationError("cert_file", "", "missing certificate file")
	dm.RecordError(ctx, ReasonConfigurationErrors, err)

	state := dm.GetCurrentState()
	assert.Equal(t, DegradationCritical, state.Level)
	assert.Equal(t, ReasonConfigurationErrors, state.Reason)
}

func TestDegradationManager_EvaluateDegradation_ResourceExhaustion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)
	ctx := context.Background()

	err := fmt.Errorf("out of memory")

	// Record errors to trigger different levels
	for i := 0; i < 5; i++ {
		dm.RecordError(ctx, ReasonResourceExhaustion, err)
	}

	state := dm.GetCurrentState()
	assert.Equal(t, DegradationWarning, state.Level)

	// Record more errors to trigger higher degradation
	for i := 0; i < 10; i++ {
		dm.RecordError(ctx, ReasonResourceExhaustion, err)
	}

	state = dm.GetCurrentState()
	assert.Equal(t, DegradationPartial, state.Level)

	// Record even more errors
	for i := 0; i < 20; i++ {
		dm.RecordError(ctx, ReasonResourceExhaustion, err)
	}

	state = dm.GetCurrentState()
	assert.Equal(t, DegradationSevere, state.Level)
}

func TestDegradationManager_DefaultActions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)
	ctx := context.Background()

	state := &DegradationState{
		Level:   DegradationWarning,
		Reason:  ReasonHandshakeFailures,
		Message: "test degradation",
	}

	// Test that default actions don't return errors
	err := dm.logDegradationWarning(ctx, state)
	assert.NoError(t, err)

	err = dm.increaseLogging(ctx, state)
	assert.NoError(t, err)

	err = dm.enableFallbackCertificate(ctx, state)
	assert.NoError(t, err)

	err = dm.disableNonEssentialFeatures(ctx, state)
	assert.NoError(t, err)

	err = dm.enableEmergencyMode(ctx, state)
	assert.NoError(t, err)
}

func TestDegradationManager_AttemptRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)

	// Manually set degradation state
	dm.mu.Lock()
	dm.currentState = &DegradationState{
		Level:      DegradationCritical,
		Reason:     ReasonHandshakeFailures,
		Message:    "test",
		StartTime:  time.Now(),
		LastUpdate: time.Now(),
	}
	dm.mu.Unlock()

	// Test recovery progression
	dm.attemptRecovery(context.Background())
	state := dm.GetCurrentState()
	assert.Equal(t, DegradationSevere, state.Level)

	dm.attemptRecovery(context.Background())
	state = dm.GetCurrentState()
	assert.Equal(t, DegradationPartial, state.Level)

	dm.attemptRecovery(context.Background())
	state = dm.GetCurrentState()
	assert.Equal(t, DegradationWarning, state.Level)

	dm.attemptRecovery(context.Background())
	state = dm.GetCurrentState()
	assert.Equal(t, DegradationNone, state.Level)

	// Should not change from None
	dm.attemptRecovery(context.Background())
	state = dm.GetCurrentState()
	assert.Equal(t, DegradationNone, state.Level)
}

func TestDegradationState_Copy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	dm := NewDegradationManager(logger)

	// Modify internal state
	dm.mu.Lock()
	dm.currentState.Level = DegradationWarning
	dm.currentState.Message = "test message"
	dm.mu.Unlock()

	// Get state copy
	state := dm.GetCurrentState()

	// Modify the copy
	state.Level = DegradationCritical
	state.Message = "modified message"

	// Original should be unchanged
	originalState := dm.GetCurrentState()
	assert.Equal(t, DegradationWarning, originalState.Level)
	assert.Equal(t, "test message", originalState.Message)
}
