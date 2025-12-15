package tls

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DegradationLevel represents the level of service degradation
type DegradationLevel int

const (
	DegradationNone DegradationLevel = iota
	DegradationWarning
	DegradationPartial
	DegradationSevere
	DegradationCritical
)

func (d DegradationLevel) String() string {
	switch d {
	case DegradationNone:
		return "none"
	case DegradationWarning:
		return "warning"
	case DegradationPartial:
		return "partial"
	case DegradationSevere:
		return "severe"
	case DegradationCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// DegradationReason represents the reason for service degradation
type DegradationReason string

const (
	ReasonCertificateExpired  DegradationReason = "certificate_expired"
	ReasonCertificateInvalid  DegradationReason = "certificate_invalid"
	ReasonHandshakeFailures   DegradationReason = "handshake_failures"
	ReasonFileSystemErrors    DegradationReason = "filesystem_errors"
	ReasonConfigurationErrors DegradationReason = "configuration_errors"
	ReasonPipelineErrors      DegradationReason = "pipeline_errors"
	ReasonResourceExhaustion  DegradationReason = "resource_exhaustion"
)

// DegradationState represents the current degradation state
type DegradationState struct {
	Level       DegradationLevel
	Reason      DegradationReason
	Message     string
	StartTime   time.Time
	LastUpdate  time.Time
	ErrorCount  int
	Suggestions []string
}

// DegradationManager handles graceful degradation of TLS services
type DegradationManager struct {
	mu                 sync.RWMutex
	logger             *slog.Logger
	currentState       *DegradationState
	errorThresholds    map[DegradationReason]int
	timeWindows        map[DegradationReason]time.Duration
	errorCounts        map[DegradationReason][]time.Time
	degradationActions map[DegradationLevel][]DegradationAction
	callbacks          []DegradationCallback
}

// DegradationAction represents an action to take during degradation
type DegradationAction func(ctx context.Context, state *DegradationState) error

// DegradationCallback is called when degradation state changes
type DegradationCallback func(oldState, newState *DegradationState)

// NewDegradationManager creates a new degradation manager
func NewDegradationManager(logger *slog.Logger) *DegradationManager {
	if logger == nil {
		logger = slog.Default()
	}

	dm := &DegradationManager{
		logger:             logger,
		errorThresholds:    make(map[DegradationReason]int),
		timeWindows:        make(map[DegradationReason]time.Duration),
		errorCounts:        make(map[DegradationReason][]time.Time),
		degradationActions: make(map[DegradationLevel][]DegradationAction),
		callbacks:          make([]DegradationCallback, 0),
		currentState: &DegradationState{
			Level:     DegradationNone,
			StartTime: time.Now(),
		},
	}

	// Set default thresholds
	dm.setDefaultThresholds()

	// Set default actions
	dm.setDefaultActions()

	return dm
}

// setDefaultThresholds sets default error thresholds and time windows
func (dm *DegradationManager) setDefaultThresholds() {
	// Certificate-related errors are critical
	dm.errorThresholds[ReasonCertificateExpired] = 1
	dm.timeWindows[ReasonCertificateExpired] = time.Hour

	dm.errorThresholds[ReasonCertificateInvalid] = 3
	dm.timeWindows[ReasonCertificateInvalid] = 5 * time.Minute

	// Handshake failures can be more tolerant
	dm.errorThresholds[ReasonHandshakeFailures] = 10
	dm.timeWindows[ReasonHandshakeFailures] = time.Minute

	// File system errors
	dm.errorThresholds[ReasonFileSystemErrors] = 5
	dm.timeWindows[ReasonFileSystemErrors] = 5 * time.Minute

	// Configuration errors are critical
	dm.errorThresholds[ReasonConfigurationErrors] = 1
	dm.timeWindows[ReasonConfigurationErrors] = time.Hour

	// Pipeline errors
	dm.errorThresholds[ReasonPipelineErrors] = 20
	dm.timeWindows[ReasonPipelineErrors] = 5 * time.Minute

	// Resource exhaustion
	dm.errorThresholds[ReasonResourceExhaustion] = 5
	dm.timeWindows[ReasonResourceExhaustion] = time.Minute
}

// setDefaultActions sets default degradation actions
func (dm *DegradationManager) setDefaultActions() {
	// Warning level actions
	dm.degradationActions[DegradationWarning] = []DegradationAction{
		dm.logDegradationWarning,
		dm.increaseLogging,
	}

	// Partial degradation actions
	dm.degradationActions[DegradationPartial] = []DegradationAction{
		dm.logDegradationWarning,
		dm.increaseLogging,
		dm.enableFallbackCertificate,
	}

	// Severe degradation actions
	dm.degradationActions[DegradationSevere] = []DegradationAction{
		dm.logDegradationWarning,
		dm.increaseLogging,
		dm.enableFallbackCertificate,
		dm.disableNonEssentialFeatures,
	}

	// Critical degradation actions
	dm.degradationActions[DegradationCritical] = []DegradationAction{
		dm.logDegradationWarning,
		dm.increaseLogging,
		dm.enableFallbackCertificate,
		dm.disableNonEssentialFeatures,
		dm.enableEmergencyMode,
	}
}

// RecordError records an error and evaluates degradation
func (dm *DegradationManager) RecordError(ctx context.Context, reason DegradationReason, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	now := time.Now()

	// Initialize error count slice if needed
	if dm.errorCounts[reason] == nil {
		dm.errorCounts[reason] = make([]time.Time, 0)
	}

	// Add current error
	dm.errorCounts[reason] = append(dm.errorCounts[reason], now)

	// Clean old errors outside time window
	timeWindow := dm.timeWindows[reason]
	if timeWindow == 0 {
		timeWindow = 5 * time.Minute // Default window
	}

	cutoff := now.Add(-timeWindow)
	filtered := make([]time.Time, 0)
	for _, errorTime := range dm.errorCounts[reason] {
		if errorTime.After(cutoff) {
			filtered = append(filtered, errorTime)
		}
	}
	dm.errorCounts[reason] = filtered

	// Check if threshold is exceeded
	threshold := dm.errorThresholds[reason]
	if threshold == 0 {
		threshold = 10 // Default threshold
	}

	if len(dm.errorCounts[reason]) >= threshold {
		dm.evaluateDegradation(ctx, reason, err)
	}
}

// evaluateDegradation evaluates and potentially changes degradation level
func (dm *DegradationManager) evaluateDegradation(ctx context.Context, reason DegradationReason, err error) {
	var newLevel DegradationLevel
	var message string
	var suggestions []string

	// Determine degradation level based on reason and error count
	errorCount := len(dm.errorCounts[reason])

	switch reason {
	case ReasonCertificateExpired, ReasonConfigurationErrors:
		newLevel = DegradationCritical
		message = fmt.Sprintf("Critical TLS error: %s", reason)
		suggestions = []string{
			"Immediately renew expired certificates",
			"Fix configuration errors",
			"Check certificate file permissions",
		}
	case ReasonCertificateInvalid:
		if errorCount >= 10 {
			newLevel = DegradationSevere
		} else {
			newLevel = DegradationPartial
		}
		message = fmt.Sprintf("Certificate validation errors: %d in time window", errorCount)
		suggestions = []string{
			"Verify certificate chain is complete",
			"Check certificate file integrity",
			"Ensure certificate matches private key",
		}
	case ReasonHandshakeFailures:
		if errorCount >= 50 {
			newLevel = DegradationSevere
		} else if errorCount >= 20 {
			newLevel = DegradationPartial
		} else {
			newLevel = DegradationWarning
		}
		message = fmt.Sprintf("High handshake failure rate: %d failures", errorCount)
		suggestions = []string{
			"Check client TLS version compatibility",
			"Verify cipher suite configuration",
			"Monitor for potential attacks",
		}
	case ReasonFileSystemErrors:
		if errorCount >= 10 {
			newLevel = DegradationPartial
		} else {
			newLevel = DegradationWarning
		}
		message = fmt.Sprintf("File system access errors: %d errors", errorCount)
		suggestions = []string{
			"Check file permissions",
			"Verify disk space availability",
			"Check file system health",
		}
	case ReasonPipelineErrors:
		if errorCount >= 50 {
			newLevel = DegradationPartial
		} else {
			newLevel = DegradationWarning
		}
		message = fmt.Sprintf("Pipeline processing errors: %d errors", errorCount)
		suggestions = []string{
			"Check pipeline configuration",
			"Verify downstream services",
			"Review pipeline component health",
		}
	case ReasonResourceExhaustion:
		if errorCount >= 20 {
			newLevel = DegradationSevere
		} else if errorCount >= 10 {
			newLevel = DegradationPartial
		} else {
			newLevel = DegradationWarning
		}
		message = fmt.Sprintf("Resource exhaustion detected: %d incidents", errorCount)
		suggestions = []string{
			"Scale up server resources",
			"Implement connection limits",
			"Review resource usage patterns",
		}
	default:
		newLevel = DegradationWarning
		message = fmt.Sprintf("Unknown degradation reason: %s", reason)
	}

	// Only change state if new level is higher than current
	if newLevel > dm.currentState.Level {
		dm.changeDegradationState(ctx, newLevel, reason, message, suggestions)
	}
}

// changeDegradationState changes the current degradation state
func (dm *DegradationManager) changeDegradationState(ctx context.Context, level DegradationLevel, reason DegradationReason, message string, suggestions []string) {
	oldState := *dm.currentState

	dm.currentState = &DegradationState{
		Level:       level,
		Reason:      reason,
		Message:     message,
		StartTime:   time.Now(),
		LastUpdate:  time.Now(),
		ErrorCount:  len(dm.errorCounts[reason]),
		Suggestions: suggestions,
	}

	dm.logger.Error("TLS service degradation detected",
		"old_level", oldState.Level.String(),
		"new_level", level.String(),
		"reason", reason,
		"message", message,
		"error_count", dm.currentState.ErrorCount)

	// Execute degradation actions
	if actions, exists := dm.degradationActions[level]; exists {
		for _, action := range actions {
			if err := action(ctx, dm.currentState); err != nil {
				dm.logger.Error("Failed to execute degradation action",
					"level", level.String(),
					"error", err)
			}
		}
	}

	// Notify callbacks
	for _, callback := range dm.callbacks {
		callback(&oldState, dm.currentState)
	}
}

// GetCurrentState returns the current degradation state
func (dm *DegradationManager) GetCurrentState() *DegradationState {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Return a copy to prevent external modification
	state := *dm.currentState
	return &state
}

// AddCallback adds a degradation state change callback
func (dm *DegradationManager) AddCallback(callback DegradationCallback) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.callbacks = append(dm.callbacks, callback)
}

// SetThreshold sets the error threshold for a specific reason
func (dm *DegradationManager) SetThreshold(reason DegradationReason, threshold int, timeWindow time.Duration) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.errorThresholds[reason] = threshold
	dm.timeWindows[reason] = timeWindow
}

// Default degradation actions
func (dm *DegradationManager) logDegradationWarning(ctx context.Context, state *DegradationState) error {
	dm.logger.Warn("TLS service degradation active",
		"level", state.Level.String(),
		"reason", state.Reason,
		"message", state.Message,
		"duration", time.Since(state.StartTime),
		"suggestions", state.Suggestions)
	return nil
}

func (dm *DegradationManager) increaseLogging(ctx context.Context, state *DegradationState) error {
	dm.logger.Info("Increasing logging verbosity due to degradation",
		"level", state.Level.String())
	// In a real implementation, this would increase the log level
	return nil
}

func (dm *DegradationManager) enableFallbackCertificate(ctx context.Context, state *DegradationState) error {
	dm.logger.Info("Enabling fallback certificate due to degradation",
		"level", state.Level.String())
	// In a real implementation, this would switch to a fallback certificate
	return nil
}

func (dm *DegradationManager) disableNonEssentialFeatures(ctx context.Context, state *DegradationState) error {
	dm.logger.Info("Disabling non-essential features due to degradation",
		"level", state.Level.String())
	// In a real implementation, this would disable features like detailed metrics, etc.
	return nil
}

func (dm *DegradationManager) enableEmergencyMode(ctx context.Context, state *DegradationState) error {
	dm.logger.Error("Enabling emergency mode due to critical degradation",
		"level", state.Level.String(),
		"reason", state.Reason)
	// In a real implementation, this would enable emergency protocols
	return nil
}

// Recovery methods
func (dm *DegradationManager) CheckRecovery(ctx context.Context) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.currentState.Level == DegradationNone {
		return
	}

	// Check if error rates have decreased
	now := time.Now()
	reason := dm.currentState.Reason
	timeWindow := dm.timeWindows[reason]
	if timeWindow == 0 {
		timeWindow = 5 * time.Minute
	}

	cutoff := now.Add(-timeWindow)
	recentErrors := 0
	for _, errorTime := range dm.errorCounts[reason] {
		if errorTime.After(cutoff) {
			recentErrors++
		}
	}

	threshold := dm.errorThresholds[reason]
	if threshold == 0 {
		threshold = 10
	}

	// If error rate has dropped below threshold, consider recovery
	if recentErrors < threshold/2 {
		dm.attemptRecovery(ctx)
	}
}

func (dm *DegradationManager) attemptRecovery(ctx context.Context) {
	oldState := *dm.currentState

	// Gradually reduce degradation level
	var newLevel DegradationLevel
	switch dm.currentState.Level {
	case DegradationCritical:
		newLevel = DegradationSevere
	case DegradationSevere:
		newLevel = DegradationPartial
	case DegradationPartial:
		newLevel = DegradationWarning
	case DegradationWarning:
		newLevel = DegradationNone
	default:
		return
	}

	dm.currentState.Level = newLevel
	dm.currentState.LastUpdate = time.Now()

	dm.logger.Info("TLS service degradation recovery",
		"old_level", oldState.Level.String(),
		"new_level", newLevel.String(),
		"reason", dm.currentState.Reason)

	// Notify callbacks
	for _, callback := range dm.callbacks {
		callback(&oldState, dm.currentState)
	}
}
