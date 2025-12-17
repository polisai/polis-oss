package bridge

import (
	"errors"
	"fmt"
)

// Sentinel errors for session management
var (
	// ErrSessionNotFound indicates the requested session does not exist
	ErrSessionNotFound = errors.New("session not found")

	// ErrAccessDenied indicates the agent does not have permission to access the session
	ErrAccessDenied = errors.New("access denied: session belongs to different agent")

	// ErrAgentIDRequired indicates the agent ID is missing from the request
	ErrAgentIDRequired = errors.New("agent ID is required")

	// ErrInvalidLastEventID indicates the Last-Event-ID format is invalid
	ErrInvalidLastEventID = errors.New("invalid last event ID format")
)

// SessionNotFoundError represents a session not found error with session ID
type SessionNotFoundError struct {
	SessionID string
}

func (e *SessionNotFoundError) Error() string {
	return fmt.Sprintf("session not found: %s", e.SessionID)
}

func (e *SessionNotFoundError) Is(target error) bool {
	return target == ErrSessionNotFound
}

// AccessDeniedError represents an access denied error with details
type AccessDeniedError struct {
	SessionID string
	AgentID   string
	OwnerID   string
}

func (e *AccessDeniedError) Error() string {
	return fmt.Sprintf("access denied: agent %s cannot access session %s owned by %s", e.AgentID, e.SessionID, e.OwnerID)
}

func (e *AccessDeniedError) Is(target error) bool {
	return target == ErrAccessDenied
}

// IsSessionNotFound checks if the error indicates a session was not found
func IsSessionNotFound(err error) bool {
	return errors.Is(err, ErrSessionNotFound)
}

// IsAccessDenied checks if the error indicates access was denied
func IsAccessDenied(err error) bool {
	return errors.Is(err, ErrAccessDenied)
}
