package bridge

import (
	"context"
	"log/slog"
	"net/http"
)

// AgentIDHeader is the HTTP header name for agent identification
const AgentIDHeader = "X-Agent-ID"

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// AgentIDContextKey is the context key for storing the agent ID
const AgentIDContextKey contextKey = "agentID"

// MultiTenantError represents an error related to multi-tenant isolation
type MultiTenantError struct {
	Code    int    // HTTP status code
	Message string // Error message
}

func (e *MultiTenantError) Error() string {
	return e.Message
}

// NewUnauthorizedError creates a 401 Unauthorized error
func NewUnauthorizedError(message string) *MultiTenantError {
	return &MultiTenantError{
		Code:    http.StatusUnauthorized,
		Message: message,
	}
}

// NewForbiddenError creates a 403 Forbidden error
func NewForbiddenError(message string) *MultiTenantError {
	return &MultiTenantError{
		Code:    http.StatusForbidden,
		Message: message,
	}
}

// NewNotFoundError creates a 404 Not Found error
func NewNotFoundError(message string) *MultiTenantError {
	return &MultiTenantError{
		Code:    http.StatusNotFound,
		Message: message,
	}
}

// AgentIDMiddleware validates the presence of X-Agent-ID header
// and adds the agent ID to the request context
type AgentIDMiddleware struct {
	logger *slog.Logger
}

// NewAgentIDMiddleware creates a new agent ID validation middleware
func NewAgentIDMiddleware(logger *slog.Logger) *AgentIDMiddleware {
	if logger == nil {
		logger = slog.Default()
	}
	return &AgentIDMiddleware{
		logger: logger,
	}
}

// Wrap wraps an HTTP handler with agent ID validation
func (m *AgentIDMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID := r.Header.Get(AgentIDHeader)
		if agentID == "" {
			m.logger.Warn("Request missing agent ID header",
				"path", r.URL.Path,
				"method", r.Method,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "Unauthorized: missing X-Agent-ID header", http.StatusUnauthorized)
			return
		}

		// Add agent ID to context
		ctx := context.WithValue(r.Context(), AgentIDContextKey, agentID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetAgentIDFromContext extracts the agent ID from the request context
func GetAgentIDFromContext(ctx context.Context) (string, bool) {
	agentID, ok := ctx.Value(AgentIDContextKey).(string)
	return agentID, ok
}

// ValidateAgentID checks if the agent ID header is present and non-empty
// Returns the agent ID if valid, or an error if not
func ValidateAgentID(r *http.Request) (string, error) {
	agentID := r.Header.Get(AgentIDHeader)
	if agentID == "" {
		return "", NewUnauthorizedError("missing X-Agent-ID header")
	}
	return agentID, nil
}

// GetAgentID extracts the agent ID from the request header.
// Returns empty string if not present.
func GetAgentID(r *http.Request) string {
	return r.Header.Get(AgentIDHeader)
}

// SessionAccessValidator validates session access for multi-tenant isolation
type SessionAccessValidator struct {
	sessionManager SessionManager
	logger         *slog.Logger
}

// NewSessionAccessValidator creates a new session access validator
func NewSessionAccessValidator(sm SessionManager, logger *slog.Logger) *SessionAccessValidator {
	if logger == nil {
		logger = slog.Default()
	}
	return &SessionAccessValidator{
		sessionManager: sm,
		logger:         logger,
	}
}

// ValidateAccess checks if the agent has access to the specified session
// Returns the session if access is granted, or an appropriate error
func (v *SessionAccessValidator) ValidateAccess(sessionID, agentID string) (*Session, error) {
	if agentID == "" {
		return nil, NewUnauthorizedError("missing agent ID")
	}

	session, err := v.sessionManager.GetSession(sessionID, agentID)
	if err != nil {
		// Check if it's an access denied error (403) or not found (404)
		if IsAccessDenied(err) {
			v.logger.Warn("Session access denied: agent mismatch",
				"session_id", sessionID,
				"requesting_agent", agentID,
			)
			return nil, NewForbiddenError("access denied: session belongs to different agent")
		}
		if IsSessionNotFound(err) {
			return nil, NewNotFoundError("session not found")
		}
		// Unknown error - treat as internal server error
		return nil, &MultiTenantError{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		}
	}

	return session, nil
}

// ListSessionsForAgent returns all sessions owned by the specified agent
func (v *SessionAccessValidator) ListSessionsForAgent(agentID string) ([]*Session, error) {
	if agentID == "" {
		return nil, NewUnauthorizedError("missing agent ID")
	}

	return v.sessionManager.ListSessions(agentID)
}
