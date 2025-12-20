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
	config *AuthConfig
	logger *slog.Logger
}

// NewAgentIDMiddleware creates a new agent ID validation middleware
func NewAgentIDMiddleware(config *AuthConfig, logger *slog.Logger) *AgentIDMiddleware {
	if logger == nil {
		logger = slog.Default()
	}
	if config == nil {
		// Safe default if config is missing
		config = &AuthConfig{
			EnforceAgentID: false,
			DefaultAgentID: "default",
		}
	}
	return &AgentIDMiddleware{
		config: config,
		logger: logger,
	}
}

// Wrap wraps an HTTP handler with agent ID validation
func (m *AgentIDMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Header (Primary)
		agentID := r.Header.Get(AgentIDHeader)

		// 2. Check Query Parameter (Secondary - for browser testing/inspector)
		if agentID == "" {
			agentID = r.URL.Query().Get("agent_id")
		}
		if agentID == "" {
			agentID = r.URL.Query().Get("agentId")
		}

		// 3. Fallback logic
		if agentID == "" {
			if m.config.EnforceAgentID {
				// Strict Mode: Reject
				m.logger.Warn("Request missing agent ID",
					"path", r.URL.Path,
					"method", r.Method,
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "Unauthorized: missing X-Agent-ID header or agent_id query param", http.StatusUnauthorized)
				return
			}

			// Relaxed Mode: Use Default
			agentID = m.config.DefaultAgentID
			// Debug log only to avoid spamming
			m.logger.Debug("Using default agent ID", "agent_id", agentID, "path", r.URL.Path)
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

// ValidateAgentID checks if the agent ID header/query is present and non-empty
// Returns the agent ID if valid, or an error if not.
// Note: This function now respects the contract of checking the request
// but since middleware typically handles the fallback/enforcement,
// this implementation is updated to look for the ID in the same places.
// Ideally, handlers should rely on Context, not this function directly for validation.
func ValidateAgentID(r *http.Request) (string, error) {
	// Check Header
	agentID := r.Header.Get(AgentIDHeader)
	if agentID != "" {
		return agentID, nil
	}

	// Check Query
	agentID = r.URL.Query().Get("agent_id")
	if agentID != "" {
		return agentID, nil
	}
	agentID = r.URL.Query().Get("agentId")
	if agentID != "" {
		return agentID, nil
	}

	// If checking raw request, we don't have access to config here easily
	// unless we change signature. For now, return error if completely missing
	// as this function implies "Validate existence".
	return "", NewUnauthorizedError("missing X-Agent-ID header or agent_id query param")
}

// GetAgentID extracts the agent ID from the request header or query.
// Returns empty string if not present.
func GetAgentID(r *http.Request) string {
	id := r.Header.Get(AgentIDHeader)
	if id != "" {
		return id
	}
	id = r.URL.Query().Get("agent_id")
	if id != "" {
		return id
	}
	return r.URL.Query().Get("agentId")
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
