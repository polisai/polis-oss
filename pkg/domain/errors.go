package domain

import "errors"

// Common domain errors
var (
	ErrPipelineNotFound     = errors.New("pipeline not found")
	ErrPolicyNotFound       = errors.New("policy not found")
	ErrPolicyEvalFailed     = errors.New("policy evaluation failed")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrAuthorizationDenied  = errors.New("authorization denied")
	ErrInvalidToken         = errors.New("invalid token")
	ErrTokenExpired         = errors.New("token expired")
	ErrConfigInvalid        = errors.New("invalid configuration")
	ErrUpstreamUnreachable  = errors.New("upstream service unreachable")
)

// DomainError wraps errors with additional context.
//
//nolint:revive // Name is intentionally verbose to distinguish domain-layer errors
type DomainError struct {
	Err     error
	Code    string
	Message string
	Details map[string]any
}

func (e *DomainError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Err.Error()
}

func (e *DomainError) Unwrap() error {
	return e.Err
}

// ErrorResponse defines the standard JSON error model returned by admin and data APIs.
// It intentionally avoids exposing sensitive details while providing a stable machine-readable code.
// TraceID should carry the current OpenTelemetry trace identifier when available to aid diagnostics.
type ErrorResponse struct {
	Code    string `json:"code"`               // Machine-readable error code (e.g., AUTHN_FAILED, RELOAD_FAILED)
	Message string `json:"message"`            // Human-readable message (safe for logs)
	TraceID string `json:"trace_id,omitempty"` // Optional trace/correlation ID
}
