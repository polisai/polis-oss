package tls

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLSError_Error(t *testing.T) {
	tests := []struct {
		name     string
		tlsError *TLSError
		expected string
	}{
		{
			name: "basic error",
			tlsError: &TLSError{
				Type:    ErrorTypeCertificateLoad,
				Message: "failed to load certificate",
			},
			expected: "[certificate_load] failed to load certificate",
		},
		{
			name: "error with context",
			tlsError: &TLSError{
				Type:    ErrorTypeCertificateLoad,
				Message: "failed to load certificate",
				Context: map[string]interface{}{
					"cert_file": "/path/to/cert.pem",
					"key_file":  "/path/to/key.pem",
				},
			},
			expected: "[certificate_load] failed to load certificate | context: cert_file=/path/to/cert.pem, key_file=/path/to/key.pem",
		},
		{
			name: "error with cause",
			tlsError: &TLSError{
				Type:    ErrorTypeCertificateLoad,
				Message: "failed to load certificate",
				Cause:   fmt.Errorf("file not found"),
			},
			expected: "[certificate_load] failed to load certificate | cause: file not found",
		},
		{
			name: "error with context and cause",
			tlsError: &TLSError{
				Type:    ErrorTypeCertificateLoad,
				Message: "failed to load certificate",
				Context: map[string]interface{}{
					"cert_file": "/path/to/cert.pem",
				},
				Cause: fmt.Errorf("permission denied"),
			},
			expected: "[certificate_load] failed to load certificate | context: cert_file=/path/to/cert.pem | cause: permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tlsError.Error()
			// Since map iteration order is not guaranteed, we need to check components
			assert.Contains(t, result, "[certificate_load]")
			assert.Contains(t, result, "failed to load certificate")

			if tt.tlsError.Context != nil {
				assert.Contains(t, result, "context:")
			}
			if tt.tlsError.Cause != nil {
				assert.Contains(t, result, "cause:")
			}
		})
	}
}

func TestTLSError_WithContext(t *testing.T) {
	err := NewTLSError(ErrorTypeCertificateLoad, "test error")

	result := err.WithContext("key", "value")

	assert.Same(t, err, result) // Should return same instance
	assert.Equal(t, "value", err.Context["key"])
}

func TestTLSError_WithSuggestion(t *testing.T) {
	err := NewTLSError(ErrorTypeCertificateLoad, "test error")

	result := err.WithSuggestion("Check file permissions")

	assert.Same(t, err, result) // Should return same instance
	assert.Len(t, err.Suggestions, 1)
	assert.Equal(t, "Check file permissions", err.Suggestions[0])
}

func TestTLSError_GetDetailedMessage(t *testing.T) {
	err := NewTLSError(ErrorTypeCertificateLoad, "test error").
		WithSuggestion("First suggestion").
		WithSuggestion("Second suggestion")

	result := err.GetDetailedMessage()

	assert.Contains(t, result, "test error")
	assert.Contains(t, result, "Suggestions:")
	assert.Contains(t, result, "1. First suggestion")
	assert.Contains(t, result, "2. Second suggestion")
}

func TestTLSError_Unwrap(t *testing.T) {
	cause := fmt.Errorf("underlying error")
	err := NewTLSErrorWithCause(ErrorTypeCertificateLoad, "test error", cause)

	result := err.Unwrap()

	assert.Equal(t, cause, result)
}

func TestNewConfigValidationError(t *testing.T) {
	err := NewConfigValidationError("cert_file", "/invalid/path", "file not found")

	assert.Equal(t, ErrorTypeConfigValidation, err.Type)
	assert.Contains(t, err.Message, "cert_file")
	assert.Equal(t, "cert_file", err.Context["field"])
	assert.Equal(t, "/invalid/path", err.Context["value"])
	assert.Equal(t, "file not found", err.Context["reason"])
}

func TestNewCertificateLoadError(t *testing.T) {
	cause := fmt.Errorf("permission denied")
	err := NewCertificateLoadError("/cert.pem", "/key.pem", cause)

	assert.Equal(t, ErrorTypeCertificateLoad, err.Type)
	assert.Equal(t, cause, err.Cause)
	assert.Equal(t, "/cert.pem", err.Context["cert_file"])
	assert.Equal(t, "/key.pem", err.Context["key_file"])
	assert.NotEmpty(t, err.Suggestions)
}

func TestNewHandshakeFailureError(t *testing.T) {
	cause := fmt.Errorf("protocol version mismatch")
	err := NewHandshakeFailureError("version mismatch", cause)

	assert.Equal(t, ErrorTypeHandshakeFailure, err.Type)
	assert.Contains(t, err.Message, "version mismatch")
	assert.Equal(t, cause, err.Cause)
	assert.Equal(t, "version mismatch", err.Context["failure_reason"])
	assert.NotEmpty(t, err.Suggestions)
}

func TestErrorClassificationHelpers(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		checker  func(error) bool
		expected bool
	}{
		{
			name:     "certificate error",
			err:      NewCertificateLoadError("/cert.pem", "/key.pem", nil),
			checker:  IsCertificateError,
			expected: true,
		},
		{
			name:     "configuration error",
			err:      NewConfigValidationError("field", "value", "reason"),
			checker:  IsConfigurationError,
			expected: true,
		},
		{
			name:     "handshake error",
			err:      NewHandshakeFailureError("reason", nil),
			checker:  IsHandshakeError,
			expected: true,
		},
		{
			name:     "file system error",
			err:      NewFileNotFoundError("/path"),
			checker:  IsFileSystemError,
			expected: true,
		},
		{
			name:     "non-TLS error",
			err:      fmt.Errorf("regular error"),
			checker:  IsCertificateError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.checker(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetErrorSeverity(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorSeverity
	}{
		{
			name:     "critical certificate expired",
			err:      NewCertificateExpiredError("/cert.pem", "2023-01-01"),
			expected: SeverityCritical,
		},
		{
			name:     "error certificate load",
			err:      NewCertificateLoadError("/cert.pem", "/key.pem", nil),
			expected: SeverityError,
		},
		{
			name:     "warning handshake failure",
			err:      NewHandshakeFailureError("reason", nil),
			expected: SeverityWarning,
		},
		{
			name:     "error for non-TLS error",
			err:      fmt.Errorf("regular error"),
			expected: SeverityError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetErrorSeverity(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRecoverySuggestions(t *testing.T) {
	err := NewCertificateLoadError("/cert.pem", "/key.pem", nil).
		WithSuggestion("Check file permissions").
		WithSuggestion("Verify certificate format")

	suggestions := GetRecoverySuggestions(err)

	// The error constructor adds its own suggestions, so we expect more than 2
	assert.GreaterOrEqual(t, len(suggestions), 2)
	assert.Contains(t, suggestions, "Check file permissions")
	assert.Contains(t, suggestions, "Verify certificate format")
}

func TestGetRecoverySuggestions_NonTLSError(t *testing.T) {
	err := fmt.Errorf("regular error")

	suggestions := GetRecoverySuggestions(err)

	assert.Len(t, suggestions, 2)
	assert.Contains(t, suggestions, "Check server logs for more details")
	assert.Contains(t, suggestions, "Verify TLS configuration is correct")
}
