package tls

import (
	"fmt"
	"strings"
)

// TLSErrorType represents different categories of TLS errors
type TLSErrorType string

const (
	// Configuration errors
	ErrorTypeConfigValidation TLSErrorType = "config_validation"
	ErrorTypeConfigParsing    TLSErrorType = "config_parsing"
	ErrorTypeConfigMissing    TLSErrorType = "config_missing"

	// Certificate errors
	ErrorTypeCertificateLoad        TLSErrorType = "certificate_load"
	ErrorTypeCertificateValidation  TLSErrorType = "certificate_validation"
	ErrorTypeCertificateParsing     TLSErrorType = "certificate_parsing"
	ErrorTypeCertificateExpired     TLSErrorType = "certificate_expired"
	ErrorTypeCertificateNotYetValid TLSErrorType = "certificate_not_yet_valid"
	ErrorTypeCertificateChain       TLSErrorType = "certificate_chain"

	// File system errors
	ErrorTypeFileAccess     TLSErrorType = "file_access"
	ErrorTypeFileNotFound   TLSErrorType = "file_not_found"
	ErrorTypeFilePermission TLSErrorType = "file_permission"
	ErrorTypeFileWatching   TLSErrorType = "file_watching"

	// TLS handshake errors
	ErrorTypeHandshakeFailure  TLSErrorType = "handshake_failure"
	ErrorTypeHandshakeTimeout  TLSErrorType = "handshake_timeout"
	ErrorTypeProtocolMismatch  TLSErrorType = "protocol_mismatch"
	ErrorTypeCipherNegotiation TLSErrorType = "cipher_negotiation"
	ErrorTypeClientAuth        TLSErrorType = "client_auth"

	// SNI errors
	ErrorTypeSNISelection TLSErrorType = "sni_selection"
	ErrorTypeSNIConfig    TLSErrorType = "sni_config"

	// Server operation errors
	ErrorTypeServerStartup    TLSErrorType = "server_startup"
	ErrorTypeServerShutdown   TLSErrorType = "server_shutdown"
	ErrorTypeListenerCreate   TLSErrorType = "listener_create"
	ErrorTypeConnectionHandle TLSErrorType = "connection_handle"

	// Pipeline integration errors
	ErrorTypePipelineIntegration TLSErrorType = "pipeline_integration"
	ErrorTypeRequestProcessing   TLSErrorType = "request_processing"
	ErrorTypeResponseProcessing  TLSErrorType = "response_processing"
)

// TLSError represents a structured TLS error with context
type TLSError struct {
	Type        TLSErrorType
	Message     string
	Cause       error
	Context     map[string]interface{}
	Suggestions []string
}

// Error implements the error interface
func (e *TLSError) Error() string {
	var parts []string

	// Add error type prefix
	parts = append(parts, fmt.Sprintf("[%s]", string(e.Type)))

	// Add main message
	parts = append(parts, e.Message)

	// Add context if available
	if len(e.Context) > 0 {
		var contextParts []string
		for key, value := range e.Context {
			contextParts = append(contextParts, fmt.Sprintf("%s=%v", key, value))
		}
		parts = append(parts, fmt.Sprintf("context: %s", strings.Join(contextParts, ", ")))
	}

	// Add underlying cause if available
	if e.Cause != nil {
		parts = append(parts, fmt.Sprintf("cause: %v", e.Cause))
	}

	return strings.Join(parts, " | ")
}

// Unwrap returns the underlying error for error unwrapping
func (e *TLSError) Unwrap() error {
	return e.Cause
}

// WithContext adds context information to the error
func (e *TLSError) WithContext(key string, value interface{}) *TLSError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithSuggestion adds a suggestion for resolving the error
func (e *TLSError) WithSuggestion(suggestion string) *TLSError {
	e.Suggestions = append(e.Suggestions, suggestion)
	return e
}

// GetDetailedMessage returns a detailed error message with suggestions
func (e *TLSError) GetDetailedMessage() string {
	message := e.Error()

	if len(e.Suggestions) > 0 {
		message += "\n\nSuggestions:"
		for i, suggestion := range e.Suggestions {
			message += fmt.Sprintf("\n  %d. %s", i+1, suggestion)
		}
	}

	return message
}

// NewTLSError creates a new TLS error with the specified type and message
func NewTLSError(errorType TLSErrorType, message string) *TLSError {
	return &TLSError{
		Type:    errorType,
		Message: message,
		Context: make(map[string]interface{}),
	}
}

// NewTLSErrorWithCause creates a new TLS error with an underlying cause
func NewTLSErrorWithCause(errorType TLSErrorType, message string, cause error) *TLSError {
	return &TLSError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
		Context: make(map[string]interface{}),
	}
}

// Configuration error constructors
func NewConfigValidationError(field string, value interface{}, reason string) *TLSError {
	return NewTLSError(ErrorTypeConfigValidation, fmt.Sprintf("invalid configuration field '%s'", field)).
		WithContext("field", field).
		WithContext("value", value).
		WithContext("reason", reason).
		WithSuggestion(fmt.Sprintf("Check the '%s' field in your TLS configuration", field)).
		WithSuggestion("Refer to the TLS configuration documentation for valid values")
}

func NewConfigMissingError(field string) *TLSError {
	return NewTLSError(ErrorTypeConfigMissing, fmt.Sprintf("required configuration field '%s' is missing", field)).
		WithContext("field", field).
		WithSuggestion(fmt.Sprintf("Add the '%s' field to your TLS configuration", field)).
		WithSuggestion("Ensure all required TLS configuration fields are present")
}

// Certificate error constructors
func NewCertificateLoadError(certFile, keyFile string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypeCertificateLoad, "failed to load certificate", cause).
		WithContext("cert_file", certFile).
		WithContext("key_file", keyFile).
		WithSuggestion("Verify that the certificate and key files exist and are readable").
		WithSuggestion("Check that the certificate and key files are in the correct format (PEM)").
		WithSuggestion("Ensure the certificate and private key match")
}

func NewCertificateValidationError(reason string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypeCertificateValidation, fmt.Sprintf("certificate validation failed: %s", reason), cause).
		WithContext("validation_reason", reason).
		WithSuggestion("Check the certificate validity period").
		WithSuggestion("Verify the certificate chain is complete").
		WithSuggestion("Ensure the certificate is properly formatted")
}

func NewCertificateExpiredError(certFile string, expiredAt string) *TLSError {
	return NewTLSError(ErrorTypeCertificateExpired, "certificate has expired").
		WithContext("cert_file", certFile).
		WithContext("expired_at", expiredAt).
		WithSuggestion("Renew the expired certificate").
		WithSuggestion("Update the certificate file path if a new certificate is available").
		WithSuggestion("Check certificate expiration monitoring to prevent future issues")
}

func NewCertificateNotYetValidError(certFile string, validFrom string) *TLSError {
	return NewTLSError(ErrorTypeCertificateNotYetValid, "certificate is not yet valid").
		WithContext("cert_file", certFile).
		WithContext("valid_from", validFrom).
		WithSuggestion("Check the system clock is correct").
		WithSuggestion("Wait until the certificate becomes valid").
		WithSuggestion("Use a certificate that is currently valid")
}

// File system error constructors
func NewFileNotFoundError(filePath string) *TLSError {
	return NewTLSError(ErrorTypeFileNotFound, fmt.Sprintf("file not found: %s", filePath)).
		WithContext("file_path", filePath).
		WithSuggestion("Verify the file path is correct").
		WithSuggestion("Check that the file exists at the specified location").
		WithSuggestion("Ensure the file has not been moved or deleted")
}

func NewFilePermissionError(filePath string, operation string) *TLSError {
	return NewTLSError(ErrorTypeFilePermission, fmt.Sprintf("permission denied for %s operation on file: %s", operation, filePath)).
		WithContext("file_path", filePath).
		WithContext("operation", operation).
		WithSuggestion("Check file permissions (should be readable by the process)").
		WithSuggestion("Ensure the process has appropriate file system permissions").
		WithSuggestion("For private keys, ensure permissions are restrictive (e.g., 600)")
}

// TLS handshake error constructors
func NewHandshakeFailureError(reason string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypeHandshakeFailure, fmt.Sprintf("TLS handshake failed: %s", reason), cause).
		WithContext("failure_reason", reason).
		WithSuggestion("Check client and server TLS version compatibility").
		WithSuggestion("Verify cipher suite compatibility").
		WithSuggestion("Ensure certificates are valid and trusted")
}

func NewHandshakeTimeoutError(timeout string) *TLSError {
	return NewTLSError(ErrorTypeHandshakeTimeout, "TLS handshake timed out").
		WithContext("timeout", timeout).
		WithSuggestion("Check network connectivity between client and server").
		WithSuggestion("Consider increasing the handshake timeout").
		WithSuggestion("Verify the server is responding to TLS connections")
}

func NewProtocolMismatchError(clientVersion, serverMinVersion string) *TLSError {
	return NewTLSError(ErrorTypeProtocolMismatch, "TLS protocol version mismatch").
		WithContext("client_version", clientVersion).
		WithContext("server_min_version", serverMinVersion).
		WithSuggestion("Update client to support a newer TLS version").
		WithSuggestion("Consider lowering the server minimum TLS version if security allows").
		WithSuggestion("Check TLS version configuration on both client and server")
}

func NewCipherNegotiationError(clientCiphers, serverCiphers string) *TLSError {
	return NewTLSError(ErrorTypeCipherNegotiation, "no common cipher suites found").
		WithContext("client_ciphers", clientCiphers).
		WithContext("server_ciphers", serverCiphers).
		WithSuggestion("Add compatible cipher suites to server configuration").
		WithSuggestion("Check client cipher suite support").
		WithSuggestion("Use standard, widely-supported cipher suites")
}

func NewClientAuthError(reason string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypeClientAuth, fmt.Sprintf("client authentication failed: %s", reason), cause).
		WithContext("auth_failure_reason", reason).
		WithSuggestion("Verify client certificate is valid and not expired").
		WithSuggestion("Check that client certificate is signed by a trusted CA").
		WithSuggestion("Ensure client certificate chain is complete")
}

// SNI error constructors
func NewSNISelectionError(serverName string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypeSNISelection, fmt.Sprintf("SNI certificate selection failed for server name: %s", serverName), cause).
		WithContext("server_name", serverName).
		WithSuggestion("Add a certificate for the requested server name").
		WithSuggestion("Configure a wildcard certificate if appropriate").
		WithSuggestion("Ensure the default certificate is properly configured")
}

// Server operation error constructors
func NewServerStartupError(reason string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypeServerStartup, fmt.Sprintf("TLS server startup failed: %s", reason), cause).
		WithContext("startup_failure_reason", reason).
		WithSuggestion("Check TLS configuration is valid").
		WithSuggestion("Verify certificates are accessible and valid").
		WithSuggestion("Ensure ports are not already in use")
}

func NewListenerCreateError(address string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypeListenerCreate, fmt.Sprintf("failed to create TLS listener on address: %s", address), cause).
		WithContext("address", address).
		WithSuggestion("Check that the address is not already in use").
		WithSuggestion("Verify the address format is correct").
		WithSuggestion("Ensure the process has permission to bind to the address")
}

func NewConnectionHandleError(remoteAddr string, reason string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypeConnectionHandle, fmt.Sprintf("failed to handle connection from %s: %s", remoteAddr, reason), cause).
		WithContext("remote_addr", remoteAddr).
		WithContext("handle_failure_reason", reason).
		WithSuggestion("Check server logs for more details").
		WithSuggestion("Verify client is using compatible TLS settings").
		WithSuggestion("Monitor connection patterns for potential issues")
}

// Pipeline integration error constructors
func NewPipelineIntegrationError(reason string, cause error) *TLSError {
	return NewTLSErrorWithCause(ErrorTypePipelineIntegration, fmt.Sprintf("pipeline integration failed: %s", reason), cause).
		WithContext("integration_failure_reason", reason).
		WithSuggestion("Check pipeline configuration is valid").
		WithSuggestion("Verify pipeline components are properly initialized").
		WithSuggestion("Review pipeline processing logs for errors")
}

// Error classification helpers
func IsCertificateError(err error) bool {
	if tlsErr, ok := err.(*TLSError); ok {
		switch tlsErr.Type {
		case ErrorTypeCertificateLoad, ErrorTypeCertificateValidation, ErrorTypeCertificateParsing,
			ErrorTypeCertificateExpired, ErrorTypeCertificateNotYetValid, ErrorTypeCertificateChain:
			return true
		}
	}
	return false
}

func IsConfigurationError(err error) bool {
	if tlsErr, ok := err.(*TLSError); ok {
		switch tlsErr.Type {
		case ErrorTypeConfigValidation, ErrorTypeConfigParsing, ErrorTypeConfigMissing:
			return true
		}
	}
	return false
}

func IsHandshakeError(err error) bool {
	if tlsErr, ok := err.(*TLSError); ok {
		switch tlsErr.Type {
		case ErrorTypeHandshakeFailure, ErrorTypeHandshakeTimeout, ErrorTypeProtocolMismatch,
			ErrorTypeCipherNegotiation, ErrorTypeClientAuth:
			return true
		}
	}
	return false
}

func IsFileSystemError(err error) bool {
	if tlsErr, ok := err.(*TLSError); ok {
		switch tlsErr.Type {
		case ErrorTypeFileAccess, ErrorTypeFileNotFound, ErrorTypeFilePermission, ErrorTypeFileWatching:
			return true
		}
	}
	return false
}

// Error recovery suggestions
func GetRecoverySuggestions(err error) []string {
	if tlsErr, ok := err.(*TLSError); ok {
		return tlsErr.Suggestions
	}
	return []string{"Check server logs for more details", "Verify TLS configuration is correct"}
}

// Error severity levels
type ErrorSeverity int

const (
	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

func GetErrorSeverity(err error) ErrorSeverity {
	if tlsErr, ok := err.(*TLSError); ok {
		switch tlsErr.Type {
		case ErrorTypeConfigValidation, ErrorTypeConfigMissing, ErrorTypeCertificateExpired,
			ErrorTypeServerStartup, ErrorTypeListenerCreate:
			return SeverityCritical
		case ErrorTypeCertificateLoad, ErrorTypeCertificateValidation, ErrorTypeFileNotFound,
			ErrorTypeFilePermission:
			return SeverityError
		case ErrorTypeHandshakeFailure, ErrorTypeConnectionHandle, ErrorTypeSNISelection:
			return SeverityWarning
		default:
			return SeverityInfo
		}
	}
	return SeverityError
}
