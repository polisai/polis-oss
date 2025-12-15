package config

import (
	"fmt"
	"strings"
)

// ConfigError represents a configuration validation error
type ConfigError struct {
	Field       string
	Value       interface{}
	Reason      string
	Suggestions []string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("configuration error in field '%s': %s", e.Field, e.Reason)
}

func (e *ConfigError) WithSuggestion(suggestion string) *ConfigError {
	e.Suggestions = append(e.Suggestions, suggestion)
	return e
}

func NewConfigMissingError(field string) *ConfigError {
	return &ConfigError{
		Field:  field,
		Reason: fmt.Sprintf("required field '%s' is missing", field),
	}
}

func NewConfigValidationError(field string, value interface{}, reason string) *ConfigError {
	return &ConfigError{
		Field:  field,
		Value:  value,
		Reason: reason,
	}
}

// TLSVersion represents supported TLS protocol versions
type TLSVersion string

const (
	TLSVersion10 TLSVersion = "1.0"
	TLSVersion11 TLSVersion = "1.1"
	TLSVersion12 TLSVersion = "1.2"
	TLSVersion13 TLSVersion = "1.3"
)

// ParseTLSVersion converts a string to a TLSVersion with validation
func ParseTLSVersion(version string) (TLSVersion, error) {
	if version == "" {
		return TLSVersion12, nil
	}

	normalized := strings.TrimSpace(version)
	switch TLSVersion(normalized) {
	case TLSVersion10, TLSVersion11, TLSVersion12, TLSVersion13:
		return TLSVersion(normalized), nil
	default:
		return "", fmt.Errorf("unsupported TLS version %q", version)
	}
}

// TLSConfig represents TLS termination configuration
type TLSConfig struct {
	Enabled      bool                     `yaml:"enabled" json:"enabled"`
	CertFile     string                   `yaml:"cert_file" json:"cert_file"`
	KeyFile      string                   `yaml:"key_file" json:"key_file"`
	CAFile       string                   `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	MinVersion   string                   `yaml:"min_version,omitempty" json:"min_version,omitempty"`
	MaxVersion   string                   `yaml:"max_version,omitempty" json:"max_version,omitempty"`
	CipherSuites []string                 `yaml:"cipher_suites,omitempty" json:"cipher_suites,omitempty"`
	ClientAuth   TLSClientAuthConfig      `yaml:"client_auth,omitempty" json:"client_auth,omitempty"`
	SNI          map[string]TLSCertConfig `yaml:"sni,omitempty" json:"sni,omitempty"`
}

// TLSClientAuthConfig configures mutual TLS authentication
type TLSClientAuthConfig struct {
	Required   bool   `yaml:"required" json:"required"`
	CAFile     string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	VerifyMode string `yaml:"verify_mode,omitempty" json:"verify_mode,omitempty"`
}

// TLSCertConfig represents SNI-specific certificate configuration
type TLSCertConfig struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

// UpstreamTLSConfig configures upstream TLS connections
type UpstreamTLSConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	ServerName         string   `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	CAFile             string   `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	CertFile           string   `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	KeyFile            string   `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	MinVersion         string   `yaml:"min_version,omitempty" json:"min_version,omitempty"`
	CipherSuites       []string `yaml:"cipher_suites,omitempty" json:"cipher_suites,omitempty"`
}

// ListenParamConfig supports multiple listeners with different TLS configs
type ListenParamConfig struct {
	Address  string     `yaml:"address" json:"address"`
	Protocol string     `yaml:"protocol" json:"protocol"`
	TLS      *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// Validate performs comprehensive validation of TLS configuration
func (c *TLSConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	// Validate required fields
	if strings.TrimSpace(c.CertFile) == "" {
		return NewConfigMissingError("cert_file").
			WithSuggestion("Provide a path to a valid TLS certificate file").
			WithSuggestion("Ensure the certificate file is in PEM format")
	}
	if strings.TrimSpace(c.KeyFile) == "" {
		return NewConfigMissingError("key_file").
			WithSuggestion("Provide a path to a valid TLS private key file").
			WithSuggestion("Ensure the private key file is in PEM format and matches the certificate")
	}

	// Validate TLS versions
	if c.MinVersion != "" {
		if _, err := ParseTLSVersion(c.MinVersion); err != nil {
			return NewConfigValidationError("min_version", c.MinVersion, err.Error()).
				WithSuggestion("Use a valid TLS version: 1.0, 1.1, 1.2, or 1.3").
				WithSuggestion("Consider using TLS 1.2 or higher for better security")
		}
	}

	if c.MaxVersion != "" {
		if _, err := ParseTLSVersion(c.MaxVersion); err != nil {
			return NewConfigValidationError("max_version", c.MaxVersion, err.Error()).
				WithSuggestion("Use a valid TLS version: 1.0, 1.1, 1.2, or 1.3").
				WithSuggestion("Ensure max_version is greater than or equal to min_version")
		}
	}

	// Validate version range
	if c.MinVersion != "" && c.MaxVersion != "" {
		minVer, _ := ParseTLSVersion(c.MinVersion)
		maxVer, _ := ParseTLSVersion(c.MaxVersion)
		if minVer > maxVer {
			return NewConfigValidationError("version_range",
				fmt.Sprintf("min_version=%s, max_version=%s", c.MinVersion, c.MaxVersion),
				"min_version cannot be greater than max_version").
				WithSuggestion("Ensure min_version is less than or equal to max_version").
				WithSuggestion("Review your TLS version requirements")
		}
	}

	// Validate cipher suites with enhanced security checks
	if err := c.validateCipherSuites(); err != nil {
		return err
	}

	// Additional security validation
	if err := c.validateSecuritySettings(); err != nil {
		return err
	}

	// Validate client authentication
	if err := c.ClientAuth.Validate(); err != nil {
		return fmt.Errorf("client authentication configuration error: %w", err)
	}

	// Validate SNI configurations
	for serverName, sniConfig := range c.SNI {
		if err := sniConfig.Validate(); err != nil {
			return fmt.Errorf("SNI configuration error for server '%s': %w", serverName, err)
		}

		// Validate server name format
		if err := c.validateServerName(serverName); err != nil {
			return NewConfigValidationError("sni_server_name", serverName, err.Error()).
				WithSuggestion("Use a valid domain name or wildcard pattern").
				WithSuggestion("Examples: example.com, *.example.com, api.example.com")
		}
	}

	return nil
}

// validateCipherSuites validates the cipher suite configuration
func (c *TLSConfig) validateCipherSuites() error {
	if len(c.CipherSuites) == 0 {
		return nil // Empty means use defaults
	}

	validCiphers := map[string]bool{
		"TLS_RSA_WITH_RC4_128_SHA":                      true,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 true,
		"TLS_RSA_WITH_AES_128_CBC_SHA":                  true,
		"TLS_RSA_WITH_AES_256_CBC_SHA":                  true,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":               true,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":               true,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":               true,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              true,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          true,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          true,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                true,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           true,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            true,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            true,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       true,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         true,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         true,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       true,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         true,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       true,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   true,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": true,
	}

	var invalidCiphers []string
	var insecureCiphers []string

	for _, cipher := range c.CipherSuites {
		cipher = strings.TrimSpace(cipher)
		if !validCiphers[cipher] {
			invalidCiphers = append(invalidCiphers, cipher)
		}

		// Check for known insecure ciphers
		if strings.Contains(cipher, "RC4") || strings.Contains(cipher, "3DES") {
			insecureCiphers = append(insecureCiphers, cipher)
		}
	}

	if len(invalidCiphers) > 0 {
		return NewConfigValidationError("cipher_suites", invalidCiphers, "invalid cipher suites specified").
			WithSuggestion("Use only supported TLS cipher suites").
			WithSuggestion("Refer to the TLS configuration documentation for valid cipher suite names").
			WithSuggestion("Consider using modern, secure cipher suites like ECDHE with AES-GCM")
	}

	if len(insecureCiphers) > 0 {
		return NewConfigValidationError("cipher_suites", insecureCiphers, "insecure cipher suites detected").
			WithSuggestion("Remove insecure cipher suites (RC4, 3DES) from configuration").
			WithSuggestion("Use modern cipher suites with forward secrecy (ECDHE)").
			WithSuggestion("Consider using AES-GCM or ChaCha20-Poly1305 for authenticated encryption")
	}

	return nil
}

// validateSecuritySettings performs additional security validation
func (c *TLSConfig) validateSecuritySettings() error {
	// Check minimum TLS version for security
	if c.MinVersion != "" {
		minVer, _ := ParseTLSVersion(c.MinVersion)
		if minVer < TLSVersion12 {
			return NewConfigValidationError("min_version", c.MinVersion,
				"TLS versions below 1.2 are deprecated and insecure").
				WithSuggestion("Use TLS 1.2 or higher for security").
				WithSuggestion("TLS 1.3 is recommended for best security and performance")
		}
	}

	// Warn about insecure settings
	if c.MaxVersion != "" {
		maxVer, _ := ParseTLSVersion(c.MaxVersion)
		if maxVer < TLSVersion12 {
			return NewConfigValidationError("max_version", c.MaxVersion,
				"maximum TLS version below 1.2 is insecure").
				WithSuggestion("Allow TLS 1.2 or higher").
				WithSuggestion("Remove max_version to use the latest supported version")
		}
	}

	return nil
}

// validateServerName validates SNI server name format
func (c *TLSConfig) validateServerName(serverName string) error {
	if serverName == "" {
		return fmt.Errorf("server name cannot be empty")
	}

	// Allow wildcard patterns
	if strings.HasPrefix(serverName, "*.") {
		serverName = serverName[2:] // Remove wildcard prefix for validation
	}

	// Basic domain name validation
	if len(serverName) > 253 {
		return fmt.Errorf("server name too long (max 253 characters)")
	}

	parts := strings.Split(serverName, ".")
	for _, part := range parts {
		if len(part) == 0 {
			return fmt.Errorf("empty label in server name")
		}
		if len(part) > 63 {
			return fmt.Errorf("label too long (max 63 characters): %s", part)
		}

		// Check for valid characters (simplified validation)
		for _, char := range part {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') || char == '-') {
				return fmt.Errorf("invalid character in server name: %c", char)
			}
		}

		// Labels cannot start or end with hyphen
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return fmt.Errorf("label cannot start or end with hyphen: %s", part)
		}
	}

	return nil
}

// Validate performs validation of client authentication configuration
func (c *TLSClientAuthConfig) Validate() error {
	if c.Required && strings.TrimSpace(c.CAFile) == "" {
		return fmt.Errorf("ca_file is required when client authentication is required")
	}
	return nil
}

// Validate performs validation of SNI certificate configuration
func (c *TLSCertConfig) Validate() error {
	if strings.TrimSpace(c.CertFile) == "" {
		return fmt.Errorf("cert_file is required for SNI configuration")
	}
	if strings.TrimSpace(c.KeyFile) == "" {
		return fmt.Errorf("key_file is required for SNI configuration")
	}
	return nil
}

// Validate performs validation of upstream TLS configuration
func (c *UpstreamTLSConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.MinVersion != "" {
		if _, err := ParseTLSVersion(c.MinVersion); err != nil {
			return fmt.Errorf("invalid min_version: %w", err)
		}
	}

	if c.CertFile != "" && c.KeyFile == "" {
		return fmt.Errorf("key_file is required when cert_file is specified")
	}
	if c.KeyFile != "" && c.CertFile == "" {
		return fmt.Errorf("cert_file is required when key_file is specified")
	}

	return nil
}

// Validate performs validation of listen parameter configuration
func (c *ListenParamConfig) Validate() error {
	if strings.TrimSpace(c.Address) == "" {
		return fmt.Errorf("address is required")
	}

	protocol := strings.TrimSpace(strings.ToLower(c.Protocol))
	if protocol == "" {
		protocol = "http"
	}

	switch protocol {
	case "http", "https":
		c.Protocol = protocol
	default:
		return fmt.Errorf("unsupported protocol %q", c.Protocol)
	}

	if c.TLS != nil {
		if err := c.TLS.Validate(); err != nil {
			return fmt.Errorf("invalid TLS configuration: %w", err)
		}

		if c.TLS.Enabled && protocol != "https" {
			return fmt.Errorf("protocol must be 'https' when TLS is enabled")
		}
	}

	if protocol == "https" && (c.TLS == nil || !c.TLS.Enabled) {
		return fmt.Errorf("TLS configuration is required for HTTPS protocol")
	}

	return nil
}
