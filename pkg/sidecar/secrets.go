package sidecar

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// SecretManager handles detection and redaction of secrets
type SecretManager struct {
	knownSecrets []string
	patterns     []*regexp.Regexp
}

// NewSecretManager creates a manager knowing provided secrets
func NewSecretManager(secrets []string) *SecretManager {
	// Common patterns for keys
	// Simplistic pattern: "sk-..." or similar.
	// For now we just implement exact match redaction + basic heuristic.

	sm := &SecretManager{
		knownSecrets: secrets,
		patterns: []*regexp.Regexp{
			// Example pattern: Authorization: Bearer <token>
			regexp.MustCompile(`(Authorization: Bearer\s+)([a-zA-Z0-9\-\._~+/]+=*)`),
		},
	}
	return sm
}

// FromConfig creates a SecretManager finding secrets in configured Env
func SecretManagerFromConfig(config *SidecarConfig) *SecretManager {
	var secrets []string
	// E.g. scan env vars for specific prefixes or sensitive keys
	sensitiveKeys := []string{"E2B_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"}

	// Also check config.Tools for environment variables?
	// For now, check process environment
	for _, key := range sensitiveKeys {
		if val := os.Getenv(key); val != "" {
			secrets = append(secrets, val)
		}
	}

	return NewSecretManager(secrets)
}

// Redact replaces secrets in the input string
func (sm *SecretManager) Redact(input string) string {
	res := input

	// 1. Exact match redaction
	for _, secret := range sm.knownSecrets {
		if len(secret) > 0 {
			res = strings.ReplaceAll(res, secret, "[REDACTED]")
		}
	}

	// 2. Pattern redaction
	for _, re := range sm.patterns {
		res = re.ReplaceAllString(res, "${1}[REDACTED]")
	}

	return res
}

// ValidateRequiredSecrets checks for essential secrets
func (sm *SecretManager) ValidateRequiredSecrets(requiredKeys []string) error {
	var missing []string
	for _, key := range requiredKeys {
		if os.Getenv(key) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	return nil
}
