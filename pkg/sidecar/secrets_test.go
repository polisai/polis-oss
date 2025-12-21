package sidecar

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestSecretManager_Redaction(t *testing.T) {
	sm := NewSecretManager([]string{"secret123"})

	input := "This is a secret123 value"
	expected := "This is a [REDACTED] value"

	assert.Equal(t, expected, sm.Redact(input))
}

func TestSecretManager_PatternRedaction(t *testing.T) {
	sm := NewSecretManager(nil)

	input := "Authorization: Bearer mytoken123"
	expected := "Authorization: Bearer [REDACTED]"

	assert.Equal(t, expected, sm.Redact(input))
}

// Property 14: Secret Redaction
func TestSecretsProperties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a secret
		secret := rapid.StringMatching(`[a-zA-Z0-9]{10,20}`).Draw(t, "secret")

		sm := NewSecretManager([]string{secret})

		// Generate text containing the secret
		prefix := rapid.String().Draw(t, "prefix")
		suffix := rapid.String().Draw(t, "suffix")
		input := prefix + secret + suffix

		redacted := sm.Redact(input)

		if strings.Contains(redacted, secret) {
			t.Fatalf("Secret leaked in redacted string: %s", redacted)
		}

		if !strings.Contains(redacted, "[REDACTED]") {
			t.Fatalf("Redaction marker not found in: %s", redacted)
		}
	})
}
