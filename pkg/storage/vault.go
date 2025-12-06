package storage

import "context"

// TokenVault manages the secure storage and retrieval of sensitive data tokens.
type TokenVault interface {
	// Tokenize stores the sensitive value and returns a secure token.
	Tokenize(ctx context.Context, value string, ruleID string) (string, error)

	// Detokenize retrieves the original sensitive value for a given token.
	Detokenize(ctx context.Context, token string) (string, error)
}
