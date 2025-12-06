package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// MemoryTokenVault is an in-memory implementation of TokenVault.
type MemoryTokenVault struct {
	mu     sync.RWMutex
	tokens map[string]string // token -> original value
}

// NewMemoryTokenVault creates a new in-memory token vault.
func NewMemoryTokenVault() *MemoryTokenVault {
	return &MemoryTokenVault{
		tokens: make(map[string]string),
	}
}

// Tokenize stores the sensitive value and returns a secure token.
func (v *MemoryTokenVault) Tokenize(_ context.Context, value string, _ string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	id := uuid.New().String()
	token := fmt.Sprintf("[TOKEN::%s]", id)

	v.tokens[token] = value
	return token, nil
}

// Detokenize retrieves the original sensitive value for a given token.
func (v *MemoryTokenVault) Detokenize(_ context.Context, token string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	value, ok := v.tokens[token]
	if !ok {
		return "", fmt.Errorf("token not found: %s", token)
	}
	return value, nil
}
