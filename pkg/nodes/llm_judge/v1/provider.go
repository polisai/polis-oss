package llmjudge

import (
	"context"
	"errors"
)

// ErrPromptNotFound is returned when a requested prompt file cannot be found.
var ErrPromptNotFound = errors.New("prompt not found")

// PromptProvider defines the interface for retrieving prompt templates.
// Implementations can read from local files (OSS) or DB/Cache (Enterprise).
type PromptProvider interface {
	// GetPrompts retrieves the task and rules prompts for the given IDs.
	GetPrompts(ctx context.Context, taskID, rulesID string) (taskPrompt, rulesPrompt string, err error)
}
