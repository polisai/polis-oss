package llmjudge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LocalPromptProvider implements PromptProvider using local files.
// It expects a directory structure:
// rootDir/
//
//	tasks/
//	  {taskId}.txt
//	rules/
//	  {rulesId}.txt
type LocalPromptProvider struct {
	rootDir string
}

// NewLocalPromptProvider creates a provider reading from the specified root directory.
func NewLocalPromptProvider(rootDir string) *LocalPromptProvider {
	if rootDir == "" {
		// Default to a "prompts" directory in current working dir if not set
		rootDir = "prompts"
	}
	return &LocalPromptProvider{rootDir: rootDir}
}

func (p *LocalPromptProvider) GetPrompts(ctx context.Context, taskID, rulesID string) (string, string, error) {
	if taskID == "" || rulesID == "" {
		return "", "", fmt.Errorf("taskID and rulesID are required")
	}

	// Sanitize IDs to prevent directory traversal
	taskID = cleanFilename(taskID)
	rulesID = cleanFilename(rulesID)

	taskPath := filepath.Join(p.rootDir, "tasks", taskID+".txt")
	rulesPath := filepath.Join(p.rootDir, "rules", rulesID+".txt")

	taskContent, err := os.ReadFile(taskPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("%w: task %q at %s", ErrPromptNotFound, taskID, taskPath)
		}
		return "", "", fmt.Errorf("failed to read task prompt: %w", err)
	}

	rulesContent, err := os.ReadFile(rulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("%w: rules %q at %s", ErrPromptNotFound, rulesID, rulesPath)
		}
		return "", "", fmt.Errorf("failed to read rules prompt: %w", err)
	}

	return string(taskContent), string(rulesContent), nil
}

func cleanFilename(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "..", ""), "/", "")
}
