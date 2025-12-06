// Package dlp provides configurable data loss prevention scanning utilities.
package dlp

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultConfig returns a baseline configuration covering common PII classes.
func DefaultConfig() Config {
	return Config{
		Rules: []Rule{
			{
				Name:        "email",
				Pattern:     `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
				Action:      ActionRedact,
				Replacement: "[REDACTED:email]",
			},
			{
				Name:        "ssn",
				Pattern:     `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`,
				Action:      ActionRedact,
				Replacement: "[REDACTED:ssn]",
			},
		},
	}
}

// NewScanner constructs a Scanner for the provided configuration.
func NewScanner(cfg Config) (*Scanner, error) {
	if len(cfg.Rules) == 0 {
		return &Scanner{}, nil
	}

	compiled := make([]compiledRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			return nil, fmt.Errorf("dlp: rule name is required")
		}
		pattern := strings.TrimSpace(rule.Pattern)
		if pattern == "" {
			return nil, fmt.Errorf("dlp: pattern is required for rule %s", name)
		}
		action := rule.Action
		if action == "" {
			action = ActionRedact
		}
		if !isValidAction(action) {
			return nil, fmt.Errorf("dlp: unsupported action %q for rule %s", action, name)
		}
		expr, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("dlp: invalid pattern for rule %s: %w", name, err)
		}
		replacement := rule.Replacement
		if replacement == "" && action == ActionRedact {
			replacement = fmt.Sprintf("[REDACTED:%s]", name)
		}

		compiled = append(compiled, compiledRule{
			name:        name,
			expr:        expr,
			action:      action,
			replacement: replacement,
		})
	}

	return &Scanner{rules: compiled, vault: cfg.Vault}, nil
}

// NewStreamRedactor constructs a streaming redactor for incremental inspection.
func NewStreamRedactor(cfg Config) (*StreamRedactor, error) {
	scanner, err := NewScanner(cfg)
	if err != nil {
		return nil, err
	}

	chunkSize := cfg.ChunkSize
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}

	overlap := cfg.Overlap
	if overlap < 0 {
		overlap = 0
	}
	if overlap > chunkSize {
		overlap = chunkSize
	}

	maxReplacement := overlap
	for _, rule := range cfg.Rules {
		if rule.Action == ActionRedact {
			repl := len(rule.Replacement)
			if repl > maxReplacement {
				maxReplacement = repl
			}
		}
	}
	overlap = maxReplacement

	maxFindings := cfg.MaxFindings
	if maxFindings <= 0 {
		maxFindings = defaultMaxFindings
	}

	deferEmission := false
	for _, rule := range cfg.Rules {
		if rule.Action == ActionBlock {
			deferEmission = true
			break
		}
	}

	return &StreamRedactor{
		scanner:       scanner,
		chunkSize:     chunkSize,
		overlap:       overlap,
		maxRead:       cfg.MaxReadBytes,
		maxFindings:   maxFindings,
		bufferRaw:     make([]byte, 0, chunkSize),
		findings:      []Finding{},
		deferEmission: deferEmission,
	}, nil
}
