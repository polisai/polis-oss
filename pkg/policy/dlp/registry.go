package dlp

import (
	"fmt"
	"strings"
	"sync"
)

// Registry provides a threadsafe catalog of reusable DLP rule definitions.
type Registry struct {
	mu    sync.RWMutex
	rules map[string]Rule
}

// NewRegistry constructs an empty Registry instance.
func NewRegistry() *Registry {
	return &Registry{rules: make(map[string]Rule)}
}

// Register inserts or replaces a rule in the registry using its name as the identifier.
func (r *Registry) Register(rule Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("dlp: registry rule name is required")
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("dlp: registry rule %s missing pattern", rule.Name)
	}

	key := strings.ToLower(rule.Name)

	r.mu.Lock()
	r.rules[key] = rule
	r.mu.Unlock()
	return nil
}

// RegisterAll inserts multiple rules in a single call.
func (r *Registry) RegisterAll(rules []Rule) error {
	for _, rule := range rules {
		if err := r.Register(rule); err != nil {
			return err
		}
	}
	return nil
}

// Resolve retrieves a rule by identifier.
func (r *Registry) Resolve(id string) (Rule, bool) {
	if id == "" {
		return Rule{}, false
	}
	key := strings.ToLower(id)

	r.mu.RLock()
	rule, ok := r.rules[key]
	r.mu.RUnlock()
	if !ok {
		return Rule{}, false
	}
	return rule, true
}

// Clone returns a snapshot of all registered rules.
func (r *Registry) Clone() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		result = append(result, rule)
	}
	return result
}

var (
	defaultRegistry     = newRegistryWithBuiltins()
	defaultRegistryOnce sync.Once
)

// GlobalRegistry returns the process-wide registry populated with builtin rules.
func GlobalRegistry() *Registry {
	defaultRegistryOnce.Do(func() {
		if defaultRegistry == nil {
			defaultRegistry = newRegistryWithBuiltins()
		}
	})
	return defaultRegistry
}

func newRegistryWithBuiltins() *Registry {
	r := NewRegistry()
	_ = r.RegisterAll([]Rule{
		{
			Name:        "pii.email",
			Pattern:     `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
			Action:      ActionRedact,
			Replacement: "[REDACTED:email]",
		},
		{
			Name:        "pii.ssn",
			Pattern:     `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`,
			Action:      ActionRedact,
			Replacement: "[REDACTED:ssn]",
		},
		{
			Name:        "pci.card-number",
			Pattern:     `(?i)\b(?:\d[ -]?){13,16}\b`,
			Action:      ActionBlock,
			Replacement: "[REDACTED:card]",
		},
		{
			Name:        "credit_card",
			Pattern:     `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
			Action:      ActionRedact,
			Replacement: "[REDACTED:credit-card]",
		},
		{
			Name:        "api_key",
			Pattern:     `(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|bearer[_-]?token)[:=\s]+[a-z0-9_\-]{16,}\b`,
			Action:      ActionRedact,
			Replacement: "[REDACTED:api-key]",
		},
		{
			Name:        "api_keys",
			Pattern:     `(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|bearer[_-]?token)[:=\s]+[a-z0-9_\-]{16,}\b`,
			Action:      ActionRedact,
			Replacement: "[REDACTED:api-key]",
		},
		{
			Name:        "ssn",
			Pattern:     `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`,
			Action:      ActionRedact,
			Replacement: "[REDACTED:ssn]",
		},
	})
	return r
}
