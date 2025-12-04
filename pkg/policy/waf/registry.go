package waf

import (
	"fmt"
	"strings"
	"sync"
)

// Registry maintains a threadsafe catalogue of reusable WAF rules.
type Registry struct {
	mu    sync.RWMutex
	rules map[string]Rule
}

// NewRegistry creates an empty registry instance.
func NewRegistry() *Registry {
	return &Registry{rules: make(map[string]Rule)}
}

// Register inserts or replaces a rule definition.
func (r *Registry) Register(rule Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("waf: registry rule name is required")
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("waf: registry rule %s missing pattern", rule.Name)
	}

	key := strings.ToLower(rule.Name)

	r.mu.Lock()
	r.rules[key] = rule
	r.mu.Unlock()
	return nil
}

// RegisterAll adds multiple rules.
func (r *Registry) RegisterAll(rules []Rule) error {
	for _, rule := range rules {
		if err := r.Register(rule); err != nil {
			return err
		}
	}
	return nil
}

// Resolve fetches a rule definition by identifier.
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

var (
	defaultRegistry     = newRegistryWithBuiltins()
	defaultRegistryOnce sync.Once
)

// GlobalRegistry exposes the process-wide registry populated with builtin rules.
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
			Name:     "waf.sql.union-select",
			Pattern:  `(?i)union\s+select`,
			Severity: SeverityHigh,
			Action:   ActionBlock,
		},
		{
			Name:     "waf.sql.comment-sequence",
			Pattern:  `(?i)(--|/\*|\*/)`,
			Severity: SeverityMedium,
			Action:   ActionBlock,
		},
		{
			Name:     "waf.xss.script-tag",
			Pattern:  `(?i)<script\b`,
			Severity: SeverityHigh,
			Action:   ActionBlock,
		},
		{
			Name:     "waf.path.traversal",
			Pattern:  `(\.\./|\.\.\\)`,
			Severity: SeverityMedium,
			Action:   ActionBlock,
		},
		// Friendly aliases used by example pipeline fixtures
		{
			Name:     "sql_injection",
			Pattern:  `(?i)union\s+select`,
			Severity: SeverityHigh,
			Action:   ActionBlock,
		},
		{
			Name:     "xss",
			Pattern:  `(?i)<script\b`,
			Severity: SeverityHigh,
			Action:   ActionBlock,
		},
		{
			Name:     "path_traversal",
			Pattern:  `(\.\./|\.\.\\)`,
			Severity: SeverityMedium,
			Action:   ActionBlock,
		},
	})
	return r
}
