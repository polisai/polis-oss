package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Domain represents a policy domain that can express a failure posture.
type Domain string

const (
	// DomainAuth captures authentication posture decisions.
	DomainAuth Domain = "auth"
	// DomainContentDLP governs egress data loss prevention posture.
	DomainContentDLP Domain = "dlp"
	// DomainContentWAF governs ingress web application firewall posture.
	DomainContentWAF Domain = "waf"
	// DomainGovernance controls governance API posture defaults.
	DomainGovernance Domain = "governance"
	// DomainGlobal governs global policy failure posture.
	DomainGlobal Domain = "global"
)

// Mode indicates whether a domain fails open or closed when an error occurs.
type Mode string

const (
	// ModeFailClosed denies requests when the domain encounters an error.
	ModeFailClosed Mode = "fail-closed"
	// ModeFailOpen allows requests to continue when the domain encounters an error.
	ModeFailOpen Mode = "fail-open"
)

var (
	supportedDomains = map[Domain]struct{}{
		DomainAuth:       {},
		DomainContentDLP: {},
		DomainContentWAF: {},
		DomainGovernance: {},
		DomainGlobal:     {},
	}

	defaultModes = map[Domain]Mode{
		DomainAuth:       ModeFailClosed,
		DomainContentDLP: ModeFailOpen,
		DomainContentWAF: ModeFailOpen,
		DomainGovernance: ModeFailClosed,
		DomainGlobal:     ModeFailClosed,
	}
)

// PostureSet stores default postures with optional overrides per domain.
type PostureSet struct {
	defaults  map[Domain]Mode
	overrides map[Domain]Mode
}

// DefaultPostureSet returns the constitution defaults for all domains.
func DefaultPostureSet() PostureSet {
	defaults := make(map[Domain]Mode, len(defaultModes))
	for domain, mode := range defaultModes {
		defaults[domain] = mode
	}
	return PostureSet{defaults: defaults, overrides: map[Domain]Mode{}}
}

// Clone provides a deep copy of the set so callers can mutate safely.
func (s PostureSet) Clone() PostureSet {
	clone := PostureSet{
		defaults:  make(map[Domain]Mode, len(s.defaults)),
		overrides: make(map[Domain]Mode, len(s.overrides)),
	}
	for domain, mode := range s.defaults {
		clone.defaults[domain] = mode
	}
	for domain, mode := range s.overrides {
		clone.overrides[domain] = mode
	}
	return clone
}

// Mode returns the effective posture for the specified domain.
func (s PostureSet) Mode(domain Domain) Mode {
	if override, ok := s.overrides[domain]; ok {
		return override
	}
	if def, ok := s.defaults[domain]; ok {
		return def
	}
	return ModeFailClosed
}

// Effective returns a snapshot of all effective postures.
func (s PostureSet) Effective() map[Domain]Mode {
	effective := make(map[Domain]Mode, len(defaultModes))
	for domain := range supportedDomains {
		effective[domain] = s.Mode(domain)
	}
	return effective
}

// ApplyOverride sets the posture for a domain, validating input.
func (s *PostureSet) ApplyOverride(domain Domain, mode Mode) error {
	if _, ok := supportedDomains[domain]; !ok {
		return fmt.Errorf("policy: unknown failure posture domain %q", domain)
	}
	if !mode.IsValid() {
		return fmt.Errorf("policy: invalid failure posture mode %q", mode)
	}
	if s.overrides == nil {
		s.overrides = make(map[Domain]Mode)
	}
	s.overrides[domain] = mode
	return nil
}

// ApplyOverrideStrings parses and applies overrides provided as raw strings.
func (s *PostureSet) ApplyOverrideStrings(overrides map[string]string) error {
	for domainStr, modeStr := range overrides {
		domain := Domain(strings.TrimSpace(strings.ToLower(domainStr)))
		mode, err := ParseMode(modeStr)
		if err != nil {
			return fmt.Errorf("policy: domain %s: %w", domainStr, err)
		}
		if err := s.ApplyOverride(domain, mode); err != nil {
			return err
		}
	}
	return nil
}

// ParseMode converts a textual representation into a Mode constant.
func ParseMode(value string) (Mode, error) {
	mode := Mode(strings.TrimSpace(strings.ToLower(value)))
	if mode == "" {
		return "", errors.New("mode is required")
	}
	if !mode.IsValid() {
		return "", fmt.Errorf("invalid mode %q", value)
	}
	return mode, nil
}

// IsValid reports whether the mode is recognised.
func (m Mode) IsValid() bool {
	switch m {
	case ModeFailClosed, ModeFailOpen:
		return true
	default:
		return false
	}
}

// Domains returns the ordered list of supported posture domains.
func Domains() []Domain {
	domains := make([]Domain, 0, len(supportedDomains))
	for domain := range supportedDomains {
		domains = append(domains, domain)
	}
	sort.Slice(domains, func(i, j int) bool {
		return domains[i] < domains[j]
	})
	return domains
}
