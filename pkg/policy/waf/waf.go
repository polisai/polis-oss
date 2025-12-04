// Package waf implements pattern-based content inspection for request and response filtering.
package waf

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Severity represents the impact level of a WAF match.
type Severity string

const (
	// SeverityLow indicates informational detections.
	SeverityLow Severity = "low"
	// SeverityMedium indicates a suspicious but not critical match.
	SeverityMedium Severity = "medium"
	// SeverityHigh indicates a critical match that typically requires blocking.
	SeverityHigh Severity = "high"
)

// Action describes the enforcement decision for a WAF rule.
type Action string

const (
	// ActionAllow permits the content to pass while recording the detection.
	ActionAllow Action = "allow"
	// ActionBlock blocks the content when the rule matches.
	ActionBlock Action = "block"
)

// Rule declares a detection rule for the WAF engine.
type Rule struct {
	Name     string
	Pattern  string
	Severity Severity
	Action   Action
}

// Config bundles the rule set for a WAF detector.
type Config struct {
	Rules        []Rule
	ChunkSize    int
	Overlap      int
	MaxReadBytes int64
	MaxFindings  int
	Mode         string
}

// Detector evaluates text against the configured WAF rule set.
type Detector struct {
	rules []compiledRule
}

// Match represents a single detection produced by the WAF detector.
type Match struct {
	Rule     string
	Match    string
	Start    int
	End      int
	Severity Severity
	Action   Action
}

// Report summarises matches and the overall enforcement decision.
type Report struct {
	Matches []Match
	Blocked bool
}

// StreamInspector incrementally scans byte streams for WAF detections.
type StreamInspector struct {
	detector    *Detector
	chunkSize   int
	overlap     int
	maxRead     int64
	maxFindings int
	totalRead   int64
	tail        []byte
	matches     []Match
	blocked     bool
}

// ChunkSize returns the preferred chunk size for streaming inspection.
func (s *StreamInspector) ChunkSize() int {
	if s == nil {
		return defaultChunkSize
	}
	return s.chunkSize
}

// Process analyzes the provided chunk and accumulates matches.
// Callers must invoke Report after the final chunk to obtain the result summary.
func (s *StreamInspector) Process(ctx context.Context, chunk []byte) error {
	if len(chunk) == 0 {
		return nil
	}

	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	if s.maxRead > 0 && s.totalRead+int64(len(chunk)) > s.maxRead {
		return errMaxReadExceeded
	}

	searchBuf := make([]byte, 0, len(s.tail)+len(chunk))
	searchBuf = append(searchBuf, s.tail...)
	searchBuf = append(searchBuf, chunk...)

	tailLen := len(s.tail)
	baseOffset := s.totalRead - int64(tailLen)

	for _, rule := range s.detector.rules {
		indices := rule.expr.FindAllIndex(searchBuf, -1)
		for _, idx := range indices {
			// Skip matches that are entirely contained in the previous tail section.
			// This avoids reporting matches that were already reported in the previous iteration.
			if idx[0] < tailLen && idx[1] <= tailLen {
				continue
			}
			if len(s.matches) >= s.maxFindings {
				return errMaxFindingsExceeded
			}

			match := Match{
				Rule:     rule.name,
				Match:    string(searchBuf[idx[0]:idx[1]]),
				Start:    int(baseOffset) + idx[0],
				End:      int(baseOffset) + idx[1],
				Severity: rule.severity,
				Action:   rule.action,
			}
			s.matches = append(s.matches, match)
			if rule.action == ActionBlock {
				s.blocked = true
			}
		}
	}

	s.totalRead += int64(len(chunk))

	if s.overlap == 0 {
		s.tail = s.tail[:0]
		return nil
	}

	maxTail := s.overlap
	if len(searchBuf) < maxTail {
		maxTail = len(searchBuf)
	}

	if maxTail == 0 {
		s.tail = s.tail[:0]
		return nil
	}

	if cap(s.tail) < maxTail {
		s.tail = make([]byte, maxTail)
	} else {
		s.tail = s.tail[:maxTail]
	}
	copy(s.tail, searchBuf[len(searchBuf)-maxTail:])

	return nil
}

// Report returns the accumulated inspection report.
func (s *StreamInspector) Report() Report {
	report := Report{
		Matches: append([]Match(nil), s.matches...),
		Blocked: s.blocked,
	}
	return report
}

// Reset clears accumulated state so the inspector can be reused.
func (s *StreamInspector) Reset() {
	s.totalRead = 0
	s.blocked = false
	s.matches = s.matches[:0]
	if s.tail != nil {
		s.tail = s.tail[:0]
	}
}

const (
	defaultChunkSize   = 16 * 1024
	defaultOverlap     = 256
	defaultMaxFindings = 128
)

var (
	errMaxReadExceeded     = errors.New("waf: maximum inspected bytes exceeded")
	errMaxFindingsExceeded = errors.New("waf: maximum findings exceeded")
)

type compiledRule struct {
	name     string
	expr     *regexp.Regexp
	severity Severity
	action   Action
}

// NewDetector constructs a WAF detector using the provided configuration.
func NewDetector(cfg Config) (*Detector, error) {
	if len(cfg.Rules) == 0 {
		return &Detector{}, nil
	}

	compiled := make([]compiledRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			return nil, fmt.Errorf("waf: rule name is required")
		}
		pattern := strings.TrimSpace(rule.Pattern)
		if pattern == "" {
			return nil, fmt.Errorf("waf: pattern is required for rule %s", name)
		}
		severity := rule.Severity
		if severity == "" {
			severity = SeverityMedium
		}
		if !isValidSeverity(severity) {
			return nil, fmt.Errorf("waf: invalid severity %q for rule %s", severity, name)
		}
		action := rule.Action
		if action == "" {
			action = ActionBlock
		}
		if !isValidAction(action) {
			return nil, fmt.Errorf("waf: invalid action %q for rule %s", action, name)
		}
		expr, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("waf: invalid pattern for rule %s: %w", name, err)
		}
		compiled = append(compiled, compiledRule{
			name:     name,
			expr:     expr,
			severity: severity,
			action:   action,
		})
	}

	return &Detector{rules: compiled}, nil
}

// NewStreamInspector constructs a StreamInspector using detector configuration.
func NewStreamInspector(cfg Config) (*StreamInspector, error) {
	detector, err := NewDetector(cfg)
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

	maxFindings := cfg.MaxFindings
	if maxFindings <= 0 {
		maxFindings = defaultMaxFindings
	}

	inspector := &StreamInspector{
		detector:    detector,
		chunkSize:   chunkSize,
		overlap:     overlap,
		maxRead:     cfg.MaxReadBytes,
		maxFindings: maxFindings,
		tail:        make([]byte, 0, overlap),
	}

	return inspector, nil
}

// Evaluate inspects the provided text and returns a report containing matches and enforcement outcome.
func (d *Detector) Evaluate(ctx context.Context, text string) (Report, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
	}

	if len(d.rules) == 0 {
		return Report{}, nil
	}

	var matches []Match
	blocked := false

	for _, rule := range d.rules {
		indices := rule.expr.FindAllStringIndex(text, -1)
		for _, idx := range indices {
			matches = append(matches, Match{
				Rule:     rule.name,
				Match:    text[idx[0]:idx[1]],
				Start:    idx[0],
				End:      idx[1],
				Severity: rule.severity,
				Action:   rule.action,
			})
			if rule.action == ActionBlock {
				blocked = true
			}
		}
	}

	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Start == matches[j].Start {
			return matches[i].End < matches[j].End
		}
		return matches[i].Start < matches[j].Start
	})

	return Report{Matches: matches, Blocked: blocked}, nil
}

func isValidSeverity(severity Severity) bool {
	switch severity {
	case SeverityLow, SeverityMedium, SeverityHigh:
		return true
	default:
		return false
	}
}

func isValidAction(action Action) bool {
	switch action {
	case ActionAllow, ActionBlock:
		return true
	default:
		return false
	}
}
