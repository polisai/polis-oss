package dlp

import (
	"context"
	"sort"
)

// Scan applies all configured DLP rules to the supplied text.
func (s *Scanner) Scan(ctx context.Context, text string) (Report, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
	}

	if len(s.rules) == 0 {
		return Report{Findings: nil, Redacted: text}, nil
	}

	original := text
	redacted := text
	var findings []Finding
	blocked := false

	for _, rule := range s.rules {
		matches := rule.expr.FindAllStringIndex(original, -1)
		for _, match := range matches {
			findings = append(findings, Finding{
				Rule:   rule.name,
				Match:  original[match[0]:match[1]],
				Start:  match[0],
				End:    match[1],
				Action: rule.action,
			})
		}

		switch rule.action {
		case ActionRedact:
			redacted = rule.expr.ReplaceAllStringFunc(redacted, func(_ string) string {
				return rule.replacement
			})
		case ActionBlock:
			if len(matches) > 0 {
				blocked = true
			}
		case ActionAllow:
			// no-op
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Start == findings[j].Start {
			return findings[i].End < findings[j].End
		}
		return findings[i].Start < findings[j].Start
	})

	redactionsApplied := original != redacted

	return Report{
		Findings:          findings,
		Redacted:          redacted,
		RedactionsApplied: redactionsApplied,
		Blocked:           blocked,
	}, nil
}
