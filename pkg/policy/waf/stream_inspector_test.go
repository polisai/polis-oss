package waf

import (
	"context"
	"testing"
)

func TestStreamInspector_DetectsAcrossChunks(t *testing.T) {
	cfg := Config{
		ChunkSize: 8,
		Overlap:   4,
		Rules: []Rule{
			{
				Name:     "sql_union",
				Pattern:  `(?i)union select`,
				Severity: SeverityHigh,
				Action:   ActionBlock,
			},
		},
	}

	inspector, err := NewStreamInspector(cfg)
	if err != nil {
		t.Fatalf("failed to build inspector: %v", err)
	}

	payload := []byte("select * fr")
	if err := inspector.Process(context.Background(), payload); err != nil {
		t.Fatalf("unexpected process error: %v", err)
	}

	second := []byte("om users union select password")
	if err := inspector.Process(context.Background(), second); err != nil {
		t.Fatalf("unexpected process error: %v", err)
	}

	report := inspector.Report()
	if !report.Blocked {
		t.Fatalf("expected report to be blocked")
	}

	if len(report.Matches) == 0 {
		t.Fatalf("expected at least one match")
	}

	if report.Matches[0].Rule != "sql_union" {
		t.Errorf("unexpected rule id: %s", report.Matches[0].Rule)
	}
}
