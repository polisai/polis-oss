package dlp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestStreamRedactor_RedactsAcrossChunks(t *testing.T) {
	cfg := Config{
		ChunkSize: 32,
		Overlap:   12,
		Rules: []Rule{
			{
				Name:        "email",
				Pattern:     `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`,
				Action:      ActionRedact,
				Replacement: "[REDACTED:email]",
			},
		},
	}

	redactor, err := NewStreamRedactor(cfg)
	if err != nil {
		t.Fatalf("failed to create redactor: %v", err)
	}

	input := "contact us at support@example.com for details"
	src := &chunkedReader{data: []byte(input), chunkSize: 8}
	var dst bytes.Buffer

	report, err := redactor.RedactStream(context.Background(), src, &dst)
	if err != nil {
		t.Fatalf("unexpected redaction error: %v", err)
	}

	if !report.RedactionsApplied {
		t.Fatalf("expected redactions to be applied")
	}

	got := dst.String()
	if !strings.Contains(got, "[REDACTED:email]") {
		t.Fatalf("expected redacted email, got: %s", got)
	}
}

func TestStreamRedactor_BlocksContent(t *testing.T) {
	cfg := Config{
		ChunkSize: 32,
		Overlap:   12,
		Rules: []Rule{
			{
				Name:    "ssn",
				Pattern: `123-45-6789`,
				Action:  ActionBlock,
			},
		},
	}

	redactor, err := NewStreamRedactor(cfg)
	if err != nil {
		t.Fatalf("failed to create redactor: %v", err)
	}

	src := &chunkedReader{data: []byte("sensitive: 123-45-6789 data"), chunkSize: 8}
	var dst bytes.Buffer

	report, err := redactor.RedactStream(context.Background(), src, &dst)
	if err == nil || !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected blocking error, got: %v", err)
	}

	if !report.Blocked {
		t.Fatalf("expected report.Blocked to be true")
	}

	if dst.Len() != 0 {
		t.Fatalf("expected no data to be written, got %d bytes", dst.Len())
	}
}

type chunkedReader struct {
	data      []byte
	chunkSize int
	offset    int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.offset >= len(c.data) {
		return 0, io.EOF
	}
	n := c.chunkSize
	remaining := len(c.data) - c.offset
	if n > remaining {
		n = remaining
	}
	copy(p, c.data[c.offset:c.offset+n])
	c.offset += n
	return n, nil
}
