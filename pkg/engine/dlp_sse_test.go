package engine

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/polisai/polis-oss/pkg/policy/dlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFlushWriter is a helper to mock http.ResponseWriter for tests
type mockFlushWriter struct {
	*bytes.Buffer
}

func (m *mockFlushWriter) Header() http.Header        { return http.Header{} }
func (m *mockFlushWriter) WriteHeader(statusCode int) {}
func (m *mockFlushWriter) Flush()                     {}

func TestRedactSSEStreamWithMatches(t *testing.T) {
	// Setup
	cfg := dlp.Config{
		Rules: []dlp.Rule{
			{
				Name:        "email",
				Pattern:     `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
				Action:      dlp.ActionRedact,
				Replacement: "[REDACTED]",
			},
		},
		Mode: "stream",
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single data line with match",
			input:    "data: hello user@example.com\n\n",
			expected: "data: hello [REDACTED]\n\n",
		},
		{
			name:     "multiple lines, some with matches",
			input:    "id: 1\ndata: first event\n\ndata: second event user@example.com\n\n",
			expected: "id: 1\ndata: first event\n\ndata: second event [REDACTED]\n\n",
		},
		{
			name:     "mixed fields",
			input:    "event: update\ndata: {\"email\": \"foo@bar.com\"}\n\n",
			expected: "event: update\ndata: {\"email\": \"[REDACTED]\"}\n\n",
		},
		{
			name:     "leading space in data",
			input:    "data:  user@example.com\n\n",
			expected: "data:  [REDACTED]\n\n",
		},
		{
			name:     "no leading space in data",
			input:    "data:user@example.com\n\n",
			expected: "data:[REDACTED]\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := strings.NewReader(tt.input)

			var outBuf bytes.Buffer
			mockWriter := &mockFlushWriter{
				Buffer: &outBuf,
			}

			// flushCountingWriter is internal to engine package, so we can access it here
			cw := &flushCountingWriter{ResponseWriter: mockWriter}

			report, err := redactSSEStream(context.Background(), src, cw, cfg)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, outBuf.String())
			assert.True(t, report.RedactionsApplied, "Expected redactions to apply")
		})
	}
}

func TestRedactSSEStreamNoMatches(t *testing.T) {
	cfg := dlp.Config{
		Rules: []dlp.Rule{
			{
				Name:        "email",
				Pattern:     `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
				Action:      dlp.ActionRedact,
				Replacement: "[REDACTED]",
			},
		},
		Mode: "stream",
	}

	input := "data: hello world\n\n"
	src := strings.NewReader(input)

	var outBuf bytes.Buffer
	mockWriter := &mockFlushWriter{Buffer: &outBuf}
	cw := &flushCountingWriter{ResponseWriter: mockWriter}

	report, err := redactSSEStream(context.Background(), src, cw, cfg)
	require.NoError(t, err)
	assert.Equal(t, input, outBuf.String())
	assert.False(t, report.RedactionsApplied)
}
