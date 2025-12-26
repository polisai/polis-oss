package sidecar

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestSerialization_Basic(t *testing.T) {
	input := &SSEEvent{
		ID:    "123",
		Event: "message",
		Data:  []byte(`{"json":"rpc"}`),
	}

	serialized := SerializeSSEEvent(input)
	parsed, err := ParseSSEEvent(serialized)

	assert.NoError(t, err)
	assert.Equal(t, input.ID, parsed.ID)
	assert.Equal(t, input.Event, parsed.Event)
	assert.Equal(t, string(input.Data), string(parsed.Data))
}

func TestSerialization_Multiline(t *testing.T) {
	input := &SSEEvent{
		Data: []byte("line1\nline2\nline3"),
	}

	serialized := SerializeSSEEvent(input)
	parsed, err := ParseSSEEvent(serialized)

	assert.NoError(t, err)
	assert.Equal(t, string(input.Data), string(parsed.Data))
}

// Property 12: Serialization Round-Trip
func TestSerializationProperties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := rapid.String().Draw(t, "id")
		event := rapid.String().Draw(t, "event")

		// SSE data shouldn't contain null bytes generally, but we handle text.
		// Newlines are special in SSE (data: line1\ndata: line2), so we must ensure roundtrip handles them.
		// rapid.String() can verify this.
		data := rapid.String().Draw(t, "data")

		// Limitation: ParseSSEEvent trims leading space after 'data:'.
		// If input data is " foo", typical SSE parse splits "data: foo" -> "foo" (space consumed).
		// Serialize logic: "data:  foo" -> parsers often consume one space: " foo"
		// My implementation: `if strings.HasPrefix(value, " ") { value = value[1:] }`
		// So if we serialize "foo", we write "data: foo". Parse reads "foo".
		// If we serialize " foo", we write "data:  foo". Parse reads " foo".
		// Round trip should work.

		// Constraint: Newlines in ID or Event are invalid in SSE usually.
		// Also \r in Data is normalized to \n or swalloed by Scanner, preventing exact binary round-trip.
		if strings.Contains(id, "\n") || strings.Contains(event, "\n") ||
			strings.Contains(id, "\r") || strings.Contains(event, "\r") ||
			strings.Contains(data, "\r") {
			t.Skip("Newlines/CR invalid/normalized in SSE")
		}

		retry := rapid.IntRange(0, 10000).Draw(t, "retry")

		input := &SSEEvent{
			ID:    id,
			Event: event,
			Retry: retry,
			Data:  []byte(data),
		}

		serialized := SerializeSSEEvent(input)
		parsed, err := ParseSSEEvent(serialized)

		if err != nil {
			t.Fatalf("Parse error: %v", err)
		}

		if input.ID != parsed.ID {
			t.Fatalf("ID mismatch: got %q, want %q", parsed.ID, input.ID)
		}
		if input.Event != parsed.Event {
			t.Fatalf("Event mismatch: got %q, want %q", parsed.Event, input.Event)
		}
		if string(input.Data) != string(parsed.Data) {
			t.Fatalf("Data mismatch: got %q, want %q", string(parsed.Data), string(input.Data))
		}
		if input.Retry != parsed.Retry {
			t.Fatalf("Retry mismatch: got %d, want %d", parsed.Retry, input.Retry)
		}
	})
}
