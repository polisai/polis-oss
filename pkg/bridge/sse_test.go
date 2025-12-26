package bridge

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// **Feature: mcp-expansion, Property 1: SSE Event Round-Trip Consistency**
// **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**
func TestSSEEventRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random SSE event
		event := generateSSEEvent(t)
		
		// Serialize the event
		serialized := SerializeSSEEvent(event)
		
		// Parse it back
		parsed, err := ParseSSEEvent(serialized)
		require.NoError(t, err, "Failed to parse serialized SSE event")
		
		// Verify round-trip consistency
		assert.Equal(t, event.ID, parsed.ID, "ID field should be preserved")
		assert.Equal(t, event.Event, parsed.Event, "Event field should be preserved")
		assert.Equal(t, string(event.Data), string(parsed.Data), "Data field should be preserved")
	})
}

// generateSSEEvent creates a random SSE event for property testing
func generateSSEEvent(t *rapid.T) *SSEEvent {
	event := &SSEEvent{}
	
	// Generate optional ID field (sometimes empty)
	if rapid.Bool().Draw(t, "has_id") {
		event.ID = rapid.StringMatching(`[a-zA-Z0-9\-_]*`).Draw(t, "id")
	}
	
	// Generate optional Event field (sometimes empty)
	if rapid.Bool().Draw(t, "has_event") {
		event.Event = rapid.StringMatching(`[a-zA-Z0-9\-_]*`).Draw(t, "event_type")
	}
	
	// Generate data field - this is the most complex part
	dataType := rapid.IntRange(0, 4).Draw(t, "data_type")
	switch dataType {
	case 0:
		// Empty data
		event.Data = []byte{}
	case 1:
		// Single line data
		data := rapid.StringMatching(`[a-zA-Z0-9\s\-_.,!@#$%^&*()+={}[\]|\\:";'<>?/~` + "`" + `]*`).Draw(t, "single_line_data")
		event.Data = []byte(data)
	case 2:
		// Multi-line data
		lines := rapid.SliceOfN(rapid.StringMatching(`[a-zA-Z0-9\s\-_.,!@#$%^&*()+={}[\]|\\:";'<>?/~` + "`" + `]*`), 1, 5).Draw(t, "multi_line_data")
		event.Data = []byte(strings.Join(lines, "\n"))
	case 3:
		// JSON-like data (common in MCP)
		jsonData := `{"method":"test","params":{"key":"value"}}`
		event.Data = []byte(jsonData)
	case 4:
		// Data with special characters and unicode
		specialData := rapid.StringMatching(`[a-zA-Z0-9\s\-_.,!@#$%^&*()+={}[\]|\\:";'<>?/~` + "`" + `\n\r\t]*`).Draw(t, "special_data")
		event.Data = []byte(specialData)
	}
	
	return event
}

// Test specific edge cases that are important for SSE parsing
func TestSSEParsingEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *SSEEvent
		wantErr  bool
	}{
		{
			name:  "empty data field",
			input: "event: test\ndata: \n\n",
			expected: &SSEEvent{
				Event: "test",
				Data:  []byte(""),
			},
		},
		{
			name:  "only id field",
			input: "id: 123\n\n",
			expected: &SSEEvent{
				ID:   "123",
				Data: []byte{},
			},
		},
		{
			name:  "multi-line data",
			input: "data: line1\ndata: line2\ndata: line3\n\n",
			expected: &SSEEvent{
				Data: []byte("line1\nline2\nline3"),
			},
		},
		{
			name:  "data with special characters",
			input: "data: {\"key\": \"value with spaces and symbols!@#$%\"}\n\n",
			expected: &SSEEvent{
				Data: []byte("{\"key\": \"value with spaces and symbols!@#$%\"}"),
			},
		},
		{
			name:  "comment lines ignored",
			input: ": this is a comment\nevent: test\n: another comment\ndata: hello\n\n",
			expected: &SSEEvent{
				Event: "test",
				Data:  []byte("hello"),
			},
		},
		{
			name:  "CRLF line endings",
			input: "event: test\r\ndata: hello world\r\n\r\n",
			expected: &SSEEvent{
				Event: "test",
				Data:  []byte("hello world"),
			},
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSSEEvent([]byte(tt.input))
			
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.Event, result.Event)
			assert.Equal(t, string(tt.expected.Data), string(result.Data))
		})
	}
}

func TestSSEStreamParsing(t *testing.T) {
	// Test parsing multiple events from a stream
	streamData := `event: message
data: {"type": "hello"}

id: 123
event: update
data: line1
data: line2

data: final message

`

	reader := strings.NewReader(streamData)
	eventChan := ParseSSEStream(reader)
	
	var events []*SSEEvent
	for event := range eventChan {
		events = append(events, event)
	}
	
	require.Len(t, events, 3)
	
	// First event
	assert.Equal(t, "message", events[0].Event)
	assert.Equal(t, `{"type": "hello"}`, string(events[0].Data))
	
	// Second event
	assert.Equal(t, "123", events[1].ID)
	assert.Equal(t, "update", events[1].Event)
	assert.Equal(t, "line1\nline2", string(events[1].Data))
	
	// Third event
	assert.Equal(t, "final message", string(events[2].Data))
}

func TestSSESerialization(t *testing.T) {
	tests := []struct {
		name     string
		event    *SSEEvent
		expected string
	}{
		{
			name: "complete event",
			event: &SSEEvent{
				ID:    "123",
				Event: "message",
				Data:  []byte("hello world"),
			},
			expected: "event: message\nid: 123\ndata: hello world\n\n",
		},
		{
			name: "multi-line data",
			event: &SSEEvent{
				Data: []byte("line1\nline2\nline3"),
			},
			expected: "data: line1\ndata: line2\ndata: line3\n\n",
		},
		{
			name: "empty data",
			event: &SSEEvent{
				Event: "test",
				Data:  []byte{},
			},
			expected: "event: test\ndata: \n\n",
		},
		{
			name:     "nil event",
			event:    nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SerializeSSEEvent(tt.event)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

// Test that serialization preserves all SSE format requirements
func TestSSESerializationFormat(t *testing.T) {
	event := &SSEEvent{
		ID:    "test-id",
		Event: "test-event",
		Data:  []byte("test data\nwith newlines"),
	}
	
	serialized := SerializeSSEEvent(event)
	
	// Verify format requirements
	lines := strings.Split(string(serialized), "\n")
	
	// Should end with empty line
	assert.Equal(t, "", lines[len(lines)-1])
	
	// Should have proper field prefixes
	serializedStr := string(serialized)
	assert.Contains(t, serializedStr, "event: test-event")
	assert.Contains(t, serializedStr, "id: test-id")
	assert.Contains(t, serializedStr, "data: test data")
	assert.Contains(t, serializedStr, "data: with newlines")
}