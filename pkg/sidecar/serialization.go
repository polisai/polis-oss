package sidecar

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// SSEEvent represents a standard Server-Sent Event
type SSEEvent struct {
	ID    string
	Event string
	Data  []byte
	Retry int
}

// ParseSSEEvent parses a raw byte slice into an SSEEvent
// It handles standard SSE format (data: ..., event: ..., id: ...)
func ParseSSEEvent(raw []byte) (*SSEEvent, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	event := &SSEEvent{}
	var dataBuffer bytes.Buffer
	hasData := false

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue // End of event usually marked by empty line in stream, but here we parse single event block?
			// Actually, ParseSSEEvent usually takes a chunk.
			// If raw is "data: foo\n\n", scanner handles lines.
		}

		if strings.HasPrefix(line, ":") {
			// Comment, ignore
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		field := parts[0]
		value := ""
		if len(parts) > 1 {
			value = parts[1]
			if strings.HasPrefix(value, " ") {
				value = value[1:]
			}
		}

		switch field {
		case "id":
			event.ID = value
		case "event":
			event.Event = value
		case "data":
			// If multiple data lines, append with newline
			if hasData {
				dataBuffer.WriteString("\n")
			}
			dataBuffer.WriteString(value)
			hasData = true
		case "retry":
			if i, err := strconv.Atoi(value); err == nil {
				event.Retry = i
			}
		}
	}

	event.Data = dataBuffer.Bytes()
	return event, nil
}

// IsJSONRPC checks if the data looks like a JSON-RPC message
func IsJSONRPC(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	// Quick heuristic: starts with { and contains "jsonrpc"
	// Or just starts with {
	if !bytes.HasPrefix(trimmed, []byte("{")) {
		return false
	}
	return bytes.Contains(trimmed, []byte(`"jsonrpc"`))
}

// SerializeSSEEvent converts an SSEEvent back to wire format
func SerializeSSEEvent(e *SSEEvent) []byte {
	var buf bytes.Buffer

	if e.ID != "" {
		fmt.Fprintf(&buf, "id: %s\n", e.ID)
	}
	if e.Event != "" {
		fmt.Fprintf(&buf, "event: %s\n", e.Event)
	}
	if e.Retry > 0 {
		fmt.Fprintf(&buf, "retry: %d\n", e.Retry)
	}

	// Handle multi-line data using Split to preserve trailing newlines
	if len(e.Data) > 0 {
		lines := strings.Split(string(e.Data), "\n")
		for _, line := range lines {
			fmt.Fprintf(&buf, "data: %s\n", line)
		}
	}

	// Ensure we handle case where Data is empty string vs empty byte slice?
	// Spec says: data: <content>
	// If e.Data is empty, we might skip it or send "data: \n"

	// Standard SSE terminator
	buf.WriteString("\n")

	return buf.Bytes()
}
