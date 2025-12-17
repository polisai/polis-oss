package bridge

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// ParseSSEEvent parses a single SSE event from raw bytes
// The input should contain a complete SSE event (ending with double newline)
func ParseSSEEvent(data []byte) (*SSEEvent, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty SSE event data")
	}

	event := &SSEEvent{}
	// Convert to string and handle CRLF normalization carefully
	input := string(data)
	
	// Only normalize CRLF if the entire input appears to use CRLF line endings consistently
	// This is detected by checking if the input ends with \r\n\r\n (CRLF event terminator)
	// or if all SSE field lines end with \r\n
	
	lines := strings.Split(input, "\n")
	
	// Detect CRLF pattern: input should end with \r\n\r\n or all SSE field lines should end with \r
	hasCRLFPattern := false
	if strings.HasSuffix(input, "\r\n\r\n") || strings.HasSuffix(input, "\r\n") {
		// Count SSE field lines that end with \r vs those that don't
		sseFieldLinesWithR := 0
		sseFieldLinesWithoutR := 0
		
		for _, line := range lines {
			trimmed := strings.TrimSuffix(line, "\r")
			// Check if this is an SSE field line (not data content)
			if trimmed == "" || 
			   strings.HasPrefix(trimmed, "event:") || 
			   strings.HasPrefix(trimmed, "data:") || 
			   strings.HasPrefix(trimmed, "id:") || 
			   strings.HasPrefix(trimmed, ":") {
				if strings.HasSuffix(line, "\r") {
					sseFieldLinesWithR++
				} else if line != "" {
					sseFieldLinesWithoutR++
				}
			}
		}
		
		// If all or most SSE field lines end with \r, treat as CRLF input
		hasCRLFPattern = sseFieldLinesWithR > 0 && sseFieldLinesWithR >= sseFieldLinesWithoutR
	}
	
	var dataLines []string
	
	for _, line := range lines {
		// Handle CRLF line endings - remove trailing \r only from empty lines
		// and lines that start with SSE field prefixes
		if line == "\r" || line == "" {
			// Empty line indicates end of event
			continue
		}
		
		// Handle CRLF normalization very conservatively
		// Only remove \r if we detected a clear CRLF pattern AND this is an SSE field line
		cleanLine := line
		if hasCRLFPattern && strings.HasSuffix(line, "\r") {
			trimmed := strings.TrimSuffix(line, "\r")
			// Only remove \r from SSE field lines, never from data content
			if trimmed == "" || 
			   strings.HasPrefix(trimmed, "event:") || 
			   strings.HasPrefix(trimmed, "id:") || 
			   strings.HasPrefix(trimmed, ":") {
				cleanLine = trimmed
			}
			// For data lines, we need to be more careful - only remove \r if it's clearly a line ending
		}
		
		if strings.HasPrefix(cleanLine, "event:") {
			// Remove only a single space after colon, as per SSE spec
			content := cleanLine[6:]
			if len(content) > 0 && content[0] == ' ' {
				content = content[1:]
			}
			event.Event = content
		} else if strings.HasPrefix(cleanLine, "data:") {
			// Remove only a single space after colon, as per SSE spec
			content := cleanLine[5:]
			if len(content) > 0 && content[0] == ' ' {
				content = content[1:]
			}
			// For data lines, only remove trailing \r if we detected CRLF pattern AND
			// the original line ended with \r (meaning it was a CRLF line ending, not content)
			if hasCRLFPattern && strings.HasSuffix(line, "\r") && strings.HasSuffix(content, "\r") {
				content = strings.TrimSuffix(content, "\r")
			}
			dataLines = append(dataLines, content)
		} else if strings.HasPrefix(cleanLine, "id:") {
			// Remove only a single space after colon, as per SSE spec
			content := cleanLine[3:]
			if len(content) > 0 && content[0] == ' ' {
				content = content[1:]
			}
			event.ID = content
		} else if strings.HasPrefix(cleanLine, ":") {
			// Comment line, ignore
			continue
		}
		// Ignore unrecognized fields as per SSE spec
	}
	
	// Join data lines with newlines to preserve multi-line data
	if len(dataLines) > 0 {
		event.Data = []byte(strings.Join(dataLines, "\n"))
	}
	
	return event, nil
}

// ParseSSEStream reads SSE events from a reader and returns a channel
// The channel will be closed when the reader reaches EOF or an error occurs
func ParseSSEStream(r io.Reader) <-chan *SSEEvent {
	events := make(chan *SSEEvent, 10) // Buffered channel to prevent blocking
	
	go func() {
		defer close(events)
		
		scanner := bufio.NewScanner(r)
		var eventBuffer bytes.Buffer
		
		for scanner.Scan() {
			line := scanner.Text()
			
			// Add line to buffer
			eventBuffer.WriteString(line)
			eventBuffer.WriteString("\n")
			
			// Check if this is an empty line (end of event)
			if strings.TrimSpace(line) == "" {
				// Parse the complete event
				if eventBuffer.Len() > 1 { // More than just the empty line
					eventData := eventBuffer.Bytes()
					if event, err := ParseSSEEvent(eventData); err == nil {
						// Only send events that have some content
						if len(event.Data) > 0 || event.Event != "" || event.ID != "" {
							events <- event
						}
					}
					// Reset buffer for next event
					eventBuffer.Reset()
				}
			}
		}
		
		// Handle any remaining data in buffer (stream ended without empty line)
		if eventBuffer.Len() > 0 {
			eventData := eventBuffer.Bytes()
			if event, err := ParseSSEEvent(eventData); err == nil {
				if len(event.Data) > 0 || event.Event != "" || event.ID != "" {
					events <- event
				}
			}
		}
	}()
	
	return events
}

// SerializeSSEEvent converts an SSEEvent back to SSE format
func SerializeSSEEvent(event *SSEEvent) []byte {
	if event == nil {
		return []byte{}
	}
	
	var buffer bytes.Buffer
	
	// Write event field if present
	if event.Event != "" {
		buffer.WriteString("event: ")
		buffer.WriteString(event.Event)
		buffer.WriteString("\n")
	}
	
	// Write id field if present
	if event.ID != "" {
		buffer.WriteString("id: ")
		buffer.WriteString(event.ID)
		buffer.WriteString("\n")
	}
	
	// Write data field - handle multi-line data correctly
	if len(event.Data) > 0 {
		dataStr := string(event.Data)
		// Split on \n but preserve any \r characters that were part of the original data
		dataLines := strings.Split(dataStr, "\n")
		
		for _, dataLine := range dataLines {
			buffer.WriteString("data: ")
			buffer.WriteString(dataLine)
			buffer.WriteString("\n")
		}
	} else {
		// Even if data is empty, we need at least one data line for valid SSE
		buffer.WriteString("data: \n")
	}
	
	// End event with empty line
	buffer.WriteString("\n")
	
	return buffer.Bytes()
}