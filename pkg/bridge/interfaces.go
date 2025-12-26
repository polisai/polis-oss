package bridge

import (
	"context"
	"fmt"
	"io"
	"time"
)

// ProcessManager handles child process lifecycle and communication
type ProcessManager interface {
	// Start spawns the child process with the given command and arguments
	Start(ctx context.Context, command []string, workDir string, env []string) error

	// Write sends data to the child process's stdin
	Write(data []byte) error

	// ReadLoop continuously reads from stdout and calls the handler for each message
	ReadLoop(handler func([]byte)) error

	// Stop gracefully terminates the child process within the given timeout
	Stop(timeout time.Duration) error

	// IsRunning returns true if the child process is currently running
	IsRunning() bool

	// ExitCode returns the exit code of the process (only valid after process exits)
	ExitCode() int
}

// StreamInspector parses and evaluates SSE events for policy enforcement
type StreamInspector interface {
	// ParseSSEEvent parses a single SSE event from raw bytes
	ParseSSEEvent(line []byte) (*SSEEvent, error)

	// ParseSSEStream reads SSE events from a reader and returns a channel
	ParseSSEStream(r io.Reader) <-chan *SSEEvent

	// Inspect evaluates an SSE event against configured policies
	Inspect(ctx context.Context, event *SSEEvent, toolID string) (*InspectionResult, error)

	// IsServerRequest determines if the event data contains a server-initiated JSON-RPC request
	IsServerRequest(data []byte) bool
}

// SessionManager manages persistent sessions with reconnection support
type SessionManager interface {
	// CreateSession creates a new session for the given agent
	CreateSession(agentID string) (*Session, error)

	// GetSession retrieves an existing session by ID and agent
	GetSession(sessionID, agentID string) (*Session, error)

	// ResumeSession resumes a session from a specific event ID
	ResumeSession(sessionID, agentID, lastEventID string) (*Session, uint64, error)

	// CloseSession terminates a session and cleans up resources
	CloseSession(sessionID string) error

	// Cleanup removes expired sessions
	Cleanup()

	// ListSessions returns all sessions for the given agent
	ListSessions(agentID string) ([]*Session, error)

	// GetDisconnectedSession returns an existing session for the agent that has no connected clients
	GetDisconnectedSession(agentID string) (*Session, error)
}

// SSEEvent represents a parsed Server-Sent Event
type SSEEvent struct {
	ID    string `json:"id,omitempty"`
	Event string `json:"event,omitempty"`
	Data  []byte `json:"data"`
}

// InspectionResult contains the result of inspecting an SSE event
type InspectionResult struct {
	Action       string `json:"action"`        // "allow", "block", "redact"
	Reason       string `json:"reason"`        // Human-readable reason
	ModifiedData []byte `json:"modified_data"` // Only set if action is "redact"
}

// Session represents an active MCP session
type Session struct {
	ID           string                 `json:"id"`
	AgentID      string                 `json:"agent_id"`
	ToolID       string                 `json:"tool_id,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	EventBuffer  *RingBuffer            `json:"-"`
	Clients      map[string]*SSEClient  `json:"-"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// SSEClient represents a connected SSE client
type SSEClient struct {
	ID             string
	ResponseWriter io.Writer
	LastEventID    string
	ConnectedAt    time.Time
}

// RingBuffer is a fixed-size circular buffer for event storage
type RingBuffer struct {
	events   []*BufferedEvent
	head     int
	tail     int
	size     int
	capacity int
}

// BufferedEvent stores an event with metadata for reconnection
type BufferedEvent struct {
	ID        string    `json:"id"`
	Sequence  uint64    `json:"sequence"`
	Data      []byte    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// NewRingBuffer creates a new ring buffer with the specified capacity
func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		events:   make([]*BufferedEvent, capacity),
		capacity: capacity,
	}
}

// Add inserts an event into the buffer, evicting oldest if necessary
// Returns true if an event was evicted
func (rb *RingBuffer) Add(event *BufferedEvent) bool {
	rb.events[rb.tail] = event
	rb.tail = (rb.tail + 1) % rb.capacity

	evicted := false
	if rb.size < rb.capacity {
		rb.size++
	} else {
		// Buffer is full, advance head to maintain size
		rb.head = (rb.head + 1) % rb.capacity
		evicted = true
	}

	return evicted
}

// GetFromSequence returns all events starting from the given sequence number
func (rb *RingBuffer) GetFromSequence(sequence uint64) []*BufferedEvent {
	var result []*BufferedEvent

	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.capacity
		event := rb.events[idx]
		if event != nil && event.Sequence >= sequence {
			result = append(result, event)
		}
	}

	return result
}

// Size returns the current number of events in the buffer
func (rb *RingBuffer) Size() int {
	return rb.size
}

// Resize changes the capacity of the buffer, preserving as many recent events as possible
func (rb *RingBuffer) Resize(newCapacity int) error {
	if newCapacity <= 0 {
		return fmt.Errorf("capacity must be positive")
	}

	if newCapacity == rb.capacity {
		return nil // No change needed
	}

	// Get all current events in order
	currentEvents := make([]*BufferedEvent, 0, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.capacity
		if rb.events[idx] != nil {
			currentEvents = append(currentEvents, rb.events[idx])
		}
	}

	// Create new buffer
	rb.events = make([]*BufferedEvent, newCapacity)
	rb.capacity = newCapacity
	rb.head = 0
	rb.tail = 0
	rb.size = 0

	// Add back events, keeping the most recent ones if new capacity is smaller
	startIdx := 0
	if len(currentEvents) > newCapacity {
		startIdx = len(currentEvents) - newCapacity
	}

	for i := startIdx; i < len(currentEvents); i++ {
		rb.events[rb.tail] = currentEvents[i]
		rb.tail = (rb.tail + 1) % rb.capacity
		rb.size++
	}

	return nil
}
