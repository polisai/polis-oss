package bridge

import (
	"fmt"
	"sync"
	"time"
)

// EnhancedRingBuffer is a thread-safe fixed-size circular buffer for event storage
// with proper sequence number tracking and oldest-first eviction
type EnhancedRingBuffer struct {
	events   []*BufferedEvent
	head     int    // Index of oldest element
	tail     int    // Index where next element will be inserted
	size     int    // Current number of elements
	capacity int    // Maximum capacity
	mu       sync.RWMutex
}

// NewEnhancedRingBuffer creates a new ring buffer with the specified capacity
func NewEnhancedRingBuffer(capacity int) *EnhancedRingBuffer {
	if capacity <= 0 {
		capacity = 100 // Default capacity
	}
	return &EnhancedRingBuffer{
		events:   make([]*BufferedEvent, capacity),
		capacity: capacity,
	}
}

// Add inserts an event into the buffer, evicting oldest if necessary
// Returns true if an event was evicted to make room
func (rb *EnhancedRingBuffer) Add(event *BufferedEvent) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	evicted := false

	// Store the event at tail position
	rb.events[rb.tail] = event
	rb.tail = (rb.tail + 1) % rb.capacity

	if rb.size < rb.capacity {
		rb.size++
	} else {
		// Buffer is full, advance head to evict oldest
		rb.head = (rb.head + 1) % rb.capacity
		evicted = true
	}

	return evicted
}


// GetFromSequence returns all events starting from the given sequence number
// Events are returned in order from oldest to newest
func (rb *EnhancedRingBuffer) GetFromSequence(sequence uint64) []*BufferedEvent {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

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

// GetAll returns all events in the buffer in order from oldest to newest
func (rb *EnhancedRingBuffer) GetAll() []*BufferedEvent {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]*BufferedEvent, 0, rb.size)

	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.capacity
		if rb.events[idx] != nil {
			result = append(result, rb.events[idx])
		}
	}

	return result
}

// Size returns the current number of events in the buffer
func (rb *EnhancedRingBuffer) Size() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size
}

// Capacity returns the maximum capacity of the buffer
func (rb *EnhancedRingBuffer) Capacity() int {
	return rb.capacity
}

// IsFull returns true if the buffer is at capacity
func (rb *EnhancedRingBuffer) IsFull() bool {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size == rb.capacity
}

// IsEmpty returns true if the buffer has no events
func (rb *EnhancedRingBuffer) IsEmpty() bool {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size == 0
}

// Oldest returns the oldest event in the buffer, or nil if empty
func (rb *EnhancedRingBuffer) Oldest() *BufferedEvent {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 {
		return nil
	}
	return rb.events[rb.head]
}

// Newest returns the newest event in the buffer, or nil if empty
func (rb *EnhancedRingBuffer) Newest() *BufferedEvent {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 {
		return nil
	}
	// tail points to next insertion point, so newest is at tail-1
	newestIdx := (rb.tail - 1 + rb.capacity) % rb.capacity
	return rb.events[newestIdx]
}

// Clear removes all events from the buffer
func (rb *EnhancedRingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for i := range rb.events {
		rb.events[i] = nil
	}
	rb.head = 0
	rb.tail = 0
	rb.size = 0
}

// GetByID finds an event by its ID, returns nil if not found
func (rb *EnhancedRingBuffer) GetByID(id string) *BufferedEvent {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.capacity
		if rb.events[idx] != nil && rb.events[idx].ID == id {
			return rb.events[idx]
		}
	}
	return nil
}

// GetBySequence finds an event by its sequence number, returns nil if not found
func (rb *EnhancedRingBuffer) GetBySequence(sequence uint64) *BufferedEvent {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.capacity
		if rb.events[idx] != nil && rb.events[idx].Sequence == sequence {
			return rb.events[idx]
		}
	}
	return nil
}

// RemoveOlderThan removes events older than the specified duration
// Returns the number of events removed
func (rb *EnhancedRingBuffer) RemoveOlderThan(duration time.Duration) int {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	cutoff := time.Now().Add(-duration)
	removed := 0

	// Remove from head while events are older than cutoff
	for rb.size > 0 {
		event := rb.events[rb.head]
		if event == nil || event.Timestamp.After(cutoff) {
			break
		}
		rb.events[rb.head] = nil
		rb.head = (rb.head + 1) % rb.capacity
		rb.size--
		removed++
	}

	return removed
}

// SequenceRange returns the min and max sequence numbers in the buffer
// Returns (0, 0) if buffer is empty
func (rb *EnhancedRingBuffer) SequenceRange() (min, max uint64) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 {
		return 0, 0
	}

	oldest := rb.events[rb.head]
	newestIdx := (rb.tail - 1 + rb.capacity) % rb.capacity
	newest := rb.events[newestIdx]

	if oldest != nil && newest != nil {
		return oldest.Sequence, newest.Sequence
	}
	return 0, 0
}

// Resize changes the capacity of the buffer, preserving as many recent events as possible
func (rb *EnhancedRingBuffer) Resize(newCapacity int) error {
	if newCapacity <= 0 {
		return fmt.Errorf("capacity must be positive")
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

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
