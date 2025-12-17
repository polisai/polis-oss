package bridge

import (
	"testing"
	"time"
)

func TestRingBuffer(t *testing.T) {
	// Test basic ring buffer functionality
	buffer := NewRingBuffer(3)
	
	if buffer.Size() != 0 {
		t.Errorf("Expected empty buffer size 0, got %d", buffer.Size())
	}
	
	// Add some events
	event1 := &BufferedEvent{
		ID:        "1",
		Sequence:  1,
		Data:      []byte("event1"),
		Timestamp: time.Now(),
	}
	
	event2 := &BufferedEvent{
		ID:        "2",
		Sequence:  2,
		Data:      []byte("event2"),
		Timestamp: time.Now(),
	}
	
	buffer.Add(event1)
	buffer.Add(event2)
	
	if buffer.Size() != 2 {
		t.Errorf("Expected buffer size 2, got %d", buffer.Size())
	}
	
	// Test retrieval from sequence
	events := buffer.GetFromSequence(1)
	if len(events) != 2 {
		t.Errorf("Expected 2 events from sequence 1, got %d", len(events))
	}
	
	events = buffer.GetFromSequence(2)
	if len(events) != 1 {
		t.Errorf("Expected 1 event from sequence 2, got %d", len(events))
	}
}

func TestRingBufferEviction(t *testing.T) {
	// Test buffer eviction when capacity is exceeded
	buffer := NewRingBuffer(2)
	
	event1 := &BufferedEvent{ID: "1", Sequence: 1, Data: []byte("event1")}
	event2 := &BufferedEvent{ID: "2", Sequence: 2, Data: []byte("event2")}
	event3 := &BufferedEvent{ID: "3", Sequence: 3, Data: []byte("event3")}
	
	buffer.Add(event1)
	buffer.Add(event2)
	buffer.Add(event3) // This should evict event1
	
	if buffer.Size() != 2 {
		t.Errorf("Expected buffer size 2, got %d", buffer.Size())
	}
	
	// Should only have events 2 and 3
	events := buffer.GetFromSequence(1)
	if len(events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(events))
	}
	
	// First event should be sequence 2 (event1 was evicted)
	if events[0].Sequence != 2 {
		t.Errorf("Expected first event sequence 2, got %d", events[0].Sequence)
	}
}

func TestDefaultBridgeConfig(t *testing.T) {
	config := DefaultBridgeConfig()
	
	if config.ListenAddr != ":8090" {
		t.Errorf("Expected default listen addr :8090, got %s", config.ListenAddr)
	}
	
	if config.ShutdownTimeout != 5*time.Second {
		t.Errorf("Expected default shutdown timeout 5s, got %v", config.ShutdownTimeout)
	}
	
	if config.BufferSize != 1000 {
		t.Errorf("Expected default buffer size 1000, got %d", config.BufferSize)
	}
	
	if config.Session == nil {
		t.Error("Expected session config to be initialized")
	}
	
	if config.Session.BufferSize != 1000 {
		t.Errorf("Expected session buffer size 1000, got %d", config.Session.BufferSize)
	}
}