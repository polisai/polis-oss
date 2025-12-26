package bridge

import (
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// **Feature: mcp-expansion, Property 3: Session Identifier Uniqueness**
// **Validates: Requirements 5.1**
func TestSessionIdentifierUniquenessProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random number of concurrent session creations
		numSessions := rapid.IntRange(2, 100).Draw(t, "num_sessions")
		
		// Generate random agent IDs
		agentIDs := rapid.SliceOfN(
			rapid.StringMatching(`[a-zA-Z0-9\-_]{1,32}`),
			1, 10,
		).Draw(t, "agent_ids")
		
		config := &SessionConfig{
			BufferSize:     100,
			BufferDuration: 60 * time.Second,
			SessionTimeout: 300 * time.Second,
		}
		sm := NewSessionManager(config, slog.Default())
		
		// Create sessions concurrently
		var wg sync.WaitGroup
		sessionIDs := make(chan string, numSessions)
		errors := make(chan error, numSessions)
		
		for i := 0; i < numSessions; i++ {
			wg.Add(1)
			agentID := agentIDs[i%len(agentIDs)]
			go func(aid string) {
				defer wg.Done()
				session, err := sm.CreateSession(aid)
				if err != nil {
					errors <- err
					return
				}
				sessionIDs <- session.ID
			}(agentID)
		}
		
		wg.Wait()
		close(sessionIDs)
		close(errors)
		
		// Check for errors
		for err := range errors {
			t.Fatalf("Session creation failed: %v", err)
		}
		
		// Collect all session IDs and verify uniqueness
		seen := make(map[string]bool)
		for id := range sessionIDs {
			if seen[id] {
				t.Fatalf("Duplicate session ID found: %s", id)
			}
			seen[id] = true
		}
		
		// Verify we got the expected number of unique sessions
		assert.Equal(t, numSessions, len(seen), "Should have created %d unique sessions", numSessions)
	})
}


// **Feature: mcp-expansion, Property 5: Buffer Eviction Order**
// **Validates: Requirements 5.3, 5.4**
func TestBufferEvictionOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random buffer capacity between 5 and 50
		capacity := rapid.IntRange(5, 50).Draw(t, "capacity")
		
		// Generate more events than capacity to force eviction
		numEvents := rapid.IntRange(capacity+1, capacity*3).Draw(t, "num_events")
		
		buffer := NewEnhancedRingBuffer(capacity)
		
		// Add events with increasing sequence numbers
		for i := 1; i <= numEvents; i++ {
			event := &BufferedEvent{
				ID:        fmt.Sprintf("%d", i),
				Sequence:  uint64(i),
				Data:      []byte(fmt.Sprintf("event-%d", i)),
				Timestamp: time.Now(),
			}
			buffer.Add(event)
		}
		
		// Verify buffer size is at capacity
		assert.Equal(t, capacity, buffer.Size(), "Buffer should be at capacity")
		
		// Get all events and verify they are in order
		events := buffer.GetAll()
		assert.Len(t, events, capacity, "Should have exactly capacity events")
		
		// Verify events are in order from oldest to newest
		for i := 1; i < len(events); i++ {
			assert.True(t, events[i].Sequence > events[i-1].Sequence,
				"Events should be in ascending sequence order")
		}
		
		// Verify the oldest events were evicted (oldest-first eviction)
		// The remaining events should be the most recent ones
		expectedOldestSeq := uint64(numEvents - capacity + 1)
		oldest := buffer.Oldest()
		assert.NotNil(t, oldest, "Oldest should not be nil")
		assert.Equal(t, expectedOldestSeq, oldest.Sequence,
			"Oldest event should have sequence %d, got %d", expectedOldestSeq, oldest.Sequence)
		
		// Verify newest event
		newest := buffer.Newest()
		assert.NotNil(t, newest, "Newest should not be nil")
		assert.Equal(t, uint64(numEvents), newest.Sequence,
			"Newest event should have sequence %d", numEvents)
		
		// Verify sequence range
		minSeq, maxSeq := buffer.SequenceRange()
		assert.Equal(t, expectedOldestSeq, minSeq, "Min sequence should match oldest")
		assert.Equal(t, uint64(numEvents), maxSeq, "Max sequence should match newest")
	})
}

// Test that GetFromSequence returns correct events after eviction
func TestBufferGetFromSequenceAfterEviction(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		capacity := rapid.IntRange(10, 30).Draw(t, "capacity")
		numEvents := rapid.IntRange(capacity+5, capacity*2).Draw(t, "num_events")
		
		buffer := NewEnhancedRingBuffer(capacity)
		
		// Add events
		for i := 1; i <= numEvents; i++ {
			event := &BufferedEvent{
				ID:        fmt.Sprintf("%d", i),
				Sequence:  uint64(i),
				Data:      []byte(fmt.Sprintf("event-%d", i)),
				Timestamp: time.Now(),
			}
			buffer.Add(event)
		}
		
		// Pick a random sequence to query from
		minAvailableSeq := uint64(numEvents - capacity + 1)
		querySeq := rapid.Uint64Range(minAvailableSeq, uint64(numEvents)).Draw(t, "query_seq")
		
		events := buffer.GetFromSequence(querySeq)
		
		// All returned events should have sequence >= querySeq
		for _, event := range events {
			assert.GreaterOrEqual(t, event.Sequence, querySeq,
				"All events should have sequence >= query sequence")
		}
		
		// Events should be in order
		for i := 1; i < len(events); i++ {
			assert.True(t, events[i].Sequence > events[i-1].Sequence,
				"Events should be in ascending order")
		}
		
		// Expected count
		expectedCount := int(uint64(numEvents) - querySeq + 1)
		assert.Len(t, events, expectedCount, "Should return correct number of events")
	})
}


// **Feature: mcp-expansion, Property 4: Session Reconnection Consistency**
// **Validates: Requirements 5.2**
func TestSessionReconnectionConsistencyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		config := &SessionConfig{
			BufferSize:     100,
			BufferDuration: 60 * time.Second,
			SessionTimeout: 300 * time.Second,
		}
		sm := NewSessionManager(config, slog.Default())
		
		// Create a session
		agentID := rapid.StringMatching(`[a-zA-Z0-9\-_]{1,32}`).Draw(t, "agent_id")
		session, err := sm.CreateSession(agentID)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
		
		// Generate and buffer some events
		numEvents := rapid.IntRange(10, 50).Draw(t, "num_events")
		var sequences []uint64
		
		for i := 0; i < numEvents; i++ {
			data := []byte(fmt.Sprintf("event-data-%d", i))
			seq, err := sm.BufferEvent(session.ID, data)
			if err != nil {
				t.Fatalf("Failed to buffer event: %v", err)
			}
			sequences = append(sequences, seq)
		}
		
		// Pick a random point to "disconnect" and reconnect from
		disconnectIdx := rapid.IntRange(0, numEvents-1).Draw(t, "disconnect_idx")
		lastEventID := fmt.Sprintf("%d", sequences[disconnectIdx])
		
		// Resume session with Last-Event-ID
		resumedSession, fromSeq, err := sm.ResumeSession(session.ID, agentID, lastEventID)
		if err != nil {
			t.Fatalf("Failed to resume session: %v", err)
		}
		
		// Verify we got the same session
		assert.Equal(t, session.ID, resumedSession.ID, "Should resume the same session")
		
		// fromSeq should be the sequence AFTER the last acknowledged one
		expectedFromSeq := sequences[disconnectIdx] + 1
		assert.Equal(t, expectedFromSeq, fromSeq, "Should resume from sequence after last acknowledged")
		
		// Get buffered events from the resume point
		events, err := sm.GetBufferedEvents(session.ID, fromSeq)
		if err != nil {
			t.Fatalf("Failed to get buffered events: %v", err)
		}
		
		// Verify we get all events after the disconnect point
		expectedEventCount := numEvents - disconnectIdx - 1
		assert.Len(t, events, expectedEventCount, "Should get all events after disconnect point")
		
		// Verify events are in order and have correct sequences
		for i, event := range events {
			expectedSeq := sequences[disconnectIdx+1+i]
			assert.Equal(t, expectedSeq, event.Sequence, "Event sequence should match")
		}
		
		// Verify all returned events have sequence >= fromSeq
		for _, event := range events {
			assert.GreaterOrEqual(t, event.Sequence, fromSeq,
				"All events should have sequence >= fromSeq")
		}
	})
}

// Test reconnection with empty Last-Event-ID (fresh connection)
func TestSessionReconnectionFreshConnection(t *testing.T) {
	config := &SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 300 * time.Second,
	}
	sm := NewSessionManager(config, slog.Default())
	
	// Create a session and buffer some events
	session, err := sm.CreateSession("test-agent")
	assert.NoError(t, err)
	
	for i := 0; i < 10; i++ {
		_, err := sm.BufferEvent(session.ID, []byte(fmt.Sprintf("event-%d", i)))
		assert.NoError(t, err)
	}
	
	// Resume with empty Last-Event-ID (fresh connection)
	_, fromSeq, err := sm.ResumeSession(session.ID, "test-agent", "")
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), fromSeq, "Fresh connection should start from sequence 0")
	
	// Should get all events
	events, err := sm.GetBufferedEvents(session.ID, fromSeq)
	assert.NoError(t, err)
	assert.Len(t, events, 10, "Should get all buffered events")
}

// Test reconnection with invalid Last-Event-ID
func TestSessionReconnectionInvalidLastEventID(t *testing.T) {
	config := &SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 300 * time.Second,
	}
	sm := NewSessionManager(config, slog.Default())
	
	session, err := sm.CreateSession("test-agent")
	assert.NoError(t, err)
	
	// Try to resume with invalid Last-Event-ID
	_, _, err = sm.ResumeSession(session.ID, "test-agent", "invalid-id")
	assert.Error(t, err, "Should fail with invalid Last-Event-ID")
}

// Test reconnection with wrong agent ID
func TestSessionReconnectionWrongAgent(t *testing.T) {
	config := &SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 300 * time.Second,
	}
	sm := NewSessionManager(config, slog.Default())
	
	session, err := sm.CreateSession("agent-1")
	assert.NoError(t, err)
	
	// Try to resume with different agent ID
	_, _, err = sm.ResumeSession(session.ID, "agent-2", "")
	assert.Error(t, err, "Should fail with wrong agent ID")
}


// Test session timeout and cleanup
func TestSessionTimeoutAndCleanup(t *testing.T) {
	// Use a very short timeout for testing
	config := &SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 50 * time.Millisecond, // Very short timeout
	}
	sm := NewSessionManager(config, slog.Default())
	
	// Create a session
	session, err := sm.CreateSession("test-agent")
	assert.NoError(t, err)
	assert.NotNil(t, session)
	
	// Verify session exists
	assert.Equal(t, 1, sm.SessionCount())
	
	// Wait for session to expire
	time.Sleep(100 * time.Millisecond)
	
	// Run cleanup
	sm.Cleanup()
	
	// Session should be removed
	assert.Equal(t, 0, sm.SessionCount())
	
	// Trying to get the session should fail
	_, err = sm.GetSession(session.ID, "test-agent")
	assert.Error(t, err)
}

// Test that active sessions are not cleaned up
func TestActiveSessionNotCleanedUp(t *testing.T) {
	config := &SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 100 * time.Millisecond,
	}
	sm := NewSessionManager(config, slog.Default())
	
	// Create a session
	session, err := sm.CreateSession("test-agent")
	assert.NoError(t, err)
	
	// Keep the session active by updating activity
	for i := 0; i < 5; i++ {
		time.Sleep(30 * time.Millisecond)
		err := sm.UpdateActivity(session.ID)
		assert.NoError(t, err)
		sm.Cleanup()
		// Session should still exist
		assert.Equal(t, 1, sm.SessionCount())
	}
	
	// Session should still be accessible
	retrieved, err := sm.GetSession(session.ID, "test-agent")
	assert.NoError(t, err)
	assert.Equal(t, session.ID, retrieved.ID)
}

// Test cleanup routine
func TestCleanupRoutine(t *testing.T) {
	config := &SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 30 * time.Millisecond,
	}
	sm := NewSessionManager(config, slog.Default())
	
	// Create sessions
	_, err := sm.CreateSession("agent-1")
	assert.NoError(t, err)
	_, err = sm.CreateSession("agent-2")
	assert.NoError(t, err)
	
	assert.Equal(t, 2, sm.SessionCount())
	
	// Start cleanup routine
	stopCh := make(chan struct{})
	sm.StartCleanupRoutine(20*time.Millisecond, stopCh)
	
	// Wait for sessions to expire and be cleaned up
	time.Sleep(100 * time.Millisecond)
	
	// Sessions should be cleaned up
	assert.Equal(t, 0, sm.SessionCount())
	
	// Stop the cleanup routine
	close(stopCh)
}

// Test last activity tracking
func TestLastActivityTracking(t *testing.T) {
	config := &SessionConfig{
		BufferSize:     100,
		BufferDuration: 60 * time.Second,
		SessionTimeout: 300 * time.Second,
	}
	sm := NewSessionManager(config, slog.Default())
	
	session, err := sm.CreateSession("test-agent")
	assert.NoError(t, err)
	
	initialActivity := session.LastActivity
	
	// Wait a bit
	time.Sleep(10 * time.Millisecond)
	
	// Buffer an event (should update activity)
	_, err = sm.BufferEvent(session.ID, []byte("test"))
	assert.NoError(t, err)
	
	// Get session and check activity was updated
	retrieved, err := sm.GetSession(session.ID, "test-agent")
	assert.NoError(t, err)
	assert.True(t, retrieved.LastActivity.After(initialActivity))
}
