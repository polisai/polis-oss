package bridge

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// DefaultSessionManager implements the SessionManager interface
type DefaultSessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	config   *SessionConfig
	logger   *slog.Logger
	metrics  *Metrics
	sequence uint64 // Global sequence counter for events
	seqMu    sync.Mutex
}

// NewSessionManager creates a new session manager with the given configuration
func NewSessionManager(config *SessionConfig, logger *slog.Logger) *DefaultSessionManager {
	if config == nil {
		config = &SessionConfig{
			BufferSize:     1000,
			BufferDuration: 60 * time.Second,
			SessionTimeout: 300 * time.Second,
		}
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &DefaultSessionManager{
		sessions: make(map[string]*Session),
		config:   config,
		logger:   logger,
	}
}

// SetMetrics sets the metrics instance for recording session metrics
func (sm *DefaultSessionManager) SetMetrics(metrics *Metrics) {
	sm.metrics = metrics
}

// generateSessionID generates a unique session identifier
func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}


// CreateSession creates a new session for the given agent
func (sm *DefaultSessionManager) CreateSession(agentID string) (*Session, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agent ID cannot be empty")
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:           sessionID,
		AgentID:      agentID,
		CreatedAt:    now,
		LastActivity: now,
		EventBuffer:  NewRingBuffer(sm.config.BufferSize),
		Clients:      make(map[string]*SSEClient),
		Metadata:     make(map[string]interface{}),
	}

	sm.mu.Lock()
	sm.sessions[sessionID] = session
	sm.mu.Unlock()

	sm.logger.Info("Session created",
		"session_id", sessionID,
		"agent_id", agentID,
	)

	// Record session creation metrics
	if sm.metrics != nil {
		sm.metrics.RecordSessionCreated(agentID)
	}

	return session, nil
}

// GetSession retrieves an existing session by ID and agent
func (sm *DefaultSessionManager) GetSession(sessionID, agentID string) (*Session, error) {
	sm.mu.RLock()
	session, exists := sm.sessions[sessionID]
	sm.mu.RUnlock()

	if !exists {
		return nil, &SessionNotFoundError{SessionID: sessionID}
	}

	// Verify agent ownership - return 403 Forbidden for mismatched agent ID
	if session.AgentID != agentID {
		sm.logger.Warn("Session access denied",
			"session_id", sessionID,
			"requesting_agent", agentID,
			"owner_agent", session.AgentID,
		)
		return nil, &AccessDeniedError{
			SessionID: sessionID,
			AgentID:   agentID,
			OwnerID:   session.AgentID,
		}
	}

	return session, nil
}

// ResumeSession resumes a session from a specific event ID
func (sm *DefaultSessionManager) ResumeSession(sessionID, agentID, lastEventID string) (*Session, uint64, error) {
	session, err := sm.GetSession(sessionID, agentID)
	if err != nil {
		return nil, 0, err
	}

	// Parse the last event ID to get the sequence number
	var sequence uint64
	if lastEventID != "" {
		if _, err := fmt.Sscanf(lastEventID, "%d", &sequence); err != nil {
			return nil, 0, ErrInvalidLastEventID
		}
		// We want events AFTER the last acknowledged one
		sequence++
	}

	// Update last activity
	sm.mu.Lock()
	session.LastActivity = time.Now()
	sm.mu.Unlock()

	sm.logger.Info("Session resumed",
		"session_id", sessionID,
		"agent_id", agentID,
		"from_sequence", sequence,
	)

	return session, sequence, nil
}

// CloseSession terminates a session and cleans up resources
func (sm *DefaultSessionManager) CloseSession(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Close all connected clients
	for clientID := range session.Clients {
		delete(session.Clients, clientID)
	}

	// Calculate session duration for metrics
	duration := time.Since(session.CreatedAt)

	delete(sm.sessions, sessionID)

	sm.logger.Info("Session closed", "session_id", sessionID)

	// Record session closure metrics
	if sm.metrics != nil {
		sm.metrics.RecordSessionClosed(session.AgentID, duration)
	}

	return nil
}

// Cleanup removes expired sessions
func (sm *DefaultSessionManager) Cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	expiredSessions := []string{}

	for sessionID, session := range sm.sessions {
		if now.Sub(session.LastActivity) > sm.config.SessionTimeout {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		session := sm.sessions[sessionID]
		// Close all connected clients
		for clientID := range session.Clients {
			delete(session.Clients, clientID)
		}
		delete(sm.sessions, sessionID)
		sm.logger.Info("Session expired and cleaned up", "session_id", sessionID)
	}

	if len(expiredSessions) > 0 {
		sm.logger.Info("Cleanup completed", "expired_sessions", len(expiredSessions))
	}
}

// ListSessions returns all sessions for the given agent
func (sm *DefaultSessionManager) ListSessions(agentID string) ([]*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []*Session
	for _, session := range sm.sessions {
		if session.AgentID == agentID {
			result = append(result, session)
		}
	}

	return result, nil
}


// AddClient adds a new SSE client to a session
func (sm *DefaultSessionManager) AddClient(sessionID, agentID string, writer io.Writer, lastEventID string) (*SSEClient, error) {
	session, err := sm.GetSession(sessionID, agentID)
	if err != nil {
		return nil, err
	}

	clientID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	client := &SSEClient{
		ID:             clientID,
		ResponseWriter: writer,
		LastEventID:    lastEventID,
		ConnectedAt:    time.Now(),
	}

	sm.mu.Lock()
	session.Clients[clientID] = client
	session.LastActivity = time.Now()
	sm.mu.Unlock()

	sm.logger.Debug("Client added to session",
		"session_id", sessionID,
		"client_id", clientID,
	)

	return client, nil
}

// RemoveClient removes an SSE client from a session
func (sm *DefaultSessionManager) RemoveClient(sessionID, clientID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	delete(session.Clients, clientID)
	session.LastActivity = time.Now()

	sm.logger.Debug("Client removed from session",
		"session_id", sessionID,
		"client_id", clientID,
	)

	return nil
}

// BufferEvent adds an event to the session's buffer
func (sm *DefaultSessionManager) BufferEvent(sessionID string, data []byte) (uint64, error) {
	sm.mu.RLock()
	session, exists := sm.sessions[sessionID]
	sm.mu.RUnlock()

	if !exists {
		return 0, fmt.Errorf("session not found: %s", sessionID)
	}

	// Get next sequence number
	sm.seqMu.Lock()
	sm.sequence++
	seq := sm.sequence
	sm.seqMu.Unlock()

	event := &BufferedEvent{
		ID:        fmt.Sprintf("%d", seq),
		Sequence:  seq,
		Data:      data,
		Timestamp: time.Now(),
	}

	sm.mu.Lock()
	evicted := session.EventBuffer.Add(event)
	session.LastActivity = time.Now()
	
	// Update buffer size metrics and record evictions
	if sm.metrics != nil {
		sm.metrics.UpdateBufferSize(sessionID, session.EventBuffer.Size())
		if evicted {
			sm.metrics.RecordBufferEviction(sessionID, "capacity_exceeded")
		}
	}
	
	sm.mu.Unlock()

	return seq, nil
}

// GetBufferedEvents returns events from the session buffer starting from a sequence
func (sm *DefaultSessionManager) GetBufferedEvents(sessionID string, fromSequence uint64) ([]*BufferedEvent, error) {
	sm.mu.RLock()
	session, exists := sm.sessions[sessionID]
	sm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	return session.EventBuffer.GetFromSequence(fromSequence), nil
}

// SessionCount returns the total number of active sessions
func (sm *DefaultSessionManager) SessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// UpdateActivity updates the last activity timestamp for a session
func (sm *DefaultSessionManager) UpdateActivity(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.LastActivity = time.Now()
	return nil
}

// UpdateConfig atomically updates the session manager configuration
func (sm *DefaultSessionManager) UpdateConfig(newConfig *SessionConfig) error {
	if newConfig == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	oldConfig := sm.config
	sm.config = newConfig

	// Update existing session buffers if buffer size changed
	if oldConfig.BufferSize != newConfig.BufferSize {
		for sessionID, session := range sm.sessions {
			// Resize the ring buffer
			if err := session.EventBuffer.Resize(newConfig.BufferSize); err != nil {
				sm.logger.Warn("Failed to resize session buffer",
					"session_id", sessionID,
					"error", err)
			}
		}
		sm.logger.Info("Session buffer sizes updated",
			"old_size", oldConfig.BufferSize,
			"new_size", newConfig.BufferSize)
	}

	sm.logger.Info("Session manager configuration updated",
		"buffer_size", newConfig.BufferSize,
		"buffer_duration", newConfig.BufferDuration,
		"session_timeout", newConfig.SessionTimeout)

	return nil
}

// StartCleanupRoutine starts a background goroutine that periodically cleans up expired sessions
func (sm *DefaultSessionManager) StartCleanupRoutine(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.Cleanup()
			case <-stopCh:
				sm.logger.Info("Cleanup routine stopped")
				return
			}
		}
	}()
}
