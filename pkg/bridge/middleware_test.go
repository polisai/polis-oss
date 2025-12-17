package bridge

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"pgregory.net/rapid"
)

func TestAgentIDMiddleware_MissingHeader(t *testing.T) {
	middleware := NewAgentIDMiddleware(slog.Default())
	
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	
	handler.ServeHTTP(rec, req)
	
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAgentIDMiddleware_ValidHeader(t *testing.T) {
	middleware := NewAgentIDMiddleware(slog.Default())
	
	var capturedAgentID string
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID, ok := GetAgentIDFromContext(r.Context())
		if ok {
			capturedAgentID = agentID
		}
		w.WriteHeader(http.StatusOK)
	}))
	
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(AgentIDHeader, "agent-123")
	rec := httptest.NewRecorder()
	
	handler.ServeHTTP(rec, req)
	
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	
	if capturedAgentID != "agent-123" {
		t.Errorf("expected agent ID 'agent-123', got '%s'", capturedAgentID)
	}
}

func TestValidateAgentID_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	
	_, err := ValidateAgentID(req)
	if err == nil {
		t.Error("expected error for missing agent ID")
	}
	
	mtErr, ok := err.(*MultiTenantError)
	if !ok {
		t.Fatalf("expected MultiTenantError, got %T", err)
	}
	
	if mtErr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, mtErr.Code)
	}
}

func TestValidateAgentID_Present(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(AgentIDHeader, "agent-456")
	
	agentID, err := ValidateAgentID(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	
	if agentID != "agent-456" {
		t.Errorf("expected agent ID 'agent-456', got '%s'", agentID)
	}
}

func TestSessionAccessValidator_ValidAccess(t *testing.T) {
	sm := NewSessionManager(nil, slog.Default())
	validator := NewSessionAccessValidator(sm, slog.Default())
	
	// Create a session
	session, err := sm.CreateSession("agent-1")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	// Validate access with correct agent
	retrieved, err := validator.ValidateAccess(session.ID, "agent-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	
	if retrieved.ID != session.ID {
		t.Errorf("expected session ID %s, got %s", session.ID, retrieved.ID)
	}
}

func TestSessionAccessValidator_WrongAgent(t *testing.T) {
	sm := NewSessionManager(nil, slog.Default())
	validator := NewSessionAccessValidator(sm, slog.Default())
	
	// Create a session for agent-1
	session, err := sm.CreateSession("agent-1")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	// Try to access with agent-2
	_, err = validator.ValidateAccess(session.ID, "agent-2")
	if err == nil {
		t.Error("expected error for wrong agent")
	}
	
	mtErr, ok := err.(*MultiTenantError)
	if !ok {
		t.Fatalf("expected MultiTenantError, got %T", err)
	}
	
	if mtErr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, mtErr.Code)
	}
}

func TestSessionAccessValidator_SessionNotFound(t *testing.T) {
	sm := NewSessionManager(nil, slog.Default())
	validator := NewSessionAccessValidator(sm, slog.Default())
	
	_, err := validator.ValidateAccess("nonexistent-session", "agent-1")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
	
	mtErr, ok := err.(*MultiTenantError)
	if !ok {
		t.Fatalf("expected MultiTenantError, got %T", err)
	}
	
	if mtErr.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, mtErr.Code)
	}
}

func TestSessionAccessValidator_MissingAgentID(t *testing.T) {
	sm := NewSessionManager(nil, slog.Default())
	validator := NewSessionAccessValidator(sm, slog.Default())
	
	_, err := validator.ValidateAccess("some-session", "")
	if err == nil {
		t.Error("expected error for missing agent ID")
	}
	
	mtErr, ok := err.(*MultiTenantError)
	if !ok {
		t.Fatalf("expected MultiTenantError, got %T", err)
	}
	
	if mtErr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, mtErr.Code)
	}
}

func TestListSessionsForAgent_Filtered(t *testing.T) {
	sm := NewSessionManager(nil, slog.Default())
	validator := NewSessionAccessValidator(sm, slog.Default())
	
	// Create sessions for different agents
	_, err := sm.CreateSession("agent-1")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	_, err = sm.CreateSession("agent-1")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	_, err = sm.CreateSession("agent-2")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	// List sessions for agent-1
	sessions, err := validator.ListSessionsForAgent("agent-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions for agent-1, got %d", len(sessions))
	}
	
	for _, s := range sessions {
		if s.AgentID != "agent-1" {
			t.Errorf("expected agent ID 'agent-1', got '%s'", s.AgentID)
		}
	}
	
	// List sessions for agent-2
	sessions, err = validator.ListSessionsForAgent("agent-2")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	
	if len(sessions) != 1 {
		t.Errorf("expected 1 session for agent-2, got %d", len(sessions))
	}
}

func TestGetAgentIDFromContext_NotSet(t *testing.T) {
	ctx := context.Background()
	_, ok := GetAgentIDFromContext(ctx)
	if ok {
		t.Error("expected ok to be false for context without agent ID")
	}
}

func TestGetAgentIDFromContext_Set(t *testing.T) {
	ctx := context.WithValue(context.Background(), AgentIDContextKey, "test-agent")
	agentID, ok := GetAgentIDFromContext(ctx)
	if !ok {
		t.Error("expected ok to be true for context with agent ID")
	}
	if agentID != "test-agent" {
		t.Errorf("expected 'test-agent', got '%s'", agentID)
	}
}


// **Feature: mcp-expansion, Property 6: Multi-Tenant Session Isolation**
// For any two agents with different identifiers, agent A SHALL NOT be able to access,
// list, or modify sessions owned by agent B, and vice versa.
func TestMultiTenantSessionIsolationProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate two distinct agent IDs
		agentA := rapid.StringMatching(`^agent-[a-z0-9]{4,8}$`).Draw(t, "agentA")
		agentB := rapid.StringMatching(`^agent-[a-z0-9]{4,8}$`).Draw(t, "agentB")
		
		// Ensure agents are different
		if agentA == agentB {
			agentB = agentB + "-different"
		}
		
		sm := NewSessionManager(nil, slog.Default())
		validator := NewSessionAccessValidator(sm, slog.Default())
		
		// Create sessions for agent A
		numSessionsA := rapid.IntRange(1, 5).Draw(t, "numSessionsA")
		sessionsA := make([]*Session, 0, numSessionsA)
		for i := 0; i < numSessionsA; i++ {
			session, err := sm.CreateSession(agentA)
			if err != nil {
				t.Fatalf("failed to create session for agent A: %v", err)
			}
			sessionsA = append(sessionsA, session)
		}
		
		// Create sessions for agent B
		numSessionsB := rapid.IntRange(1, 5).Draw(t, "numSessionsB")
		sessionsB := make([]*Session, 0, numSessionsB)
		for i := 0; i < numSessionsB; i++ {
			session, err := sm.CreateSession(agentB)
			if err != nil {
				t.Fatalf("failed to create session for agent B: %v", err)
			}
			sessionsB = append(sessionsB, session)
		}
		
		// Property 1: Agent A cannot access Agent B's sessions
		for _, sessionB := range sessionsB {
			_, err := validator.ValidateAccess(sessionB.ID, agentA)
			if err == nil {
				t.Errorf("agent A should not be able to access agent B's session %s", sessionB.ID)
			}
			mtErr, ok := err.(*MultiTenantError)
			if !ok {
				t.Errorf("expected MultiTenantError, got %T", err)
			} else if mtErr.Code != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden, got %d", mtErr.Code)
			}
		}
		
		// Property 2: Agent B cannot access Agent A's sessions
		for _, sessionA := range sessionsA {
			_, err := validator.ValidateAccess(sessionA.ID, agentB)
			if err == nil {
				t.Errorf("agent B should not be able to access agent A's session %s", sessionA.ID)
			}
			mtErr, ok := err.(*MultiTenantError)
			if !ok {
				t.Errorf("expected MultiTenantError, got %T", err)
			} else if mtErr.Code != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden, got %d", mtErr.Code)
			}
		}
		
		// Property 3: Agent A can only see their own sessions in listing
		listedA, err := validator.ListSessionsForAgent(agentA)
		if err != nil {
			t.Fatalf("failed to list sessions for agent A: %v", err)
		}
		if len(listedA) != numSessionsA {
			t.Errorf("agent A should see %d sessions, got %d", numSessionsA, len(listedA))
		}
		for _, s := range listedA {
			if s.AgentID != agentA {
				t.Errorf("agent A's listing contains session owned by %s", s.AgentID)
			}
		}
		
		// Property 4: Agent B can only see their own sessions in listing
		listedB, err := validator.ListSessionsForAgent(agentB)
		if err != nil {
			t.Fatalf("failed to list sessions for agent B: %v", err)
		}
		if len(listedB) != numSessionsB {
			t.Errorf("agent B should see %d sessions, got %d", numSessionsB, len(listedB))
		}
		for _, s := range listedB {
			if s.AgentID != agentB {
				t.Errorf("agent B's listing contains session owned by %s", s.AgentID)
			}
		}
		
		// Property 5: Agent A can access their own sessions
		for _, sessionA := range sessionsA {
			retrieved, err := validator.ValidateAccess(sessionA.ID, agentA)
			if err != nil {
				t.Errorf("agent A should be able to access their own session: %v", err)
			}
			if retrieved.ID != sessionA.ID {
				t.Errorf("retrieved session ID mismatch: expected %s, got %s", sessionA.ID, retrieved.ID)
			}
		}
		
		// Property 6: Agent B can access their own sessions
		for _, sessionB := range sessionsB {
			retrieved, err := validator.ValidateAccess(sessionB.ID, agentB)
			if err != nil {
				t.Errorf("agent B should be able to access their own session: %v", err)
			}
			if retrieved.ID != sessionB.ID {
				t.Errorf("retrieved session ID mismatch: expected %s, got %s", sessionB.ID, retrieved.ID)
			}
		}
	})
}

// Test that requests without X-Agent-ID header are rejected with 401
func TestMissingAgentIDReturns401Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random paths and methods
		path := rapid.StringMatching(`^/[a-z]{1,10}(/[a-z]{1,10})?$`).Draw(t, "path")
		methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}
		method := methods[rapid.IntRange(0, len(methods)-1).Draw(t, "methodIdx")]
		
		middleware := NewAgentIDMiddleware(slog.Default())
		
		handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		
		req := httptest.NewRequest(method, path, nil)
		// Explicitly NOT setting X-Agent-ID header
		rec := httptest.NewRecorder()
		
		handler.ServeHTTP(rec, req)
		
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for request without X-Agent-ID, got %d", rec.Code)
		}
	})
}

// Test that requests with X-Agent-ID header pass through
func TestValidAgentIDPassesThroughProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		agentID := rapid.StringMatching(`^[a-zA-Z0-9_-]{1,32}$`).Draw(t, "agentID")
		path := rapid.StringMatching(`^/[a-z]{1,10}$`).Draw(t, "path")
		
		middleware := NewAgentIDMiddleware(slog.Default())
		
		var capturedAgentID string
		handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := GetAgentIDFromContext(r.Context())
			if ok {
				capturedAgentID = id
			}
			w.WriteHeader(http.StatusOK)
		}))
		
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set(AgentIDHeader, agentID)
		rec := httptest.NewRecorder()
		
		handler.ServeHTTP(rec, req)
		
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for request with X-Agent-ID, got %d", rec.Code)
		}
		
		if capturedAgentID != agentID {
			t.Errorf("agent ID not correctly passed through context: expected %s, got %s", agentID, capturedAgentID)
		}
	})
}
