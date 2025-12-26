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
	// Default is relaxed mode
	middleware := NewAgentIDMiddleware(nil, slog.Default())

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Relaxed mode should allow request and use "default"
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestAgentIDMiddleware_ValidHeader(t *testing.T) {
	middleware := NewAgentIDMiddleware(nil, slog.Default())

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

func TestAgentIDMiddleware_QueryParam(t *testing.T) {
	middleware := NewAgentIDMiddleware(nil, slog.Default())

	var capturedAgentID string
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID, ok := GetAgentIDFromContext(r.Context())
		if ok {
			capturedAgentID = agentID
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Test agent_id
	req1 := httptest.NewRequest(http.MethodGet, "/test?agent_id=agent-456", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if capturedAgentID != "agent-456" {
		t.Errorf("expected agent ID 'agent-456', got '%s'", capturedAgentID)
	}

	// Test agentId
	req2 := httptest.NewRequest(http.MethodGet, "/test?agentId=agent-789", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if capturedAgentID != "agent-789" {
		t.Errorf("expected agent ID 'agent-789', got '%s'", capturedAgentID)
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
}

func TestGetAgentIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), AgentIDContextKey, "test-agent")
	agentID, ok := GetAgentIDFromContext(ctx)
	if !ok || agentID != "test-agent" {
		t.Errorf("failed to extract agent ID from context")
	}

	_, ok = GetAgentIDFromContext(context.Background())
	if ok {
		t.Error("expected ok=false for empty context")
	}
}

// **Property-based tests**

func TestMultiTenantSessionIsolationProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		agentA := rapid.StringMatching(`^agent-[a-z0-9]{4}$`).Draw(t, "agentA")
		agentB := rapid.StringMatching(`^agent-[a-z0-9]{4}$`).Draw(t, "agentB")
		if agentA == agentB {
			t.Skip()
		}

		sm := NewSessionManager(nil, slog.Default())
		validator := NewSessionAccessValidator(sm, slog.Default())

		sessionA, _ := sm.CreateSession(agentA)

		// Agent B should NOT access session A
		_, err := validator.ValidateAccess(sessionA.ID, agentB)
		if err == nil {
			t.Errorf("Agent B accessed Agent A's session")
		}
	})
}

func TestStrictAuthEnforcementProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		config := &AuthConfig{
			EnforceAgentID: true,
			DefaultAgentID: "ignored",
		}
		middleware := NewAgentIDMiddleware(config, slog.Default())

		handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Strict mode failed to reject request without ID, got %d", rec.Code)
		}
	})
}

func TestRelaxedAuthFallbackProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		defaultID := rapid.StringMatching(`^def-[a-z0-9]{4}$`).Draw(t, "defaultID")
		config := &AuthConfig{
			EnforceAgentID: false,
			DefaultAgentID: defaultID,
		}
		middleware := NewAgentIDMiddleware(config, slog.Default())

		var capturedID string
		handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedID, _ = GetAgentIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Relaxed mode failed, got %d", rec.Code)
		}
		if capturedID != defaultID {
			t.Errorf("Expected default ID %s, got %s", defaultID, capturedID)
		}
	})
}
