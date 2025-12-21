package sidecar

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// MockPolicyEvaluator
type MockPolicyEvaluator struct {
	mock.Mock
}

func (m *MockPolicyEvaluator) Evaluate(ctx context.Context, input InterceptRequest) (PolicyDecision, []byte, string, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(PolicyDecision), args.Get(1).([]byte), args.String(2), args.Error(3)
}

// MockContextManager (reuses existing mock if we had exported one, or new one)
// We'll just use the real InMemoryContextManager for testing integration, or a mock if we want strict isolation.
// Using real InMemory is fine as it's logic-less mostly.

func TestInterceptorServer_HandleInterceptBefore_Allow(t *testing.T) {
	evaluator := &MockPolicyEvaluator{}
	cm := NewInMemoryContextManager()
	server := NewInterceptorServer(evaluator, cm)

	ctx := context.Background()
	reqID, _ := cm.Create(ctx)

	req := InterceptRequest{
		Body:      []byte(`{"method":"ping"}`),
		RequestID: reqID,
	}

	evaluator.On("Evaluate", ctx, req).Return(DecisionAllow, req.Body, "", nil)

	resp, err := server.HandleInterceptBefore(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Action)
	assert.Equal(t, req.Body, resp.Body)

	// Verify context updated
	c, ok := cm.Get(reqID)
	require.True(t, ok)
	assert.Equal(t, DecisionAllow, c.PolicyDecision)
}

func TestInterceptorServer_HandleInterceptBefore_Block(t *testing.T) {
	evaluator := &MockPolicyEvaluator{}
	cm := NewInMemoryContextManager()
	server := NewInterceptorServer(evaluator, cm)

	ctx := context.Background()
	req := InterceptRequest{Body: []byte(`{"method":"danger"}`)}

	evaluator.On("Evaluate", ctx, req).Return(DecisionBlock, []byte(nil), "unsafe method", nil)

	resp, err := server.HandleInterceptBefore(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, DecisionBlock, resp.Action)
	assert.Equal(t, "unsafe method", resp.Message)
}

func TestInterceptorServer_HandleInterceptBefore_Error(t *testing.T) {
	evaluator := &MockPolicyEvaluator{}
	cm := NewInMemoryContextManager()
	server := NewInterceptorServer(evaluator, cm)

	ctx := context.Background()
	req := InterceptRequest{Body: []byte(`{}`)}

	evaluator.On("Evaluate", ctx, req).Return(DecisionBlock, []byte(nil), "", errors.New("engine failure"))

	resp, err := server.HandleInterceptBefore(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, DecisionBlock, resp.Action)
	assert.Contains(t, resp.Message, "Policy evaluation failed")
}

// Property Test: Intercept consistency
func TestInterceptorServerProperties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// We want to verify that Evaluate outputs are mapped correctly to Response

		decisionStr := rapid.SampledFrom([]string{"allow", "block", "redact"}).Draw(t, "decision")
		decision := PolicyDecision(decisionStr)

		body := rapid.SliceOf(rapid.Byte()).Draw(t, "body")
		msg := rapid.String().Draw(t, "message")

		// Mock evaluator response
		evaluator := &MockPolicyEvaluator{}
		cm := NewInMemoryContextManager()
		server := NewInterceptorServer(evaluator, cm)

		req := InterceptRequest{Body: body, RequestID: "test-id"} // ID doesn't need to exist for property test mechanics if we don't check CM

		// For property test we need mock to return what we drew
		evaluator.On("Evaluate", mock.Anything, req).Return(decision, body, msg, nil)

		resp, err := server.HandleInterceptBefore(context.Background(), req)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if resp.Action != decision {
			t.Errorf("Expected action %v, got %v", decision, resp.Action)
		}
		if string(resp.Body) != string(body) {
			t.Errorf("Body mismatch")
		}
		if resp.Message != msg {
			t.Errorf("Message mismatch")
		}
	})
}
