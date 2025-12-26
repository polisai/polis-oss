package sidecar

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockProcessManager for testing
type MockProcessManager struct {
	mock.Mock
}

func (m *MockProcessManager) Start(ctx context.Context, config ProcessConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}
func (m *MockProcessManager) Write(p []byte) error                { return nil }
func (m *MockProcessManager) ReadLoop(handler func([]byte)) error { return nil }
func (m *MockProcessManager) Stop(timeout time.Duration) error    { return nil }
func (m *MockProcessManager) IsRunning() bool                     { return false }
func (m *MockProcessManager) ExitCode() int                       { return 0 }
func (m *MockProcessManager) Type() RuntimeType                   { return RuntimeLocal }

func TestBridgeRouter_Registration(t *testing.T) {
	router := NewBridgeRouter(&MockProcessManager{}, nil)

	config := ToolConfig{
		Name:    "grep",
		Command: []string{"grep"},
	}

	err := router.RegisterTool(config)
	require.NoError(t, err)

	// Get
	retrieved, ok := router.GetTool("grep")
	require.True(t, ok)
	assert.Equal(t, "grep", retrieved.Name)

	// List
	list := router.ListTools()
	require.Len(t, list, 1)
	assert.Equal(t, "grep", list[0].Name)
}

func TestBridgeRouter_Route(t *testing.T) {
	localMock := &MockProcessManager{}
	// e2bMock := &MockProcessManager{} // simulate e2b if needed

	router := NewBridgeRouter(localMock, nil)

	// 1. Local Tool (implicit)
	router.RegisterTool(ToolConfig{
		Name:    "local-tool",
		Command: []string{"echo"},
	})

	pm, cfg, err := router.Route("local-tool")
	require.NoError(t, err)
	assert.Equal(t, localMock, pm)
	assert.Equal(t, "local-tool", cfg.Name)

	// 2. Local Tool (explicit)
	router.RegisterTool(ToolConfig{
		Name:    "explicit-local",
		Command: []string{"echo"},
		Runtime: RuntimeConfig{Type: "local"},
	})

	pm, cfg, err = router.Route("explicit-local")
	require.NoError(t, err)
	assert.Equal(t, localMock, pm)

	// 3. E2B Tool (not configured)
	router.RegisterTool(ToolConfig{
		Name:    "e2b-tool",
		Runtime: RuntimeConfig{Type: "e2b"},
	})

	_, _, err = router.Route("e2b-tool")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "e2b runtime not available")

	// 4. Unknown Tool
	_, _, err = router.Route("unknown")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tool not found")
}

func TestBridgeRouter_Route_Support(t *testing.T) {
	localMock := &MockProcessManager{}
	e2bMock := &MockProcessManager{}

	router := NewBridgeRouter(localMock, e2bMock)

	router.RegisterTool(ToolConfig{
		Name:    "e2b-tool",
		Runtime: RuntimeConfig{Type: "e2b"},
	})

	pm, _, err := router.Route("e2b-tool")
	require.NoError(t, err)
	assert.Equal(t, e2bMock, pm)
}
