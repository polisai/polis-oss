package sidecar

import (
	"fmt"
	"sort"
	"sync"
)

// BridgeRouter routes tool execution requests to the appropriate runtime
type BridgeRouter struct {
	tools map[string]ToolConfig
	mu    sync.RWMutex

	localPM ProcessManager
	e2bPM   ProcessManager // Can be nil or a stub
}

// NewBridgeRouter creates a new router with supported process managers
func NewBridgeRouter(localPM ProcessManager, e2bPM ProcessManager) *BridgeRouter {
	return &BridgeRouter{
		tools:   make(map[string]ToolConfig),
		localPM: localPM,
		e2bPM:   e2bPM,
	}
}

// RegisterTool adds a tool configuration to the router
func (br *BridgeRouter) RegisterTool(config ToolConfig) error {
	br.mu.Lock()
	defer br.mu.Unlock()

	if config.Name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}

	br.tools[config.Name] = config
	return nil
}

// GetTool retrieves a tool configuration by name
func (br *BridgeRouter) GetTool(name string) (ToolConfig, bool) {
	br.mu.RLock()
	defer br.mu.RUnlock()

	config, ok := br.tools[name]
	return config, ok
}

// ListTools returns a list of all registered tools
func (br *BridgeRouter) ListTools() []ToolConfig {
	br.mu.RLock()
	defer br.mu.RUnlock()

	tools := make([]ToolConfig, 0, len(br.tools))
	for _, t := range br.tools {
		tools = append(tools, t)
	}

	// Sort for deterministic output
	sort.Slice(tools, func(i, j int) bool {
		return tools[i].Name < tools[j].Name
	})

	return tools
}

// Route resolves the appropriate ProcessManager and Config for a given tool
func (br *BridgeRouter) Route(name string) (ProcessManager, ToolConfig, error) {
	br.mu.RLock()
	config, ok := br.tools[name]
	br.mu.RUnlock()

	if !ok {
		return nil, ToolConfig{}, fmt.Errorf("tool not found: %s", name)
	}

	// Default to local if not specified
	runtimeType := config.Runtime.Type
	if runtimeType == "" {
		runtimeType = string(RuntimeLocal)
	}

	switch RuntimeType(runtimeType) {
	case RuntimeLocal:
		if br.localPM == nil {
			return nil, config, fmt.Errorf("local runtime not available")
		}
		return br.localPM, config, nil
	case RuntimeE2B:
		if br.e2bPM == nil {
			return nil, config, fmt.Errorf("e2b runtime not available (or not implemented)")
		}
		return br.e2bPM, config, nil
	default:
		return nil, config, fmt.Errorf("unsupported runtime type: %s", runtimeType)
	}
}
