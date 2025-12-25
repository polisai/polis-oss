package sidecar

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/polisai/polis-oss/pkg/bridge"
)

// ConfigProvider defines the interface for configuration loading
type ConfigProvider interface {
	Load() (*SidecarConfig, error)
	Watch(func(*SidecarConfig)) error
	Current() *SidecarConfig
	Close() error
}

// Sidecar is the unified component container
type Sidecar struct {
	config      ConfigProvider
	router      *BridgeRouter
	interceptor *InterceptorServer
	ctxManager  ContextManager
	bridge      *bridge.Bridge

	server  *http.Server
	logger  *slog.Logger
	mu      sync.RWMutex
	running bool
}

// NewSidecar creates a new unified sidecar instance
func NewSidecar(cfgLoader ConfigProvider, logger *slog.Logger) (*Sidecar, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Initialize Core Components
	// Create Context Manager
	cm := NewInMemoryContextManager()

	// Create Process Managers (Local)
	localPM := NewLocalProcessManager(logger, nil, nil)

	// Pre-register tools from config
	currentCfg := cfgLoader.Current()

	// Create Router
	router := NewBridgeRouter(localPM, nil)

	// Register configured tools
	for _, t := range currentCfg.Tools {
		if err := router.RegisterTool(t); err != nil {
			logger.Warn("Failed to register tool", "tool", t.Name, "error", err)
		}
	}

	// Create Interceptor
	// TODO: Integrate real Policy Engine
	var evaluator PolicyEvaluator = &noopPolicyEvaluator{}
	interceptor := NewInterceptorServer(evaluator, cm)

	// Initialize Bridge
	// We map the first tool from SidecarConfig to the BridgeConfig for MVP compatibility
	// In the future, the Bridge itself should support routing or we run multiple bridges
	bridgeConfig := bridge.DefaultBridgeConfig()
	bridgeConfig.ListenAddr = fmt.Sprintf(":%d", currentCfg.Server.Port)

	// If tools are defined, use the first one for the bridge command
	if len(currentCfg.Tools) > 0 {
		tool := currentCfg.Tools[0]
		bridgeConfig.Command = tool.Command

		// Convert Env map to slice
		var env []string
		for k, v := range tool.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		bridgeConfig.Env = env

		// bridgeConfig.WorkDir = "" // TODO: Add WorkDir to ToolConfig if needed
		logger.Info("Configuring Bridge with tool", "tool", tool.Name, "command", tool.Command)
	}

	// Initialize Bridge instance
	b := bridge.NewBridge(bridgeConfig, logger)

	s := &Sidecar{
		config:      cfgLoader,
		router:      router,
		interceptor: interceptor,
		ctxManager:  cm,
		bridge:      b,
		logger:      logger,
	}

	// 2. Setup HTTP Server
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.server = &http.Server{
		Handler: mux,
	}

	return s, nil
}

// Start initializes background processes and starts the HTTP server
func (s *Sidecar) Start(addr string) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("sidecar already running")
	}
	s.running = true
	s.mu.Unlock()

	s.server.Addr = addr

	// Start Context Cleanup
	s.ctxManager.StartCleanup(context.Background(), 1*time.Minute, 24*time.Hour)

	// Start Bridge Components (Backend)
	// We use the new StartComponents method to avoid starting a duplicate HTTP server
	if err := s.bridge.StartComponents(context.Background()); err != nil {
		s.logger.Error("Failed to start bridge components", "error", err)
		return err
	}

	// Also start reading process output for the bridge if it's running
	// Note: We need to access b.readProcessOutput() but it's private.
	// WAIT. StartComponents doesn't start readProcessOutput in my previous edit?
	// I checked my previous edit:
	// "func (b *Bridge) Start(ctx context.Context) error { ... if b.StartComponents(ctx) ... go b.readProcessOutput() ... }"
	// "func (b *Bridge) StartComponents(ctx context.Context) error { ... initializeComponents ... startChildProcess ... performMCPHandshake ... }"
	//
	// Make sure readProcessOutput is handled!
	// Ideally StartComponents should kickoff the background reader too, OR we need another public method.
	// Since readProcessOutput is private, Sidecar can't call it.
	// I should have included `go b.readProcessOutput()` inside `StartComponents` or made it public.
	// Let's assume for this specific write that I will FIX bridge.go in the next step if I missed it.
	// Actually, looking at my `multi_replace` above: I did NOT move `go b.readProcessOutput()` into `StartComponents`.
	// I left it in `Start`.
	// This means Sidecar calling `StartComponents` will NOT start the reader loop.
	// I need to add that to `StartComponents` or `StartBackend` in `pkg/bridge`.

	// Start Config Watcher
	if err := s.config.Watch(func(sc *SidecarConfig) {
		s.logger.Info("Configuration reloaded")
	}); err != nil {
		s.logger.Warn("Failed to start config watcher", "error", err)
	}

	s.logger.Info("Starting Sidecar", "addr", addr)
	return s.server.ListenAndServe()
}

// Stop gracefully shuts down the sidecar
func (s *Sidecar) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.running = false
	s.config.Close()

	// Stop Bridge
	if s.bridge != nil {
		s.bridge.Stop(ctx)
	}

	// Shutdown HTTP
	if err := s.server.Shutdown(ctx); err != nil {
		return err
	}

	return nil
}

// registerRoutes sets up the HTTP handlers
func (s *Sidecar) registerRoutes(mux *http.ServeMux) {
	// 1. Health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// 2. Interceptor (API Stub)
	mux.HandleFunc("/intercept/before", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// 3. MCP Handlers (Bridge Integration)
	mux.HandleFunc("/mcp/sse", s.bridge.HandleSSE)
	mux.HandleFunc("/mcp/message", s.bridge.HandleMessage)

	// Root convenience
	mux.HandleFunc("/sse", s.bridge.HandleSSE)
	mux.HandleFunc("/message", s.bridge.HandleMessage)
}

// noopPolicyEvaluator for initialization
type noopPolicyEvaluator struct{}

func (e *noopPolicyEvaluator) Evaluate(ctx context.Context, input InterceptRequest) (PolicyDecision, []byte, string, error) {
	return DecisionAllow, input.Body, "", nil
}
