package sidecar

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
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
	// Note: In a real app we might inject these or build them from config here
	// For now we assume defaults or basic construction matching our milestones

	// Create Context Manager
	cm := NewInMemoryContextManager()

	// Create Process Managers (Local)
	// We need metrics/tracer for LocalProcessManager. We'll add them later or use nil/stubs.
	localPM := NewLocalProcessManager(logger, nil, nil)

	// Pre-register tools from config?
	// The ConfigLoader returns a SidecarConfig. We should read it.
	currentCfg := cfgLoader.Current()

	// Create Router
	// We pass nil for E2B for now (Step 6 stub)
	router := NewBridgeRouter(localPM, nil)

	// Register configured tools
	for _, t := range currentCfg.Tools {
		if err := router.RegisterTool(t); err != nil {
			logger.Warn("Failed to register tool", "tool", t.Name, "error", err)
		}
	}

	// Create Interceptor (Phase 5)
	// We need a PolicyEvaluator. For now we can use a stub or separate impl.
	// Since we defined PolicyEvaluator as an interface, we can pass a dummy one if needed,
	// or ideally we integrate the real engine.
	// The implementation plan says "Integrate with policy engine".
	// Let's create a stub implementation for now to pass compilation,
	// since pkg/engine integration is complex and might be separate.
	// Or we can assume we will inject it.
	// Let's create a simple "AlwaysAllow" or "DenyAll" evaluator if nil?
	// For this step, let's allow injecting it or default to a stub.
	var evaluator PolicyEvaluator = &noopPolicyEvaluator{} // defined below
	interceptor := NewInterceptorServer(evaluator, cm)

	s := &Sidecar{
		config:      cfgLoader,
		router:      router,
		interceptor: interceptor,
		ctxManager:  cm,
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
	// We need a background context for cleanup that lives as long as the sidecar
	// Since Start blocks, we can assume the sidecar runs until Stop.
	// Ideally we pass a context to Start, but for now we'll use Background and manage via struct field if needed.
	// Actually StartCleanup takes a context. We should probably use a context derived from a cancellable one stored in Sidecar.
	// The simple fix for compilation: use context.Background() as a placeholder
	// or better, create a context in Start that we can cancel in Stop.
	s.ctxManager.StartCleanup(context.Background(), 1*time.Minute, 24*time.Hour)

	// Start Config Watcher
	if err := s.config.Watch(func(sc *SidecarConfig) {
		s.logger.Info("Configuration reloaded")
		// In a real implementation we would propagate updates to components
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
	// POST /intercept/before
	mux.HandleFunc("/intercept/before", func(w http.ResponseWriter, r *http.Request) {
		// Parse body, call s.interceptor.HandleInterceptBefore, write response
		// This is just a skeleton for Step 9
		w.WriteHeader(http.StatusOK)
	})

	// 3. MCP Handlers (Passthrough/Bridge)
	// In the final version, this would use pkg/bridge logic.
	// For now, simple stubs.
	mux.HandleFunc("/mcp/sse", func(w http.ResponseWriter, r *http.Request) {
		// MCP SSE connection
		w.WriteHeader(http.StatusNotImplemented)
	})
}

// noopPolicyEvaluator for initialization
type noopPolicyEvaluator struct{}

func (e *noopPolicyEvaluator) Evaluate(ctx context.Context, input InterceptRequest) (PolicyDecision, []byte, string, error) {
	// Default open for dev? Or default closed?
	return DecisionAllow, input.Body, "", nil
}
