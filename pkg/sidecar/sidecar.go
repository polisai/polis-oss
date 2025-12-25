package sidecar

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/polisai/polis-oss/internal/tls"
	"github.com/polisai/polis-oss/pkg/bridge"
	configpkg "github.com/polisai/polis-oss/pkg/config"
	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
	"github.com/polisai/polis-oss/pkg/storage"
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
	config ConfigProvider
	logger *slog.Logger
	mu     sync.RWMutex

	// MCP Components
	router *BridgeRouter
	bridge *bridge.Bridge

	// Core Components
	policyStore      storage.PolicyStore
	engineFactory    *pipelinepkg.EngineFactory
	pipelineRegistry *pipelinepkg.PipelineRegistry
	dagHandler       *pipelinepkg.DAGHandler

	// Servers
	servers []*http.Server
	errCh   chan error
	stopCh  chan struct{}
	running bool

	// Legacy / Compatibility
	interceptor *InterceptorServer
	ctxManager  ContextManager
}

// NewSidecar creates a new unified sidecar instance
func NewSidecar(cfgLoader ConfigProvider, logger *slog.Logger) (*Sidecar, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Initialize Core Components
	// Create Context Manager
	cm := NewInMemoryContextManager()

	// Initialize Policy Store
	policyStore := storage.NewMemoryPolicyStore()

	// Initialize Engine Factory
	engineFactory := pipelinepkg.NewEngineFactory(policyStore, logger)

	// Initialize Pipeline Registry
	pipelineRegistry := pipelinepkg.NewPipelineRegistry(engineFactory)

	// Initialize DAG Handler
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: pipelineRegistry,
		Logger:   logger,
	})

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
	// TODO: Integrate real Policy Engine (reusing engineFactory)
	var evaluator PolicyEvaluator = &noopPolicyEvaluator{}
	interceptor := NewInterceptorServer(evaluator, cm)

	// Initialize Bridge
	bridgeConfig := bridge.DefaultBridgeConfig()

	// Use legacy Port if ListenParams is empty
	listenPort := currentCfg.Server.Port
	if listenPort == 0 && len(currentCfg.Server.ListenParams) == 0 {
		listenPort = 8090 // Default
	}
	bridgeConfig.ListenAddr = fmt.Sprintf(":%d", listenPort)

	// If tools are defined, use the first one for the bridge command (MVP Compatibility)
	if len(currentCfg.Tools) > 0 {
		tool := currentCfg.Tools[0]
		bridgeConfig.Command = tool.Command

		var env []string
		for k, v := range tool.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		bridgeConfig.Env = env
		logger.Info("Configuring Bridge with tool", "tool", tool.Name, "command", tool.Command)
	}

	b := bridge.NewBridge(bridgeConfig, logger)

	s := &Sidecar{
		config:           cfgLoader,
		logger:           logger,
		router:           router,
		bridge:           b,
		policyStore:      policyStore,
		engineFactory:    engineFactory,
		pipelineRegistry: pipelineRegistry,
		dagHandler:       dagHandler,
		interceptor:      interceptor,
		ctxManager:       cm,
		stopCh:           make(chan struct{}),
	}

	return s, nil
}

// Start initializes background processes and starts all configured HTTP/HTTPS servers
func (s *Sidecar) Start(addr string) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("sidecar already running")
	}
	s.running = true
	s.mu.Unlock()

	ctx := context.Background()

	// 1. Start Context Cleanup
	s.ctxManager.StartCleanup(ctx, 1*time.Minute, 24*time.Hour)

	// 2. Start Bridge Components (Backend)
	if err := s.bridge.StartComponents(ctx); err != nil {
		s.logger.Error("Failed to start bridge components", "error", err)
		return err
	}

	// 3. Start Config Watcher
	if err := s.config.Watch(s.handleConfigUpdate); err != nil {
		s.logger.Warn("Failed to start config watcher", "error", err)
	}

	// 4. Initial Config Load & Setup
	cfg := s.config.Current()
	s.handleConfigUpdate(cfg) // Initial setup (load bundles/pipelines)

	// 5. Start Servers
	s.errCh = make(chan error, 10)
	s.startServers(addr)

	// Keep running until first terminal error or Stop() is called
	select {
	case err := <-s.errCh:
		return err
	case <-s.stopCh:
		return http.ErrServerClosed
	}
}

func (s *Sidecar) handleConfigUpdate(cfg *SidecarConfig) {
	s.logger.Info("Sidecar configuration update received")

	// Update Policy Bundles
	ctx := context.Background()
	for _, bundleDesc := range cfg.Policies.Bundles {
		// Map Sidecar.PolicyBundle to domain.PolicyBundle (via legacy loader logic)
		// For simplicity/MVP, we use legacy config.LoadPolicyBundleFromDomain if possible
		// or direct load.
		// Since we want full parity, we reuse the existing engine logic.
		s.logger.Info("Loading policy bundle", "name", bundleDesc.Name, "path", bundleDesc.Path)

		// Create a domain.PolicyBundleDescriptor for the legacy loader
		desc := domain.PolicyBundleDescriptor{
			ID:      bundleDesc.Name,
			Name:    bundleDesc.Name,
			Version: 1, // Defaulting for simple bundles
			Artifacts: []domain.BundleArtifactDescriptor{
				{
					Name: bundleDesc.Name,
					Path: bundleDesc.Path,
					Type: bundleDesc.Type,
				},
			},
		}

		bundle, err := configpkg.LoadPolicyBundleFromDomain(desc)
		if err != nil {
			s.logger.Error("Failed to load policy bundle", "bundle_id", desc.ID, "error", err)
			continue
		}

		if err := s.policyStore.SavePolicyBundle(ctx, bundle); err != nil {
			s.logger.Error("Failed to save policy bundle to store", "bundle_id", desc.ID, "error", err)
		} else {
			s.logger.Info("Policy bundle loaded", "bundle_id", desc.ID)
		}
	}

	// Update Pipelines (If any specified in config or discovered via Dir/File)
	// For now, SidecarConfig doesn't have inline pipelines but has PipelineConfig.
	// We should trigger the registry update here.
	// TODO: Implement full file-based pipeline loading if Pipeline.File/Dir is set.
}

func (s *Sidecar) startServers(defaultAddr string) {
	cfg := s.config.Current()

	// 1. Determine listeners
	httpAddresses, httpsAddresses := s.determineListenerAddresses(cfg.Server, defaultAddr)

	// 2. HTTP Root Handler
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	// 3. Start HTTP servers
	for _, httpAddr := range httpAddresses {
		httpServer := &http.Server{
			Addr:         httpAddr,
			Handler:      mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		s.mu.Lock()
		s.servers = append(s.servers, httpServer)
		s.mu.Unlock()

		go func(server *http.Server) {
			s.logger.Info("HTTP server listening", "addr", server.Addr)
			if err := server.ListenAndServe(); err != nil {
				if err != http.ErrServerClosed {
					s.logger.Error("HTTP server failed", "addr", server.Addr, "error", err)
					s.errCh <- err
				}
			}
		}(httpServer)
	}

	// 4. Start TLS server if enabled
	if len(httpsAddresses) > 0 || (cfg.Server.TLS != nil && cfg.Server.TLS.Enabled) {
		tlsConfig := cfg.Server.TLS
		if tlsConfig != nil && tlsConfig.Enabled {
			s.logger.Info("TLS is enabled, starting TLS server")

			legacyTLS := &configpkg.TLSConfig{
				Enabled:  tlsConfig.Enabled,
				CertFile: tlsConfig.CertFile,
				KeyFile:  tlsConfig.KeyFile,
			}

			tlsServer, err := tls.NewTLSServer(legacyTLS, s.dagHandler, s.logger)
			if err != nil {
				s.logger.Error("Failed to create TLS server", "error", err)
				s.errCh <- err
			} else {
				addresses := httpsAddresses
				if len(addresses) == 0 {
					addresses = []string{":8443"}
				}

				go func() {
					if err := tlsServer.Start(context.Background(), addresses); err != nil {
						if err != http.ErrServerClosed {
							s.logger.Error("TLS server failed", "error", err)
							s.errCh <- err
						}
					}
				}()
			}
		}
	}
}

func (s *Sidecar) determineListenerAddresses(serverConfig ServerConfig, defaultAddr string) (httpAddresses, httpsAddresses []string) {
	if len(serverConfig.ListenParams) > 0 {
		for _, param := range serverConfig.ListenParams {
			switch param.Protocol {
			case "http":
				httpAddresses = append(httpAddresses, param.Address)
			case "https":
				httpsAddresses = append(httpsAddresses, param.Address)
			default:
				s.logger.Warn("Unknown protocol in listen parameters", "protocol", param.Protocol, "address", param.Address)
			}
		}
	} else {
		// Use defaultAddr (which usually comes from -port flag)
		httpAddresses = []string{defaultAddr}
	}
	return httpAddresses, httpsAddresses
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

	// Signal stop
	close(s.stopCh)

	// Shutdown all HTTP servers
	for _, server := range s.servers {
		if err := server.Shutdown(ctx); err != nil {
			s.logger.Error("HTTP server shutdown error", "addr", server.Addr, "error", err)
		}
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

	// 2. MCP Handlers (Bridge Integration)
	// These are also wrapped in AgentID middleware if needed by the bridge
	mux.HandleFunc("/mcp/sse", s.bridge.HandleSSE)
	mux.HandleFunc("/mcp/message", s.bridge.HandleMessage)

	// Compatibility aliases
	mux.HandleFunc("/sse", s.bridge.HandleSSE)
	mux.HandleFunc("/message", s.bridge.HandleMessage)

	// 3. Fallthrough to DAG Handler (Legacy Pipelines)
	// We use a custom handler to choose between MCP and DAG
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If it reaches here and doesn't match MCP exact paths, forward to DAG
		s.dagHandler.ServeHTTP(w, r)
	})
}

// noopPolicyEvaluator for initialization
type noopPolicyEvaluator struct{}

func (e *noopPolicyEvaluator) Evaluate(ctx context.Context, input InterceptRequest) (PolicyDecision, []byte, string, error) {
	return DecisionAllow, input.Body, "", nil
}
