// Package main is the entry point for the polis-core binary.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/polisai/polis-oss/internal/tls"
	"github.com/polisai/polis-oss/pkg/config"
	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
	"github.com/polisai/polis-oss/pkg/logging"
	"github.com/polisai/polis-oss/pkg/storage"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	defaultConfigPath = "config.yaml"
	defaultListenAddr = ":8090"
)

func main() {
	configPath := flag.String("config", defaultConfigPath, "Path to configuration file")
	listenAddr := flag.String("listen", defaultListenAddr, "Address to listen on")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	prettyLogs := flag.Bool("pretty", false, "Enable pretty console logging")
	flag.Parse()

	// Setup Logging
	logger := logging.NewLogger(logging.Config{
		Level:  *logLevel,
		Pretty: *prettyLogs,
	})
	slog.SetDefault(logger)

	logger.Info("Starting polis-core", "config", *configPath, "build", "integration_test_verify")

	// Setup Config Provider
	cfgProvider, err := config.NewFileConfigProvider(*configPath)
	if err != nil {
		logger.Error("Failed to initialize config provider", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := cfgProvider.Close(); err != nil {
			logger.Error("Failed to close config provider", "error", err)
		}
	}()

	// Initialize Core Components
	// Note: polis-core uses in-memory storage for policies by default
	policyStore := storage.NewMemoryPolicyStore()
	engineFactory := pipelinepkg.NewEngineFactory(policyStore, logger)
	pipelineRegistry := pipelinepkg.NewPipelineRegistry(engineFactory)

	// Start Config Watcher
	go watchConfig(cfgProvider, pipelineRegistry, policyStore, logger)

	// Start Servers (HTTP and TLS)
	servers := startServers(*listenAddr, pipelineRegistry, cfgProvider, logger)

	// Wait for shutdown
	waitForShutdown(servers, logger)
}

func watchConfig(provider domain.ConfigService, registry *pipelinepkg.PipelineRegistry, policyStore storage.PolicyStore, logger *slog.Logger) {
	updates := provider.Subscribe()
	for snapshot := range updates {
		logger.Info("Configuration update received", "generation", 0) // Generation is string in domain, int64 in config.Snapshot

		// Update Policy Bundles
		// IMPORTANT: Policy bundles must be loaded BEFORE pipelines that reference them
		for _, bundleDesc := range snapshot.PolicyBundles {
			bundle, err := config.LoadPolicyBundleFromDomain(bundleDesc)
			if err != nil {
				logger.Error("Failed to load policy bundle", "bundle_id", bundleDesc.ID, "error", err)
				continue
			}

			if err := policyStore.SavePolicyBundle(context.Background(), bundle); err != nil {
				logger.Error("Failed to save policy bundle to store", "bundle_id", bundleDesc.ID, "error", err)
			} else {
				logger.Info("Policy bundle loaded", "bundle_id", bundleDesc.ID, "version", bundleDesc.Version)
			}
		}

		// Update Pipelines
		if len(snapshot.Pipelines) > 0 {
			if err := registry.UpdatePipelines(context.Background(), snapshot.Pipelines); err != nil {
				logger.Error("Failed to update pipelines", "error", err)
			} else {
				logger.Info("Pipelines updated", "count", len(snapshot.Pipelines))
				for _, p := range snapshot.Pipelines {
					var upstream string
					for _, n := range p.Nodes {
						if n.Type == "egress" || n.Type == "egress.http" {
							if u, ok := n.Config["upstream_url"].(string); ok {
								upstream = u
								break
							}
						}
					}
					if upstream != "" {
						logger.Info("Pipeline active", "id", p.ID, "upstream", upstream)
					} else {
						logger.Info("Pipeline active", "id", p.ID)
					}
				}
			}
		}

	}
}

// ServerGroup holds multiple HTTP servers and TLS servers
type ServerGroup struct {
	httpServers []*http.Server
	tlsServer   *tls.TLSServer
}

func startServers(addr string, registry *pipelinepkg.PipelineRegistry, cfgProvider *config.FileConfigProvider, logger *slog.Logger) *ServerGroup {
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
		Logger:   logger,
	})

	// Use a manual handler to avoid ServeMux's automatic redirects (301) for CONNECT requests
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		// For CONNECT requests, we must bypass opentelemetry middleware because it wraps
		// the ResponseWriter and hides the Hijack interface needed for HTTPS tunneling.
		if r.Method == http.MethodConnect {
			dagHandler.ServeHTTP(w, r)
			return
		}

		// Forward everything else to the DAG handler (wrapped in OpenTelemetry)
		otelhttp.NewHandler(dagHandler, "polis.core").ServeHTTP(w, r)
	})

	// Get configuration
	cfg, err := cfgProvider.GetConfig()
	if err != nil {
		logger.Error("Failed to get configuration for server setup", "error", err)
		os.Exit(1)
	}

	var httpServers []*http.Server
	var tlsServer *tls.TLSServer

	// Determine listeners to start
	httpAddresses, httpsAddresses := determineListenerAddresses(cfg.Server, addr, logger)

	// Start HTTP servers
	for _, httpAddr := range httpAddresses {
		httpServer := &http.Server{
			Handler:      rootHandler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		listener, err := net.Listen("tcp", httpAddr)
		if err != nil {
			logger.Error("Failed to bind HTTP listener", "addr", httpAddr, "error", err)
			// Clean up any servers we've already started
			shutdownHTTPServers(httpServers, logger)
			os.Exit(1)
		}

		// Log the actual resolved address (useful when addr is :0)
		logger.Info("HTTP server listening", "addr", listener.Addr().String())

		httpServers = append(httpServers, httpServer)

		go func(server *http.Server, listener net.Listener, address string) {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP server failed", "error", err, "address", address)
				os.Exit(1)
			}
		}(httpServer, listener, httpAddr)
	}

	// Start TLS server if there are HTTPS addresses or legacy TLS is enabled
	if len(httpsAddresses) > 0 || (cfg.Server.TLS != nil && cfg.Server.TLS.Enabled) {
		// Determine which TLS configuration to use
		tlsConfig := cfg.Server.TLS
		if len(httpsAddresses) > 0 {
			// Use the first HTTPS listener's TLS config if available, otherwise use server-level TLS config
			for _, param := range cfg.Server.ListenParams {
				if param.Protocol == "https" && param.TLS != nil {
					tlsConfig = param.TLS
					break
				}
			}
		}

		if tlsConfig != nil && tlsConfig.Enabled {
			logger.Info("TLS is enabled, starting TLS server")

			tlsServer, err = tls.NewTLSServer(tlsConfig, dagHandler, logger)
			if err != nil {
				logger.Error("Failed to create TLS server", "error", err)
			} else {
				// Use configured HTTPS addresses or default
				addresses := httpsAddresses
				if len(addresses) == 0 {
					addresses = []string{":8443"} // Default HTTPS port
				}

				ctx := context.Background()
				if err := tlsServer.Start(ctx, addresses); err != nil {
					logger.Error("Failed to start TLS server", "error", err)
					tlsServer = nil
				} else {
					logger.Info("TLS server started successfully", "addresses", addresses)
				}
			}
		}
	} else {
		logger.Info("TLS is not enabled")
	}

	return &ServerGroup{
		httpServers: httpServers,
		tlsServer:   tlsServer,
	}
}

// determineListenerAddresses determines which HTTP and HTTPS addresses to listen on
func determineListenerAddresses(serverConfig config.ServerConfig, legacyAddr string, logger *slog.Logger) (httpAddresses, httpsAddresses []string) {
	// If ListenParams are configured, use them
	if len(serverConfig.ListenParams) > 0 {
		for _, param := range serverConfig.ListenParams {
			switch param.Protocol {
			case "http":
				httpAddresses = append(httpAddresses, param.Address)
			case "https":
				httpsAddresses = append(httpsAddresses, param.Address)
			default:
				logger.Warn("Unknown protocol in listen parameters", "protocol", param.Protocol, "address", param.Address)
			}
		}
		logger.Info("Using configured listen parameters", "http_addresses", httpAddresses, "https_addresses", httpsAddresses)
	} else {
		// Backward compatibility: use legacy DataAddress for HTTP
		httpAddresses = []string{legacyAddr}
		logger.Info("Using legacy data address for HTTP", "address", legacyAddr)
	}

	return httpAddresses, httpsAddresses
}

// shutdownHTTPServers gracefully shuts down a list of HTTP servers
func shutdownHTTPServers(servers []*http.Server, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i, server := range servers {
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Failed to shutdown HTTP server", "index", i, "error", err)
		}
	}
}

func waitForShutdown(servers *ServerGroup, logger *slog.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh

	logger.Info("Shutting down", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown all HTTP servers
	for i, httpServer := range servers.httpServers {
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("HTTP server shutdown error", "index", i, "error", err)
		}
	}

	// Shutdown TLS server if running
	if servers.tlsServer != nil {
		if err := servers.tlsServer.Shutdown(ctx); err != nil {
			logger.Error("TLS server shutdown error", "error", err)
		}
	}
}
