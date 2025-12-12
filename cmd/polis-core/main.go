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

	// Start Server
	server := startServer(*listenAddr, pipelineRegistry, logger)

	// Wait for shutdown
	waitForShutdown(server, logger)
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

func startServer(addr string, registry *pipelinepkg.PipelineRegistry, logger *slog.Logger) *http.Server {
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
		Logger:   logger,
	})

	// Use a manual handler to avoid ServeMux's automatic redirects (301) for CONNECT requests
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
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

	server := &http.Server{
		Handler:      rootHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("Failed to bind listener", "addr", addr, "error", err)
		os.Exit(1)
	}

	// Log the actual resolved address (useful when addr is :0)
	logger.Info("Server listening", "addr", listener.Addr().String())

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	return server
}

func waitForShutdown(server *http.Server, logger *slog.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh

	logger.Info("Shutting down", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Shutdown error", "error", err)
	}
}
