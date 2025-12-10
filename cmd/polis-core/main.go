// Package main is the entry point for the polis-core binary.
package main

import (
	"context"
	"flag"
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
	"github.com/rs/zerolog/log"
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
	logging.SetupLogger(logging.Config{
		Level:  *logLevel,
		Pretty: *prettyLogs,
	})

	log.Info().Msgf("Starting polis-core with config: %s", *configPath)

	// Setup Config Provider
	cfgProvider, err := config.NewFileConfigProvider(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize config provider")
	}
	defer func() {
		if err := cfgProvider.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close config provider")
		}
	}()

	// Initialize Core Components
	// Note: polis-core uses in-memory storage for policies by default
	policyStore := storage.NewMemoryPolicyStore()
	engineFactory := pipelinepkg.NewEngineFactory(policyStore, nil) // Logger handled globally via zerolog adapter if needed
	pipelineRegistry := pipelinepkg.NewPipelineRegistry(engineFactory)

	// Start Config Watcher
	go watchConfig(cfgProvider, pipelineRegistry, policyStore)

	// Start Server
	server := startServer(*listenAddr, pipelineRegistry)

	// Wait for shutdown
	waitForShutdown(server)
}

func watchConfig(provider domain.ConfigService, registry *pipelinepkg.PipelineRegistry, policyStore storage.PolicyStore) {
	updates := provider.Subscribe()
	for snapshot := range updates {
		log.Info().Int64("generation", 0).Msg("Configuration update received") // Generation is string in domain, int64 in config.Snapshot

		// Update Policy Bundles
		// IMPORTANT: Policy bundles must be loaded BEFORE pipelines that reference them
		for _, bundleDesc := range snapshot.PolicyBundles {
			bundle, err := config.LoadPolicyBundleFromDomain(bundleDesc)
			if err != nil {
				log.Error().Err(err).Str("bundle_id", bundleDesc.ID).Msg("Failed to load policy bundle")
				continue
			}

			if err := policyStore.SavePolicyBundle(context.Background(), bundle); err != nil {
				log.Error().Err(err).Str("bundle_id", bundleDesc.ID).Msg("Failed to save policy bundle to store")
			} else {
				log.Info().Str("bundle_id", bundleDesc.ID).Int("version", bundleDesc.Version).Msg("Policy bundle loaded")
			}
		}

		// Update Pipelines
		if len(snapshot.Pipelines) > 0 {
			if err := registry.UpdatePipelines(context.Background(), snapshot.Pipelines); err != nil {
				log.Error().Err(err).Msg("Failed to update pipelines")
			} else {
				log.Info().Int("count", len(snapshot.Pipelines)).Msg("Pipelines updated")
			}
		}
	}
}

func startServer(addr string, registry *pipelinepkg.PipelineRegistry) *http.Server {
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/", otelhttp.NewHandler(dagHandler, "polis.core"))

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", addr).Msg("Failed to bind listener")
	}

	// Log the actual resolved address (useful when addr is :0)
	log.Info().Str("addr", listener.Addr().String()).Msg("Server listening")

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	return server
}

func waitForShutdown(server *http.Server) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh

	log.Info().Str("signal", sig.String()).Msg("Shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Shutdown error")
	}
}
