// Package main wires the Secure AI Proxy executable entry point and lifecycle management.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"gopkg.in/yaml.v3"

	"github.com/polisai/polis-oss/pkg/config"
	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
	"github.com/polisai/polis-oss/pkg/storage"
	"github.com/polisai/polis-oss/pkg/telemetry"
)

const (
	defaultConfigPath        = "config.yaml"
	defaultServiceName       = "polis"
	telemetryShutdownTimeout = 5 * time.Second
	gracefulShutdownTimeout  = 10 * time.Second
)

func main() {
	// Load .env file if present
	_ = godotenv.Load()

	// Parse flags
	configPath := flag.String("config-path", defaultConfigPath, "Path to the configuration file")
	adminAddr := flag.String("admin-listen", "", "HTTP listen address for the admin endpoints")
	dataAddr := flag.String("data-listen", "", "HTTP listen address for the data plane proxy")
	otelEndpoint := flag.String("otel-endpoint", "", "OTLP endpoint")
	logLevel := flag.String("log-level", "", "Log level")
	pipelineFile := flag.String("pipeline-file", "", "Path to a single pipeline file")
	pipelineDir := flag.String("pipeline-dir", "", "Path to a directory containing pipeline files")
	bootstrapPath := flag.String("bootstrap-path", "", "Path to the bootstrap configuration snapshot")

	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("configuration load failed: %v", err)
	}

	// Apply flag overrides
	if *adminAddr != "" {
		cfg.Server.AdminAddress = *adminAddr
	}
	if *dataAddr != "" {
		cfg.Server.DataAddress = *dataAddr
	}
	if *otelEndpoint != "" {
		cfg.Telemetry.OTLPEndpoint = *otelEndpoint
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	if *pipelineFile != "" {
		cfg.Pipeline.File = *pipelineFile
	}
	if *pipelineDir != "" {
		cfg.Pipeline.Dir = *pipelineDir
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := run(ctx, cfg, *bootstrapPath); err != nil {
		log.Fatalf("application failed: %v", err)
	}
}

// run orchestrates the application lifecycle.
func run(ctx context.Context, cfg *config.Config, bootstrapPath string) error {
	telemetryShutdown, err := initializeTelemetry(ctx, cfg)
	if err != nil {
		return fmt.Errorf("telemetry initialization failed: %w", err)
	}
	defer shutdownTelemetry(telemetryShutdown)

	// Initialize Memory Stores
	log.Println("Using in-memory storage")
	policyStore := storage.NewMemoryPolicyStore()

	var domainPipelines []domain.Pipeline

	if bootstrapPath != "" {
		log.Printf("Loading bootstrap snapshot from %s", bootstrapPath)
		// #nosec G304 -- bootstrapPath is from command-line flag
		data, err := os.ReadFile(bootstrapPath)
		if err != nil {
			return fmt.Errorf("failed to read bootstrap file: %w", err)
		}

		var snapshot config.Snapshot
		if err := yaml.Unmarshal(data, &snapshot); err != nil {
			if jsonErr := json.Unmarshal(data, &snapshot); jsonErr != nil {
				return fmt.Errorf("failed to parse bootstrap file: %v", err)
			}
		}

		// Load and Save Policy Bundles
		for _, desc := range snapshot.PolicyBundles {
			bundle, err := config.LoadPolicyBundle(desc)
			if err != nil {
				log.Printf("Warning: failed to load bundle %s: %v", desc.ID, err)
				continue
			}
			if err := policyStore.SavePolicyBundle(ctx, bundle); err != nil {
				log.Printf("Warning: failed to save bundle %s: %v", desc.ID, err)
			}
		}

		// Convert Pipelines
		for _, spec := range snapshot.Pipelines {
			domainPipelines = append(domainPipelines, spec.ToDomain())
		}
	}

	// Initialize Pipeline Registry and Engine Factory
	engineFactory := pipelinepkg.NewEngineFactory(policyStore, slog.Default())
	pipelineRegistry := pipelinepkg.NewPipelineRegistry(engineFactory)

	// Register Pipelines
	if len(domainPipelines) > 0 {
		if err := pipelineRegistry.UpdatePipelines(ctx, domainPipelines); err != nil {
			return fmt.Errorf("failed to register pipelines: %w", err)
		}
		log.Printf("Loaded %d pipelines from bootstrap", len(domainPipelines))
	} else {
		// Load from file/dir if configured
		if err := loadPipelinesFromConfig(pipelineRegistry, cfg); err != nil {
			log.Printf("Warning: failed to load pipelines: %v", err)
		}
	}

	adminSrv := startAdminServer(cfg)
	defer shutdownAdminServer(adminSrv)

	dataSrv := startDataPlaneServer(cfg, pipelineRegistry, engineFactory)
	defer shutdownDataPlaneServer(dataSrv)

	awaitShutdownSignal(dataSrv)
	return nil
}

// initializeTelemetry sets up OpenTelemetry with the provided configuration.
func initializeTelemetry(ctx context.Context, cfg *config.Config) (func(context.Context) error, error) {
	return telemetry.SetupProvider(ctx, telemetry.Config{
		ServiceName:  defaultServiceName,
		Endpoint:     cfg.Telemetry.OTLPEndpoint,
		Insecure:     cfg.Telemetry.Insecure,
		Environment:  os.Getenv("PROXY_ENVIRONMENT"),
		ResourceTags: map[string]string{"log.level": cfg.Logging.Level},
	})
}

// shutdownTelemetry gracefully shuts down the telemetry provider.
func shutdownTelemetry(shutdown func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), telemetryShutdownTimeout)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		log.Printf("telemetry shutdown error: %v", err)
	}
}

// dataPlaneComponents holds resources that need cleanup on shutdown.
type dataPlaneComponents struct {
	server        *http.Server
	engineFactory *pipelinepkg.EngineFactory
}

// startDataPlaneServer initializes and starts the data plane proxy server.
func startDataPlaneServer(cfg *config.Config, registry *pipelinepkg.PipelineRegistry, engineFactory *pipelinepkg.EngineFactory) *dataPlaneComponents {
	// Initialize Token Vault
	tokenVault := storage.NewMemoryTokenVault()

	// Build the DAG-based routing handler
	dagHandler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry:   registry,
		TokenVault: tokenVault,
	})

	// Create HTTP server
	handler := otelhttp.NewHandler(dagHandler, "proxy.data")
	server := &http.Server{
		Addr:         cfg.Server.DataAddress,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in background
	go func() {
		ln, err := net.Listen("tcp", cfg.Server.DataAddress)
		if err != nil {
			log.Printf("data plane server listen error: %v", err)
			return
		}
		log.Printf("data plane server listening on %s (DAG mode)", ln.Addr().String())
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("data plane server error: %v", err)
		}
	}()

	return &dataPlaneComponents{
		server:        server,
		engineFactory: engineFactory,
	}
}

// startAdminServer initializes and starts the admin server.
func startAdminServer(cfg *config.Config) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:              cfg.Server.AdminAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		ln, err := net.Listen("tcp", cfg.Server.AdminAddress)
		if err != nil {
			log.Printf("admin server listen error: %v", err)
			return
		}
		log.Printf("admin server listening on %s", ln.Addr().String())
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("admin server error: %v", err)
		}
	}()

	return server
}

// shutdownAdminServer performs graceful shutdown of the admin server.
func shutdownAdminServer(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("admin server shutdown error: %v", err)
	}
}

// loadPipelinesFromConfig loads pipelines from files or creates a default wildcard pipeline.
func loadPipelinesFromConfig(registry *pipelinepkg.PipelineRegistry, cfg *config.Config) error {
	// Priority 1: Load from explicit pipeline file or directory
	if cfg.Pipeline.File != "" {
		return loadPipelinesFromFile(registry, cfg.Pipeline.File)
	}
	if cfg.Pipeline.Dir != "" {
		return loadPipelinesFromDirectory(registry, cfg.Pipeline.Dir)
	}

	// No pipelines configured - create default wildcard pipeline
	return loadInitialPipelines(registry)
}

// loadInitialPipelines creates default pipelines for bootstrapping.
func loadInitialPipelines(registry *pipelinepkg.PipelineRegistry) error {
	// Determine upstream mode from environment
	// Modes: "proxy" (standard HTTP proxy), "custom_header" (X-Target-URL), "static" (configured URL)
	upstreamMode := envOrDefault("UPSTREAM_MODE", "proxy")
	upstreamURL := envOrDefault("UPSTREAM_URL", "https://localhost:8090")

	// Parse UPSTREAM_ALLOWLIST env var (comma-separated domains/URLs)
	// Only used for custom_header mode
	allowlistStr := envOrDefault("UPSTREAM_ALLOWLIST", "")
	var allowlist []interface{}
	if allowlistStr != "" {
		for _, entry := range strings.Split(allowlistStr, ",") {
			allowlist = append(allowlist, strings.TrimSpace(entry))
		}
	}

	// Build egress node config based on mode
	egressConfig := map[string]interface{}{
		"upstream_mode": upstreamMode,
	}

	switch upstreamMode {
	case "proxy":
		// Standard proxy protocol: extract target from request Host header
		// No additional config needed, but we can allow HTTP for testing
		allowHTTP := envOrDefault("PROXY_ALLOW_HTTP", "false") == "true"
		if allowHTTP {
			egressConfig["proxy.allow_http"] = true
		}

	case "custom_header":
		// Custom X-Target-URL header mode (for LLM-directed agent calls)
		egressConfig["upstream_allowlist"] = allowlist
		egressConfig["require_https"] = true

	case "static":
		// Static upstream URL from configuration
		egressConfig["upstream_url"] = upstreamURL
	}

	// Wildcard pipeline matches any agent (catch-all fallback)
	// AgentID="*" with empty Protocol="" provides true wildcard behavior
	pipeline := domain.Pipeline{
		ID:       "wildcard",
		Version:  1,
		AgentID:  "*",
		Protocol: "",
		Nodes: []domain.PipelineNode{
			{
				ID:   "start",
				Type: "auth",
				On: domain.NodeHandlers{
					Success: "egress",
					Failure: "deny",
				},
			},
			{
				ID:     "egress",
				Type:   "egress",
				Config: egressConfig,
				On: domain.NodeHandlers{
					Success: "", // Terminal success
				},
			},
			{
				ID:   "deny",
				Type: "terminal.deny",
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		return fmt.Errorf("failed to register pipelines: %w", err)
	}

	log.Printf("Loaded wildcard pipeline (mode: %s)", upstreamMode)

	return nil
}

// awaitShutdownSignal blocks until a shutdown signal or server error occurs.
func awaitShutdownSignal(components *dataPlaneComponents) {
	if components != nil && components.server != nil {
		log.Printf("data plane server active on %s", components.server.Addr)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigCh
	log.Printf("received signal %s, initiating graceful shutdown", sig)
}

// shutdownDataPlaneServer performs graceful shutdown of the data plane server and engine factory.
func shutdownDataPlaneServer(components *dataPlaneComponents) {
	// First, shut down the HTTP server to stop accepting new requests
	ctx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	defer cancel()
	if err := components.server.Shutdown(ctx); err != nil {
		log.Printf("data plane server shutdown error: %v", err)
	}

	// Then close the engine factory to clean up bundle HTTP servers
	log.Println("Shutting down engine factory...")
	if err := components.engineFactory.Close(); err != nil {
		log.Printf("engine factory close error: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// loadPipelinesFromFile loads a single pipeline from a JSON or YAML file.
func loadPipelinesFromFile(registry *pipelinepkg.PipelineRegistry, filePath string) error {
	data, err := os.ReadFile(filePath) // nolint:gosec // file path from config/flags
	if err != nil {
		return fmt.Errorf("failed to read pipeline file %s: %w", filePath, err)
	}

	specs, err := parsePipelineSpec(data, filePath)
	if err != nil {
		return fmt.Errorf("failed to parse pipeline file %s: %w", filePath, err)
	}

	var domainPipelines []domain.Pipeline
	for _, spec := range specs {
		domainPipelines = append(domainPipelines, spec.ToDomain())
		log.Printf("Loaded pipeline %s from file: %s", spec.ID, filePath)
	}

	if err := registry.UpdatePipelines(context.Background(), domainPipelines); err != nil {
		return fmt.Errorf("failed to register pipelines from %s: %w", filePath, err)
	}

	return nil
}

// loadPipelinesFromDirectory loads all pipeline files from a directory (JSON and YAML).
func loadPipelinesFromDirectory(registry *pipelinepkg.PipelineRegistry, dirPath string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read pipeline directory %s: %w", dirPath, err)
	}

	var pipelines []domain.Pipeline
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()

		// Prevent path traversal: ensure filename doesn't contain path separators
		if strings.Contains(filename, string(filepath.Separator)) || strings.Contains(filename, "..") {
			log.Printf("Warning: skipping potentially malicious filename: %s", filename)
			continue
		}

		ext := strings.ToLower(filepath.Ext(filename))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			continue
		}

		filePath := filepath.Join(dirPath, filename)

		// Additional validation: ensure the resolved path is within the expected directory
		absFilePath, err := filepath.Abs(filePath)
		if err != nil {
			log.Printf("Warning: failed to resolve absolute path for %s: %v", filePath, err)
			continue
		}
		absDirPath, err := filepath.Abs(dirPath)
		if err != nil {
			log.Printf("Warning: failed to resolve absolute directory path: %v", err)
			continue
		}
		if !strings.HasPrefix(absFilePath, absDirPath+string(filepath.Separator)) && absFilePath != absDirPath {
			log.Printf("Warning: file %s is outside of pipeline directory, skipping", filename)
			continue
		}

		data, err := os.ReadFile(filePath) // nolint:gosec // path validated above
		if err != nil {
			log.Printf("Warning: failed to read pipeline file %s: %v", filePath, err)
			continue
		}

		specs, err := parsePipelineSpec(data, filePath)
		if err != nil {
			log.Printf("Warning: failed to parse pipeline file %s: %v", filePath, err)
			continue
		}

		for _, spec := range specs {
			domainPipeline := spec.ToDomain()
			pipelines = append(pipelines, domainPipeline)
			log.Printf("Loaded pipeline %s from file: %s", spec.ID, filePath)
		}
	}

	if len(pipelines) == 0 {
		return fmt.Errorf("no valid pipeline files found in directory %s", dirPath)
	}

	if err := registry.UpdatePipelines(context.Background(), pipelines); err != nil {
		return fmt.Errorf("failed to register pipelines from directory %s: %w", dirPath, err)
	}

	log.Printf("Loaded %d pipeline(s) from directory: %s", len(pipelines), dirPath)
	return nil
}

// parsePipelineSpec parses a pipeline spec from JSON or YAML data.
// It supports both a single pipeline object and a "pipelines" list object.
func parsePipelineSpec(data []byte, filePath string) ([]config.PipelineSpec, error) {
	var singleSpec config.PipelineSpec
	var listSpec struct {
		Pipelines []config.PipelineSpec `yaml:"pipelines" json:"pipelines"`
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	isList := false

	// Try parsing as list first
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &listSpec); err == nil && len(listSpec.Pipelines) > 0 {
			isList = true
		} else {
			// Fallback to single
			if err := json.Unmarshal(data, &singleSpec); err != nil {
				return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
			}
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &listSpec); err == nil && len(listSpec.Pipelines) > 0 {
			isList = true
		} else {
			// Fallback to single
			if err := yaml.Unmarshal(data, &singleSpec); err != nil {
				return nil, fmt.Errorf("YAML unmarshal failed: %w", err)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported file extension: %s (expected .json, .yaml, or .yml)", ext)
	}

	var results []config.PipelineSpec
	if isList {
		results = listSpec.Pipelines
	} else {
		results = []config.PipelineSpec{singleSpec}
	}

	// Validate all
	for i, spec := range results {
		if spec.ID == "" {
			return nil, fmt.Errorf("pipeline [%d] missing required field: id", i)
		}
		if spec.AgentID == "" {
			return nil, fmt.Errorf("pipeline [%d] missing required field: agentId", i)
		}
		if spec.Protocol == "" {
			return nil, fmt.Errorf("pipeline [%d] missing required field: protocol", i)
		}
		if len(spec.Nodes) == 0 {
			return nil, fmt.Errorf("pipeline [%d] missing required field: nodes", i)
		}
	}

	return results, nil
}
