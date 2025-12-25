package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/polisai/polis-oss/pkg/sidecar"
)

func main() {
	// 1. Flags
	configPath := flag.String("config", "polis.yaml", "Path to configuration file")
	port := flag.Int("port", 8090, "Port to listen on (overrides config if non-zero)")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	// 2. Logging
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	// 3. Config Loader
	logger.Info("Loading configuration", "path", *configPath)
	loader, err := sidecar.NewConfigLoader(*configPath)
	if err != nil {
		logger.Error("Failed to create config loader", "error", err)
		os.Exit(1)
	}
	config, err := loader.Load()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// 4. Override Port if flag set
	if *port > 0 {
		config.Server.Port = *port
	}

	// 5. Create Sidecar
	s, err := sidecar.NewSidecar(loader, logger)
	if err != nil {
		logger.Error("Failed to initialize sidecar", "error", err)
		os.Exit(1)
	}

	// 6. Start
	addr := fmtAddr(config.Server.Port)
	if err := s.Start(addr); err != nil {
		logger.Error("Sidecar failed to start", "error", err)
		os.Exit(1)
	}

	// 7. Shutdown Handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.Stop(ctx); err != nil {
		logger.Error("Shutdown error", "error", err)
		os.Exit(1)
	}
	logger.Info("Shutdown complete")
}

func fmtAddr(port int) string {
	if port == 0 {
		port = 8090
	}
	return fmt.Sprintf(":%d", port)
}
