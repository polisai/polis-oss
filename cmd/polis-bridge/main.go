// Package main is the entry point for the polis-bridge binary.
// It provides a CLI for starting the MCP transport bridge server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/polisai/polis-oss/pkg/bridge"
	"github.com/polisai/polis-oss/pkg/logging"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	defaultPort     = "8090"
	defaultLogLevel = "info"
)

// CLIConfig holds the parsed CLI configuration
type CLIConfig struct {
	Port     string
	Config   string
	LogLevel string
	Command  []string
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newRootCmd creates the root command for polis-bridge
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "polis-bridge",
		Short: "MCP Transport Bridge for Polis",
		Long: `A bridge that translates between HTTP/SSE and Stdio transports for MCP tools.

The bridge spawns a child process (MCP tool) and exposes HTTP/SSE endpoints
that allow agents to communicate with the tool through Polis governance.

Example:
  polis-bridge --port 8090 -- npx -y @modelcontextprotocol/server-filesystem /home/user`,
		RunE: runBridge,
	}

	// Add flags
	rootCmd.Flags().StringP("port", "p", defaultPort, "Port to listen on")
	rootCmd.Flags().StringP("config", "c", "", "Path to configuration file (YAML)")
	rootCmd.Flags().StringP("log-level", "l", defaultLogLevel, "Log level (debug, info, warn, error)")

	return rootCmd
}

// parseCLIConfig parses command line arguments and returns a CLIConfig
func parseCLIConfig(cmd *cobra.Command, args []string) (*CLIConfig, error) {
	port, err := cmd.Flags().GetString("port")
	if err != nil {
		return nil, fmt.Errorf("failed to get port flag: %w", err)
	}

	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return nil, fmt.Errorf("failed to get config flag: %w", err)
	}

	logLevel, err := cmd.Flags().GetString("log-level")
	if err != nil {
		return nil, fmt.Errorf("failed to get log-level flag: %w", err)
	}

	// The command to execute comes after the -- separator
	// cobra passes these as args
	command := args

	return &CLIConfig{
		Port:     port,
		Config:   configPath,
		LogLevel: logLevel,
		Command:  command,
	}, nil
}

// expandEnvVars expands environment variables in command arguments
// Supports both $VAR and ${VAR} syntax
func expandEnvVars(args []string) []string {
	expanded := make([]string, len(args))
	for i, arg := range args {
		expanded[i] = os.ExpandEnv(arg)
	}
	return expanded
}

// loadConfigFile loads bridge configuration from a YAML file
func loadConfigFile(path string) (*bridge.BridgeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := bridge.DefaultBridgeConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// buildBridgeConfig builds the final bridge configuration from CLI args and config file
func buildBridgeConfig(cliConfig *CLIConfig) (*bridge.BridgeConfig, error) {
	var config *bridge.BridgeConfig

	// Load from config file if specified
	if cliConfig.Config != "" {
		var err error
		config, err = loadConfigFile(cliConfig.Config)
		if err != nil {
			return nil, err
		}
	} else {
		config = bridge.DefaultBridgeConfig()
	}

	// CLI flags override config file values
	if cliConfig.Port != "" {
		config.ListenAddr = ":" + cliConfig.Port
	}

	// Command from CLI takes precedence
	if len(cliConfig.Command) > 0 {
		// Expand environment variables in command arguments
		config.Command = expandEnvVars(cliConfig.Command)
	}

	return config, nil
}

// runBridge is the main entry point for the bridge command
func runBridge(cmd *cobra.Command, args []string) error {
	// Parse CLI configuration
	cliConfig, err := parseCLIConfig(cmd, args)
	if err != nil {
		return err
	}

	// Set up logging
	logger := logging.NewLogger(logging.Config{
		Level:  cliConfig.LogLevel,
		Pretty: true, // Use pretty logging for CLI
	})
	slog.SetDefault(logger)

	// Build bridge configuration
	bridgeConfig, err := buildBridgeConfig(cliConfig)
	if err != nil {
		logger.Error("Failed to build configuration", "error", err)
		return err
	}

	// Validate that we have a command to run
	if len(bridgeConfig.Command) == 0 {
		return fmt.Errorf("no command specified. Use: polis-bridge [flags] -- <command>")
	}

	logger.Info("Starting polis-bridge",
		"port", strings.TrimPrefix(bridgeConfig.ListenAddr, ":"),
		"command", bridgeConfig.Command,
		"log_level", cliConfig.LogLevel,
	)

	// Create bridge instance
	b := bridge.NewBridge(bridgeConfig, logger)

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Handle SIGHUP for config reload (placeholder for future implementation)
	sighupChan := make(chan os.Signal, 1)
	signal.Notify(sighupChan, syscall.SIGHUP)

	go func() {
		for {
			select {
			case sig := <-sigChan:
				logger.Info("Received shutdown signal", "signal", sig.String())
				cancel()
				return
			case <-sighupChan:
				logger.Info("Received SIGHUP, config reload not yet implemented")
				// TODO: Implement config hot reload in task 14
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start the bridge
	errCh := make(chan error, 1)
	go func() {
		errCh <- b.Start(ctx)
	}()

	// Wait for completion
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			logger.Error("Bridge error", "error", err)
			return err
		}
	case <-ctx.Done():
		// Give the bridge time to shut down gracefully
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := b.Stop(shutdownCtx); err != nil {
			logger.Error("Error during shutdown", "error", err)
		}
	}

	logger.Info("Bridge stopped")
	return nil
}
