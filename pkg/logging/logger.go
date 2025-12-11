// Package logging provides structured logging configuration and utilities.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Config holds logging configuration.
type Config struct {
	Level  string
	Pretty bool
}

// NewLogger creates an slog.Logger that outputs to stdout.
func NewLogger(cfg Config) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if cfg.Pretty {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
