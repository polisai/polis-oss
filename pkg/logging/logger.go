// Package logging provides structured logging configuration and utilities.
package logging

import (
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config holds logging configuration.
type Config struct {
	Level  string
	Pretty bool
}

// SetupLogger configures the global zerolog logger.
func SetupLogger(cfg Config) {
	var output io.Writer = os.Stdout

	if cfg.Pretty {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
	}

	// Use async writer for performance in production (if not pretty)
	if !cfg.Pretty {
		// 1000 buffer size, non-blocking
		output = zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.Out = os.Stdout
			w.NoColor = true
			w.TimeFormat = time.RFC3339
		})
		// Note: For true high-perf async, we'd use zerolog.DiodeWriter,
		// but ConsoleWriter is sufficient for now and safer.
	}

	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(level)
	log.Logger = zerolog.New(output).With().Timestamp().Logger()
}

// NewSlogLogger creates an slog.Logger that outputs to stdout.
func NewSlogLogger(cfg Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
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
