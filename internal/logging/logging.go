// Package logging configures structured logging for CLI diagnostics.
package logging

import (
	"io"
	"log/slog"
)

// New returns a slog logger configured for ChangeGate CLI verbosity flags.
func New(w io.Writer, verbose bool, debug bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelInfo
	}
	if debug {
		level = slog.LevelDebug
	}

	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
	}))
}
