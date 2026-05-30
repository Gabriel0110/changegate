package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	colorBold  = "\x1b[1m"
	colorGreen = "\x1b[32m"
	colorReset = "\x1b[0m"
)

type renderer struct {
	out     io.Writer
	color   bool
	quiet   bool
	format  string
	outPath string
}

type jsonEnvelope struct {
	OK      bool   `json:"ok"`
	Command string `json:"command,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

type jsonError struct {
	Type     string `json:"type"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
	Help     string `json:"help,omitempty"`
	ExitCode int    `json:"exit_code"`
}

func newRenderer(out io.Writer, opts *options) renderer {
	return renderer{
		out:     out,
		color:   !opts.noColor,
		quiet:   opts.quiet,
		format:  opts.format,
		outPath: opts.outPath,
	}
}

func (r renderer) printf(format string, args ...any) {
	if r.quiet {
		return
	}
	if _, err := fmt.Fprintf(r.out, format, args...); err != nil {
		return
	}
}

func (r renderer) successWord(word string) string {
	if !r.color {
		return word
	}
	return colorGreen + colorBold + word + colorReset
}

func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}
