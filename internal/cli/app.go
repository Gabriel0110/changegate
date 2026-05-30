package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Gabriel0110/changegate/internal/logging"
	"github.com/spf13/cobra"
)

const troubleshootingHelp = "docs/troubleshooting.md"

type appContextKey struct{}

type appState struct {
	opts     *options
	renderer renderer
	logger   *slog.Logger
	stdin    io.Reader
}

// Execute runs the ChangeGate CLI and returns a stable process exit code.
func Execute(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	opts := defaultOptions()
	root := newRootCommand(ctx, opts, stdin, stdout, stderr)
	root.SetArgs(args)

	if err := root.ExecuteContext(ctx); err != nil {
		return handleError(err, args, opts, stdout, stderr)
	}
	if opts.exitCode != 0 {
		return opts.exitCode
	}

	return exitAllowed
}

func newRootCommand(ctx context.Context, opts *options, stdin io.Reader, stdout io.Writer, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "changegate",
		Short:         "Graph-aware Terraform/OpenTofu deployment risk gate",
		Long:          rootLongDescription(),
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateEnum("--format", opts.format, validFormats); err != nil {
				return err
			}
			if err := validateEnum("--mode", opts.mode, validModes); err != nil {
				return err
			}
			state := &appState{
				opts:     opts,
				renderer: newRenderer(stdout, opts),
				logger:   logging.New(stderr, opts.verbose, opts.debug),
				stdin:    stdin,
			}
			cmd.SetContext(context.WithValue(ctx, appContextKey{}, state))
			return nil
		},
	}

	root.SetOut(stdout)
	root.SetErr(stderr)

	flags := root.PersistentFlags()
	flags.StringVar(&opts.format, "format", opts.format, "output format: table, json, sarif, junit, markdown, github-step-summary, github-annotations, gitlab-code-quality, pr-comment, audit-bundle")
	flags.StringVar(&opts.outPath, "out", opts.outPath, "write output to a file")
	flags.StringVar(&opts.policy, "policy", opts.policy, "path to .changegate.yaml policy file")
	flags.StringVar(&opts.cacheDir, "cache-dir", opts.cacheDir, "cache directory for policy packs and cloud context")
	flags.StringVar(&opts.mode, "mode", opts.mode, "enforcement mode: block, warn, audit")
	flags.BoolVar(&opts.noColor, "no-color", opts.noColor, "disable ANSI color output")
	flags.BoolVar(&opts.quiet, "quiet", opts.quiet, "suppress non-essential human output")
	flags.BoolVar(&opts.verbose, "verbose", opts.verbose, "enable informational diagnostics")
	flags.BoolVar(&opts.debug, "debug", opts.debug, "enable debug diagnostics without secrets")

	root.AddCommand(newVersionCommand())
	root.AddCommand(newDoctorCommand())
	root.AddCommand(newScanCommand())
	root.AddCommand(newImpactCommand())
	root.AddCommand(newGraphCommand())
	root.AddCommand(newExplainCommand())
	root.AddCommand(newCICommand())
	root.AddCommand(newRulesCommand())
	root.AddCommand(newPolicyCommand())
	root.AddCommand(newBaselineCommand())
	root.AddCommand(newWaiverCommand())
	root.AddCommand(newContextCommand())
	root.AddCommand(newCompletionCommand(root))

	return root
}

func appFrom(cmd *cobra.Command) (*appState, error) {
	state, ok := cmd.Context().Value(appContextKey{}).(*appState)
	if !ok || state == nil {
		return nil, internalError("CLI context was not initialized", "Report this as a ChangeGate bug.")
	}
	return state, nil
}

func handleError(err error, args []string, opts *options, stdout io.Writer, stderr io.Writer) int {
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		exitErr = internalError(err.Error(), "Run again with --debug. If the problem persists, report a bug.")
	}

	if wantsJSON(args, opts) {
		target := stdout
		if exitErr.Code != exitAllowed {
			target = stderr
		}
		if err := writeJSON(target, jsonEnvelope{
			OK: false,
			Error: jsonError{
				Type:     exitErr.Kind,
				Message:  exitErr.Error(),
				Fix:      exitErr.Fix,
				Help:     troubleshootingHelp,
				ExitCode: exitErr.Code,
			},
		}); err != nil {
			if _, writeErr := fmt.Fprintf(stderr, "Error: %s\n", exitErr.Error()); writeErr != nil {
				return exitErr.Code
			}
		}
		return exitErr.Code
	}

	if _, err := fmt.Fprintf(stderr, "Error: %s\n", exitErr.Error()); err != nil {
		return exitErr.Code
	}
	if exitErr.Fix != "" {
		if _, err := fmt.Fprintf(stderr, "Fix: %s\n", exitErr.Fix); err != nil {
			return exitErr.Code
		}
	}
	if _, err := fmt.Fprintf(stderr, "Help: %s\n", troubleshootingHelp); err != nil {
		return exitErr.Code
	}
	if _, err := fmt.Fprintf(stderr, "Exit code: %d\n", exitErr.Code); err != nil {
		return exitErr.Code
	}

	return exitErr.Code
}

func wantsJSON(args []string, opts *options) bool {
	if opts != nil && opts.format == "json" {
		return true
	}
	for i, arg := range args {
		if arg == "--format=json" || arg == "-o=json" {
			return true
		}
		if arg == "--format" && i+1 < len(args) && args[i+1] == "json" {
			return true
		}
	}
	return false
}

func rootLongDescription() string {
	return strings.TrimSpace(`ChangeGate analyzes Terraform/OpenTofu plan JSON before apply,
builds a graph of what is actually changing, and returns one deployment decision:
allow, warn, or block.

Fastest path:
  terraform plan -out=tfplan
  terraform show -json tfplan > tfplan.json
  changegate scan --plan tfplan.json`)
}

func writeCommandOutput(state *appState, command string, result any, table func(renderer)) error {
	if state.opts.outPath != "" {
		file, err := os.Create(state.opts.outPath)
		if err != nil {
			return fmt.Errorf("create output file %q: %w", state.opts.outPath, err)
		}
		if err := writeJSON(file, jsonEnvelope{OK: true, Command: command, Result: result}); err != nil {
			if closeErr := file.Close(); closeErr != nil {
				return fmt.Errorf("close output file %q after write error: %w", state.opts.outPath, closeErr)
			}
			return err
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close output file %q: %w", state.opts.outPath, err)
		}
		return nil
	}

	if state.opts.format == "json" {
		return writeJSON(state.renderer.out, jsonEnvelope{OK: true, Command: command, Result: result})
	}

	table(state.renderer)
	return nil
}
