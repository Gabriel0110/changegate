package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Gabriel0110/changegate/internal/output"
	"github.com/Gabriel0110/changegate/internal/risktest"
	"github.com/spf13/cobra"
)

type testOptions struct {
	junitPath string
	update    bool
	timeout   string
}

func newTestCommand() *cobra.Command {
	opts := &testOptions{}
	cmd := &cobra.Command{
		Use:   "test [path]",
		Short: "Run ChangeGate risk regression tests",
		Long: `Run ChangeGate risk regression tests from a manifest file or directory.

Risk tests assert deployment decisions, findings, attack paths, graph paths,
risk movement, waivers, and snapshots against Terraform/OpenTofu plan fixtures.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageError("test accepts at most one path", "Run changegate test or changegate test ./changegate-tests.")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			result, err := risktest.Runner{
				Executor:        riskTestExecutor{state: state, timeout: opts.timeout},
				UpdateSnapshots: opts.update,
			}.RunPath(cmd.Context(), path)
			if err != nil {
				return inputError(err.Error(), "Pass a risk test manifest file or a directory containing changegate-test.yaml.")
			}
			if opts.junitPath != "" {
				body, err := risktest.RenderJUnit(result)
				if err != nil {
					return internalError(err.Error(), "Report this as a ChangeGate bug.")
				}
				if err := os.MkdirAll(parentDir(opts.junitPath), 0o755); err != nil {
					return inputError(fmt.Sprintf("create JUnit output directory: %v", err), "Check the --junit path and directory permissions.")
				}
				if err := os.WriteFile(opts.junitPath, body, 0o644); err != nil {
					return inputError(fmt.Sprintf("write JUnit output %q: %v", opts.junitPath, err), "Check the --junit path and directory permissions.")
				}
			}
			if !result.Passed {
				state.opts.exitCode = exitBlocked
			}
			return writeRiskTestResult(state, result)
		},
	}
	cmd.Flags().StringVar(&opts.junitPath, "junit", "", "write JUnit XML report to this path")
	cmd.Flags().BoolVar(&opts.update, "update", false, "update risk test snapshots instead of comparing them")
	cmd.Flags().StringVar(&opts.timeout, "timeout", "", "per-test scan timeout such as 30s, 2m, or 5m")
	return cmd
}

type riskTestExecutor struct {
	state   *appState
	timeout string
}

func (e riskTestExecutor) Execute(ctx context.Context, request risktest.ExecutionRequest) (output.Report, error) {
	if e.state == nil {
		return output.Report{}, internalError("risk test executor was not initialized", "Report this as a ChangeGate bug.")
	}
	previousPolicy := e.state.opts.policy
	if request.ConfigPath != "" {
		e.state.opts.policy = request.ConfigPath
	}
	defer func() {
		e.state.opts.policy = previousPolicy
	}()
	report, err := buildScanReportFromRiskTest(ctx, e.state, request, e.timeout)
	if err != nil {
		return output.Report{}, err
	}
	return report, nil
}

func buildScanReportFromRiskTest(ctx context.Context, state *appState, request risktest.ExecutionRequest, timeout string) (output.Report, error) {
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	return buildScanReport(cmd, state, &scanOptions{
		planPaths:    []string{request.PlanPath},
		baselinePath: request.BaselinePath,
		newOnly:      request.NewOnly,
		contextFile:  request.ContextFile,
		timeout:      timeout,
	})
}

func writeRiskTestResult(state *appState, result risktest.Result) error {
	var body []byte
	var err error
	switch state.opts.format {
	case "", "table":
		body = []byte(risktest.RenderText(result))
	case "json":
		body, err = json.MarshalIndent(result, "", "  ")
		if err == nil {
			body = append(body, '\n')
		}
	case "junit":
		body, err = risktest.RenderJUnit(result)
	default:
		return usageError("--format must be table, json, or junit for changegate test", "Use --junit to write JUnit XML while keeping table or JSON output.")
	}
	if err != nil {
		return internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	if state.opts.outPath != "" {
		if err := os.MkdirAll(parentDir(state.opts.outPath), 0o755); err != nil {
			return inputError(fmt.Sprintf("create output directory: %v", err), "Check the --out path and directory permissions.")
		}
		if err := os.WriteFile(state.opts.outPath, body, 0o644); err != nil {
			return inputError(fmt.Sprintf("write output %q: %v", state.opts.outPath, err), "Check the --out path and directory permissions.")
		}
		return nil
	}
	if _, err := state.renderer.out.Write(body); err != nil {
		return err
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		_, err := fmt.Fprintln(state.renderer.out)
		return err
	}
	return nil
}
