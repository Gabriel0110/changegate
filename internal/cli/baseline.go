package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"time"

	"github.com/Gabriel0110/changegate/internal/baseline"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
	"github.com/Gabriel0110/changegate/internal/rules"
	"github.com/spf13/cobra"
)

type baselineCreateOptions struct {
	planPaths     []string
	outPath       string
	expiresAt     string
	expiresInDays int
}

type baselineDiffOptions struct {
	planPaths         []string
	baselinePath      string
	maxAgeDays        int
	requireExpiration bool
}

func newBaselineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Create and compare accepted existing-risk baselines",
	}
	cmd.AddCommand(newBaselineCreateCommand())
	cmd.AddCommand(newBaselineDiffCommand())
	return cmd
}

func newBaselineCreateCommand() *cobra.Command {
	opts := &baselineCreateOptions{}
	cmd := &cobra.Command{
		Use:   "create --plan tfplan.json --out .changegate/baseline.json",
		Short: "Create a baseline from current ChangeGate findings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if len(opts.planPaths) == 0 {
				return usageError("baseline create requires at least one --plan", "Run changegate baseline create --plan tfplan.json --out .changegate/baseline.json.")
			}
			if opts.outPath == "" {
				return usageError("baseline create requires --out", "Write the baseline to a reviewed path such as .changegate/baseline.json.")
			}
			report, err := reportForBaseline(cmd, state, opts.planPaths)
			if err != nil {
				return err
			}
			expiresAt, err := baselineExpiration(opts.expiresAt, opts.expiresInDays)
			if err != nil {
				return err
			}
			file := baseline.Build(report.Findings, rules.DefaultPolicyPacks(), time.Now().UTC(), expiresAt)
			var buf bytes.Buffer
			if err := baseline.Write(&buf, file); err != nil {
				return internalError(err.Error(), "Report this as a ChangeGate bug.")
			}
			if err := os.MkdirAll(parentDir(opts.outPath), 0o755); err != nil {
				return inputError(err.Error(), "Check permissions for the baseline output directory.")
			}
			if err := os.WriteFile(opts.outPath, buf.Bytes(), 0o644); err != nil {
				return inputError(err.Error(), "Check permissions for the baseline output path.")
			}
			result := struct {
				Path      string         `json:"path"`
				Findings  int            `json:"findings"`
				ExpiresAt string         `json:"expires_at,omitempty"`
				Decision  model.Decision `json:"decision"`
			}{
				Path:      opts.outPath,
				Findings:  len(file.Findings),
				ExpiresAt: file.ExpiresAt,
				Decision:  report.Decision,
			}
			return writeCommandOutput(state, "baseline create", result, func(r renderer) {
				r.printf("Baseline: %s\n", opts.outPath)
				r.printf("Findings: %d\n", len(file.Findings))
				if file.ExpiresAt != "" {
					r.printf("Expires: %s\n", file.ExpiresAt)
				}
				r.printf("Next: scan with --baseline %s --new-only\n", opts.outPath)
			})
		},
	}
	cmd.Flags().StringArrayVar(&opts.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON; repeat for multiple plans")
	cmd.Flags().StringVar(&opts.outPath, "out", "", "baseline file path to write")
	cmd.Flags().StringVar(&opts.expiresAt, "expires-at", "", "RFC3339 baseline expiration timestamp")
	cmd.Flags().IntVar(&opts.expiresInDays, "expires-in-days", 0, "expire the baseline after this many days")
	return cmd
}

func newBaselineDiffCommand() *cobra.Command {
	opts := &baselineDiffOptions{}
	cmd := &cobra.Command{
		Use:   "diff --baseline .changegate/baseline.json --plan tfplan.json",
		Short: "Compare current findings to an existing baseline",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if opts.baselinePath == "" {
				return usageError("baseline diff requires --baseline", "Pass the baseline created by changegate baseline create.")
			}
			if len(opts.planPaths) == 0 {
				return usageError("baseline diff requires at least one --plan", "Pass current plan JSON with --plan.")
			}
			file, err := baseline.LoadFile(opts.baselinePath)
			if err != nil {
				return inputError(err.Error(), "Check the baseline path or recreate it.")
			}
			report, err := reportForBaseline(cmd, state, opts.planPaths)
			if err != nil {
				return err
			}
			result := baseline.Diff(file, report.Findings, time.Now().UTC(), opts.maxAgeDays, opts.requireExpiration)
			result.BaselinePath = opts.baselinePath
			return writeCommandOutput(state, "baseline diff", result, func(r renderer) {
				r.printf("Baseline: %s\n", opts.baselinePath)
				r.printf("New: %d\n", result.Summary.New)
				r.printf("Unchanged: %d\n", result.Summary.Unchanged)
				r.printf("Changed: %d\n", result.Summary.Changed)
				r.printf("Stale: %d\n", result.Summary.Stale)
				r.printf("New high risks: %d\n", result.RiskMovement.NewHigh)
				r.printf("Existing unchanged risks: %d\n", result.RiskMovement.ExistingUnchanged)
				r.printf("Existing worsened risks: %d\n", result.RiskMovement.ExistingWorsened)
				r.printf("Resolved high risks: %d\n", result.RiskMovement.ResolvedHigh)
				for _, warning := range result.Warnings {
					r.printf("Warning: %s\n", warning)
				}
				for _, entry := range result.New {
					r.printf("New finding: %s %s\n", entry.RuleID, entry.Resource)
				}
				for _, entry := range result.Changed {
					if entry.ResourceMovedFrom != "" {
						r.printf("Changed finding: %s %s moved from %s\n", entry.RuleID, entry.Resource, entry.ResourceMovedFrom)
						continue
					}
					r.printf("Changed finding: %s %s\n", entry.RuleID, entry.Resource)
				}
				for _, entry := range result.ExistingWorsened {
					r.printf("Worsened existing risk: %s %s\n", entry.RuleID, entry.Resource)
				}
				for _, entry := range result.ExistingImproved {
					r.printf("Improved existing risk: %s %s\n", entry.RuleID, entry.Resource)
				}
				for _, entry := range result.Stale {
					r.printf("Stale baseline entry: %s %s\n", entry.RuleID, entry.Resource)
				}
			})
		},
	}
	cmd.Flags().StringArrayVar(&opts.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON; repeat for multiple plans")
	cmd.Flags().StringVar(&opts.baselinePath, "baseline", "", "baseline file path")
	cmd.Flags().IntVar(&opts.maxAgeDays, "max-age-days", 0, "warn when baseline is older than this many days")
	cmd.Flags().BoolVar(&opts.requireExpiration, "require-expiration", false, "warn when baseline has no expires_at value")
	return cmd
}

func reportForBaseline(cmd *cobra.Command, state *appState, planPaths []string) (output.Report, error) {
	policyConfig, selection, registry, err := loadPolicyForScan(state.opts)
	if err != nil {
		return output.Report{}, err
	}
	policyConfig.Mode = model.PolicyModeAudit
	report, err := scanPlans(cmd.Context(), state.stdin, planPaths, "", state.opts, registry, selection, policyConfig, nil, nil, false)
	if err != nil {
		return output.Report{}, err
	}
	return report, nil
}

func baselineExpiration(expiresAt string, expiresInDays int) (*time.Time, error) {
	if expiresAt != "" && expiresInDays > 0 {
		return nil, usageError("--expires-at and --expires-in-days cannot be combined", "Choose one expiration mode.")
	}
	if expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, usageError("--expires-at must be RFC3339", "Example: --expires-at 2026-08-01T00:00:00Z")
		}
		return &parsed, nil
	}
	if expiresInDays > 0 {
		parsed := time.Now().UTC().Add(time.Duration(expiresInDays) * 24 * time.Hour)
		return &parsed, nil
	}
	return nil, nil
}

func parentDir(path string) string {
	dir := filepath.Dir(path)
	if dir == "" {
		return "."
	}
	return dir
}
