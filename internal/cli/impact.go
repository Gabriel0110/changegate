package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/Gabriel0110/changegate/internal/impact"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/spf13/cobra"
)

type impactOptions struct {
	scan        scanOptions
	auditBundle string
	maxPaths    int
}

func newImpactCommand() *cobra.Command {
	opts := &impactOptions{}

	cmd := &cobra.Command{
		Use:   "impact --plan tfplan.json",
		Short: "Generate a Security Impact Statement for Terraform/OpenTofu plans",
		Long: `Generate a Security Impact Statement from the same plan, policy,
baseline, waiver, import, and cloud-context inputs used by changegate scan.`,
		Args: func(_ *cobra.Command, _ []string) error {
			return validateImpactFormat(opts)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			report, err := buildScanReport(cmd, state, &opts.scan)
			if err != nil {
				return err
			}
			statement, err := impact.Build(report, impact.Options{
				GeneratedAt:        time.Now().UTC(),
				PlansScanned:       len(opts.scan.planPaths),
				TopFindingsLimit:   impactLimit(opts.scan.maxFindings, impact.DefaultTopFindingsLimit),
				TopGraphPathsLimit: impactLimit(opts.maxPaths, impact.DefaultTopGraphPathsLimit),
				AttackPathsLimit:   impactLimit(opts.maxPaths, impact.DefaultAttackPathsLimit),
			})
			if err != nil {
				return internalError(err.Error(), "Report this as a ChangeGate bug.")
			}
			if report.Decision == model.DecisionBlock {
				state.opts.exitCode = exitBlocked
			}
			if opts.auditBundle != "" {
				body, err := impact.RenderAuditBundle(statement, report)
				if err != nil {
					return internalError(err.Error(), "Report this as a ChangeGate bug.")
				}
				if err := os.WriteFile(opts.auditBundle, body, 0o644); err != nil {
					return inputError(fmt.Sprintf("write impact audit bundle %q: %v", opts.auditBundle, err), "Check the output path and directory permissions.")
				}
			}
			return writeImpactStatement(state, statement)
		},
	}

	addImpactFlags(cmd, opts)
	return cmd
}

func addImpactFlags(cmd *cobra.Command, opts *impactOptions) {
	cmd.Flags().StringArrayVar(&opts.scan.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON produced by show -json; repeat for multiple plans")
	cmd.Flags().StringVar(&opts.scan.branch, "branch", "", "branch name for branch-specific policy thresholds")
	cmd.Flags().StringVar(&opts.scan.baselinePath, "baseline", "", "baseline file used to classify and suppress existing findings")
	cmd.Flags().BoolVar(&opts.scan.newOnly, "new-only", false, "only enforce findings not present in the baseline unless existing risk worsened")
	cmd.Flags().StringVar(&opts.scan.cloudContext, "cloud-context", "", "optional cloud context provider: aws")
	cmd.Flags().StringVar(&opts.scan.contextFile, "context-file", "", "offline cloud context snapshot file")
	cmd.Flags().StringArrayVar(&opts.scan.importSARIF, "import-sarif", nil, "import SARIF 2.1.0 findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importJSON, "import-json", nil, "import generic ChangeGate JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importCheckov, "import-checkov", nil, "import Checkov JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importTrivy, "import-trivy", nil, "import Trivy JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importKICS, "import-kics", nil, "import KICS JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importGrype, "import-grype", nil, "import Grype JSON findings as external evidence; repeatable")
	cmd.Flags().BoolVar(&opts.scan.failImport, "fail-on-import-error", false, "fail when an external scanner output cannot be imported")
	cmd.Flags().StringVar(&opts.scan.timeout, "timeout", "", "overall impact analysis timeout such as 30s, 2m, or 5m")
	cmd.Flags().IntVar(&opts.scan.maxFindings, "max-findings", 0, "maximum findings to include in the impact statement; 0 uses the default")
	cmd.Flags().IntVar(&opts.maxPaths, "max-paths", 0, "maximum graph and attack paths to include; 0 uses the default")
	cmd.Flags().StringVar(&opts.auditBundle, "audit-bundle", "", "write a deterministic impact evidence bundle zip to this path")
}

func validateImpactFormat(opts *impactOptions) error {
	if opts.scan.maxFindings < 0 {
		return usageError("--max-findings must be zero or greater", "Use 0 for the default impact finding limit, or pass a positive cap.")
	}
	if opts.maxPaths < 0 {
		return usageError("--max-paths must be zero or greater", "Use 0 for the default path limit, or pass a positive cap.")
	}
	return nil
}

func impactLimit(value int, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func writeImpactStatement(state *appState, statement impact.Statement) error {
	var (
		body []byte
		err  error
	)
	switch state.opts.format {
	case "", "table", "markdown":
		body = []byte(impact.RenderMarkdown(statement))
	case "json":
		body, err = impact.RenderJSON(statement)
	default:
		return usageError("--format for impact must be markdown or json", "Run changegate impact --format markdown or changegate impact --format json.")
	}
	if err != nil {
		return internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	if state.opts.outPath != "" {
		if err := os.WriteFile(state.opts.outPath, body, 0o644); err != nil {
			return inputError(fmt.Sprintf("write output %q: %v", state.opts.outPath, err), "Check the output path and directory permissions.")
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
