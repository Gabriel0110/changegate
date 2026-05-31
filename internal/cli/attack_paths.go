package cli

import (
	"github.com/Gabriel0110/changegate/internal/attackpath"
	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	graphpkg "github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/visual"
	"github.com/spf13/cobra"
)

type attackPathOptions struct {
	planPaths       []string
	principal       string
	toSensitiveData bool
	cloudContext    string
	contextFile     string
	maxDepth        int
	maxPaths        int
}

func newAttackPathsCommand() *cobra.Command {
	opts := &attackPathOptions{}
	cmd := &cobra.Command{
		Use:   "attack-paths --plan tfplan.json",
		Short: "Inspect high-signal infrastructure attack paths without enforcing policy",
		Long: `Inspect attack paths from Terraform/OpenTofu plans and optional cloud
context. This command is review-oriented: it renders deterministic path evidence
without evaluating deployment policy or returning a block exit code.`,
		Args: func(_ *cobra.Command, _ []string) error {
			return validateAttackPathsFormat(opts)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			paths, err := buildAttackPaths(cmd, state, opts)
			if err != nil {
				return err
			}
			return writeAttackPaths(state, paths)
		},
	}
	cmd.Flags().StringArrayVar(&opts.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON produced by show -json; repeat for multiple plans")
	cmd.Flags().StringVar(&opts.principal, "principal", "", "only include attack paths starting from this IAM principal")
	cmd.Flags().BoolVar(&opts.toSensitiveData, "to-sensitive-data", false, "only include public-to-sensitive-data attack paths")
	cmd.Flags().StringVar(&opts.cloudContext, "cloud-context", "", "optional cloud context provider: aws")
	cmd.Flags().StringVar(&opts.contextFile, "context-file", "", "offline cloud context snapshot file")
	cmd.Flags().IntVar(&opts.maxDepth, "max-depth", 12, "maximum graph path depth")
	cmd.Flags().IntVar(&opts.maxPaths, "max-paths", 25, "maximum attack paths to return")
	cmd.AddCommand(newAttackPathsVisualizeCommand())
	return cmd
}

func newAttackPathsVisualizeCommand() *cobra.Command {
	opts := &attackPathOptions{}
	cmd := &cobra.Command{
		Use:   "visualize --plan tfplan.json",
		Short: "Write a self-contained interactive HTML attack-path visualization",
		Long: `Write a self-contained HTML visualization for detected attack paths. The
output includes filtering, role toggles, highlighted path edges, and a node
evidence inspector without requiring a hosted service.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateAttackPathsFormat(opts); err != nil {
				return err
			}
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			paths, err := buildAttackPaths(cmd, state, opts)
			if err != nil {
				return err
			}
			return writeBytes(state, visual.RenderHTML(visual.NewAttackPathDiagram(paths)))
		},
	}
	cmd.Flags().StringArrayVar(&opts.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON produced by show -json; repeat for multiple plans")
	cmd.Flags().StringVar(&opts.principal, "principal", "", "only include attack paths starting from this IAM principal")
	cmd.Flags().BoolVar(&opts.toSensitiveData, "to-sensitive-data", false, "only include public-to-sensitive-data attack paths")
	cmd.Flags().StringVar(&opts.cloudContext, "cloud-context", "", "optional cloud context provider: aws")
	cmd.Flags().StringVar(&opts.contextFile, "context-file", "", "offline cloud context snapshot file")
	cmd.Flags().IntVar(&opts.maxDepth, "max-depth", 12, "maximum graph path depth")
	cmd.Flags().IntVar(&opts.maxPaths, "max-paths", 25, "maximum attack paths to return")
	return cmd
}

func validateAttackPathsFormat(opts *attackPathOptions) error {
	if len(opts.planPaths) == 0 {
		return usageError("missing required --plan path", "Generate plan JSON with terraform show -json tfplan > tfplan.json, then run changegate attack-paths --plan tfplan.json.")
	}
	if opts.maxDepth < 0 {
		return usageError("--max-depth must be zero or greater", "Use 0 for the default depth, or pass a positive cap.")
	}
	if opts.maxPaths < 0 {
		return usageError("--max-paths must be zero or greater", "Use 0 for all detected paths, or pass a positive cap.")
	}
	return nil
}

func buildAttackPaths(cmd *cobra.Command, state *appState, opts *attackPathOptions) ([]attackpath.AttackPath, error) {
	if err := prepareCache(state.opts.cacheDir); err != nil {
		return nil, err
	}
	contextSnapshot, _, err := loadCloudContext(state.opts.cacheDir, opts.cloudContext, opts.contextFile)
	if err != nil {
		return nil, err
	}
	paths := make([]attackpath.AttackPath, 0)
	for _, planPath := range opts.planPaths {
		resourceGraph, err := loadAttackPathGraph(cmd, state, planPath, contextSnapshot)
		if err != nil {
			return nil, err
		}
		paths = append(paths, attackpath.DetectPublicToSensitive(resourceGraph, attackpath.DetectionOptions{
			MaxDepth: opts.maxDepth,
			MaxPaths: perDetectorPathLimit(opts.maxPaths),
		})...)
		if !opts.toSensitiveData {
			paths = append(paths, attackpath.DetectIAMPrivilegeEscalation(resourceGraph, attackpath.IAMDetectionOptions{IncludeWarnings: true})...)
		}
	}
	paths = filterAttackPaths(paths, opts)
	paths = attackpath.Normalize(paths)
	if opts.maxPaths > 0 && len(paths) > opts.maxPaths {
		paths = append([]attackpath.AttackPath(nil), paths[:opts.maxPaths]...)
	}
	return paths, nil
}

func loadAttackPathGraph(cmd *cobra.Command, state *appState, planPath string, contextSnapshot *cloudcontext.Snapshot) (*graphpkg.Graph, error) {
	_, resourceGraph, err := loadGraphPlan(cmd, state, planPath)
	if err != nil {
		return nil, err
	}
	if contextSnapshot != nil {
		merged, _ := graphpkg.MergeContext(resourceGraph, *contextSnapshot)
		resourceGraph = merged
	}
	return resourceGraph, nil
}

func filterAttackPaths(paths []attackpath.AttackPath, opts *attackPathOptions) []attackpath.AttackPath {
	out := make([]attackpath.AttackPath, 0, len(paths))
	for _, path := range paths {
		if opts.toSensitiveData && path.Type != attackpath.TypePublicToSensitiveData {
			continue
		}
		if opts.principal != "" && path.Principal != opts.principal {
			continue
		}
		out = append(out, path)
	}
	return out
}

func writeAttackPaths(state *appState, paths []attackpath.AttackPath) error {
	var (
		body []byte
		err  error
	)
	switch state.opts.format {
	case "", "table", "markdown":
		body = []byte(attackpath.RenderMarkdown(paths))
	case "json":
		body, err = attackpath.RenderJSON(paths)
	case "dot":
		body = visual.RenderDOT(visual.NewAttackPathDiagram(paths))
	case "mermaid":
		body = visual.RenderMermaid(visual.NewAttackPathDiagram(paths))
	default:
		return usageError("--format for attack-paths must be markdown, json, dot, or mermaid", "Run changegate attack-paths --format markdown, json, dot, or mermaid.")
	}
	if err != nil {
		return internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	return writeBytes(state, body)
}

func perDetectorPathLimit(limit int) int {
	if limit <= 0 {
		return 5
	}
	return limit
}
