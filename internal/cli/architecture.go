package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/architecture"
	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	graphpkg "github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/visual"
	"github.com/spf13/cobra"
)

type architectureOptions struct {
	contextFile       string
	beforeContextFile string
	afterContextFile  string
	collectValue      string
	regionsValue      string
	profile           string
	timeoutValue      string
	tagValues         []string
	view              string
	resource          string
	maxDepth          int
	maxNodes          int
	layout            string
	render            string
	engine            string
}

type architectureGraphResult struct {
	Version int                                    `json:"version"`
	Summary architecture.Summary                   `json:"summary"`
	Nodes   map[graphpkg.ResourceID]*graphpkg.Node `json:"nodes"`
	Edges   []graphpkg.Edge                        `json:"edges"`
}

type architectureDiffResult struct {
	Version      int                  `json:"version"`
	View         string               `json:"view"`
	Before       architecture.Summary `json:"before"`
	After        architecture.Summary `json:"after"`
	AddedNodes   []string             `json:"added_nodes,omitempty"`
	RemovedNodes []string             `json:"removed_nodes,omitempty"`
	ChangedNodes []string             `json:"changed_nodes,omitempty"`
	AddedEdges   []string             `json:"added_edges,omitempty"`
	RemovedEdges []string             `json:"removed_edges,omitempty"`
}

func newArchitectureCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "architecture",
		Short: "Visualize cloud architecture from read-only context snapshots",
		Long: `Visualize cloud architecture from read-only cloud context snapshots.

Architecture commands do not evaluate policy rules or return a deployment
decision. They turn a redacted AWS context snapshot into account, network,
public-exposure, data, IAM, compute, or resource-focused diagrams.`,
	}
	root.AddCommand(newArchitectureAWSCommand())
	return root
}

func newArchitectureAWSCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "aws",
		Short: "Visualize AWS account architecture",
	}
	root.AddCommand(newArchitectureAWSSummaryCommand())
	root.AddCommand(newArchitectureAWSExportCommand())
	root.AddCommand(newArchitectureAWSVisualizeCommand())
	root.AddCommand(newArchitectureAWSRenderCommand())
	root.AddCommand(newArchitectureAWSDiffCommand())
	return root
}

func newArchitectureAWSSummaryCommand() *cobra.Command {
	opts := defaultArchitectureOptions()
	cmd := &cobra.Command{
		Use:   "summary [--context-file aws-context.json]",
		Short: "Summarize an AWS architecture snapshot",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			snapshot, diagnostics, err := loadArchitectureSnapshot(cmd, opts)
			if err != nil {
				return err
			}
			g, graphDiagnostics := architecture.BuildGraph(snapshot)
			diagnostics = append(diagnostics, graphDiagnostics...)
			view, truncated, err := architecture.BuildView(g, architecture.Options{
				View:     opts.view,
				Resource: opts.resource,
				MaxDepth: opts.maxDepth,
				MaxNodes: opts.maxNodes,
			})
			if err != nil {
				return usageError(err.Error(), "Use --view account, network, public-exposure, data, iam, compute, or resource.")
			}
			summary := architecture.Summarize(snapshot, view, opts.view, diagnostics, truncated)
			return writeArchitectureSummary(state, summary)
		},
	}
	addArchitectureSnapshotFlags(cmd, opts)
	addArchitectureViewFlags(cmd, opts)
	return cmd
}

func newArchitectureAWSExportCommand() *cobra.Command {
	opts := defaultArchitectureOptions()
	cmd := &cobra.Command{
		Use:   "export [--context-file aws-context.json] --format json|dot|mermaid",
		Short: "Export an AWS architecture graph",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			snapshot, diagnostics, err := loadArchitectureSnapshot(cmd, opts)
			if err != nil {
				return err
			}
			view, summary, err := buildArchitectureView(snapshot, diagnostics, opts)
			if err != nil {
				return err
			}
			diagram := visual.NewGraphDiagram(view, visual.GraphOptions{
				Title:       architecture.Title(opts.view),
				Description: architecture.Description(snapshot, opts.view, summary.Truncated),
			})
			switch state.opts.format {
			case "json":
				result := architectureGraphResult{Version: cloudcontext.Version, Summary: summary, Nodes: view.Nodes, Edges: view.Edges}
				return writeGraphJSON(state, result)
			case "dot", "mermaid":
				return writeGraphDiagram(state, diagram)
			default:
				return usageError("architecture aws export requires --format json, dot, or mermaid", "Run changegate architecture aws export --context-file aws-context.json --format json.")
			}
		},
	}
	addArchitectureSnapshotFlags(cmd, opts)
	addArchitectureViewFlags(cmd, opts)
	return cmd
}

func newArchitectureAWSVisualizeCommand() *cobra.Command {
	opts := defaultArchitectureOptions()
	cmd := &cobra.Command{
		Use:   "visualize [--context-file aws-context.json] --out architecture.html",
		Short: "Write a self-contained interactive AWS architecture diagram",
		Long: `Write a self-contained interactive AWS architecture diagram.

The output works offline, requires no hosted service, and supports search,
filters, zooming, panning, node dragging, and resource details.

Pass --context-file to render a saved redacted snapshot. Without --context-file,
ChangeGate collects all supported read-only AWS context groups before rendering.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			snapshot, diagnostics, err := loadArchitectureSnapshot(cmd, opts)
			if err != nil {
				return err
			}
			view, summary, err := buildArchitectureView(snapshot, diagnostics, opts)
			if err != nil {
				return err
			}
			switch normalizeArchitectureLayout(opts.layout, opts.view) {
			case "map":
				return writeBytes(state, architecture.RenderHTML(snapshot, view, summary))
			case "graph":
				diagram := visual.NewGraphDiagram(view, visual.GraphOptions{
					Title:       architecture.Title(opts.view),
					Description: architecture.Description(snapshot, opts.view, summary.Truncated),
				})
				return writeBytes(state, visual.RenderHTML(diagram))
			default:
				return usageError("--layout must be map or graph", "Use --layout map for account architecture or --layout graph for relationship graph views.")
			}
		},
	}
	addArchitectureSnapshotFlags(cmd, opts)
	addArchitectureViewFlags(cmd, opts)
	cmd.Flags().StringVar(&opts.layout, "layout", opts.layout, "HTML layout: auto, map, or graph")
	return cmd
}

func newArchitectureAWSRenderCommand() *cobra.Command {
	opts := defaultArchitectureOptions()
	opts.render = "svg"
	opts.engine = "graphviz"
	cmd := &cobra.Command{
		Use:   "render [--context-file aws-context.json] --out architecture.svg",
		Short: "Render an AWS architecture diagram with Graphviz",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if state.opts.outPath == "" {
				return usageError("architecture aws render requires --out", "Pass an output file, for example --out architecture.svg.")
			}
			if opts.engine != "graphviz" {
				return usageError("--engine must be graphviz", "Graphviz is the only external renderer supported by this release.")
			}
			if !isGraphvizRenderFormat(opts.render) {
				return usageError("--render-format must be svg, png, or pdf", "Use --render-format svg for CI-friendly review artifacts.")
			}
			snapshot, diagnostics, err := loadArchitectureSnapshot(cmd, opts)
			if err != nil {
				return err
			}
			view, summary, err := buildArchitectureView(snapshot, diagnostics, opts)
			if err != nil {
				return err
			}
			diagram := visual.NewGraphDiagram(view, visual.GraphOptions{
				Title:       architecture.Title(opts.view),
				Description: architecture.Description(snapshot, opts.view, summary.Truncated),
			})
			body, err := runGraphviz(cmd.Context(), "dot", opts.render, visual.RenderDOT(diagram))
			if err != nil {
				return err
			}
			if err := os.WriteFile(state.opts.outPath, body, 0o644); err != nil {
				return inputError(fmt.Sprintf("write output %q: %v", state.opts.outPath, err), "Check the output path and directory permissions.")
			}
			return nil
		},
	}
	addArchitectureSnapshotFlags(cmd, opts)
	addArchitectureViewFlags(cmd, opts)
	cmd.Flags().StringVar(&opts.engine, "engine", opts.engine, "external renderer engine: graphviz")
	cmd.Flags().StringVar(&opts.render, "render-format", opts.render, "rendered artifact format: svg, png, or pdf")
	return cmd
}

func newArchitectureAWSDiffCommand() *cobra.Command {
	opts := defaultArchitectureOptions()
	cmd := &cobra.Command{
		Use:   "diff --before-context-file old.json --after-context-file new.json",
		Short: "Compare two AWS architecture snapshots",
		Long: `Compare two redacted AWS context snapshots for a selected architecture view.

The diff reports added, removed, and changed resources plus relationship changes.
It does not evaluate deployment policy rules or contact AWS.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if strings.TrimSpace(opts.beforeContextFile) == "" || strings.TrimSpace(opts.afterContextFile) == "" {
				return usageError("architecture aws diff requires --before-context-file and --after-context-file", "Pass two redacted snapshots to compare.")
			}
			beforeSnapshot, err := cloudcontext.LoadFile(opts.beforeContextFile)
			if err != nil {
				return inputError(err.Error(), "Check --before-context-file.")
			}
			afterSnapshot, err := cloudcontext.LoadFile(opts.afterContextFile)
			if err != nil {
				return inputError(err.Error(), "Check --after-context-file.")
			}
			beforeView, beforeSummary, err := buildArchitectureView(beforeSnapshot, nil, opts)
			if err != nil {
				return err
			}
			afterView, afterSummary, err := buildArchitectureView(afterSnapshot, nil, opts)
			if err != nil {
				return err
			}
			result := diffArchitectureViews(opts.view, beforeSummary, afterSummary, beforeView, afterView)
			return writeArchitectureDiff(state, result)
		},
	}
	cmd.Flags().StringVar(&opts.beforeContextFile, "before-context-file", "", "older AWS context snapshot path")
	cmd.Flags().StringVar(&opts.afterContextFile, "after-context-file", "", "newer AWS context snapshot path")
	addArchitectureViewFlags(cmd, opts)
	return cmd
}

func defaultArchitectureOptions() *architectureOptions {
	return &architectureOptions{
		view:         architecture.ViewAccount,
		timeoutValue: "2m",
		maxDepth:     4,
		maxNodes:     300,
		layout:       "auto",
	}
}

func addArchitectureSnapshotFlags(cmd *cobra.Command, opts *architectureOptions) {
	cmd.Flags().StringVar(&opts.contextFile, "context-file", "", "AWS context snapshot path")
	cmd.Flags().StringVar(&opts.collectValue, "collect", "", "collect read-only AWS context groups: all, identity, network, edge, iam, data, compute")
	cmd.Flags().StringVar(&opts.regionsValue, "regions", "", "comma-separated AWS regions to collect")
	cmd.Flags().StringVar(&opts.profile, "profile", "", "AWS shared config profile to use for collection")
	cmd.Flags().StringVar(&opts.timeoutValue, "timeout", opts.timeoutValue, "AWS collection timeout")
	cmd.Flags().StringArrayVar(&opts.tagValues, "tag", nil, "only keep resources matching AWS tag key=value or key; repeatable")
	if flag := cmd.Flags().Lookup("collect"); flag != nil {
		flag.NoOptDefVal = cloudcontext.CollectAll
	}
}

func addArchitectureViewFlags(cmd *cobra.Command, opts *architectureOptions) {
	cmd.Flags().StringVar(&opts.view, "view", opts.view, "architecture view: account, network, public-exposure, data, iam, compute, or resource")
	cmd.Flags().StringVar(&opts.resource, "resource", "", "resource address, ARN, or ID for --view resource")
	cmd.Flags().IntVar(&opts.maxDepth, "max-depth", opts.maxDepth, "relationship depth for focused architecture views")
	cmd.Flags().IntVar(&opts.maxNodes, "max-nodes", opts.maxNodes, "maximum nodes to include in the rendered view")
}

func loadArchitectureSnapshot(cmd *cobra.Command, opts *architectureOptions) (cloudcontext.Snapshot, []model.Diagnostic, error) {
	if opts.contextFile != "" && opts.collectValue != "" {
		return cloudcontext.Snapshot{}, nil, usageError("use either --context-file or --collect, not both", "Use --context-file for an offline snapshot or --collect all for live read-only collection.")
	}
	if opts.contextFile != "" && len(opts.tagValues) > 0 {
		return cloudcontext.Snapshot{}, nil, usageError("use --tag only with live AWS collection", "Create a tagged snapshot first, then render it with --context-file.")
	}
	if opts.contextFile != "" {
		snapshot, err := cloudcontext.LoadFile(opts.contextFile)
		if err != nil {
			return cloudcontext.Snapshot{}, nil, inputError(err.Error(), "Check --context-file.")
		}
		return snapshot, nil, nil
	}
	if opts.collectValue != "" {
		snapshot, diagnostics, _, err := buildAWSSnapshot(cmd, opts.collectValue, opts.regionsValue, opts.profile, opts.timeoutValue, opts.tagValues)
		return snapshot, diagnostics, err
	}
	snapshot, diagnostics, _, err := buildAWSSnapshot(cmd, cloudcontext.CollectAll, opts.regionsValue, opts.profile, opts.timeoutValue, opts.tagValues)
	return snapshot, diagnostics, err
}

func buildArchitectureView(snapshot cloudcontext.Snapshot, diagnostics []model.Diagnostic, opts *architectureOptions) (*graphpkg.Graph, architecture.Summary, error) {
	g, graphDiagnostics := architecture.BuildGraph(snapshot)
	allDiagnostics := appendArchitectureDiagnostics(diagnostics, graphDiagnostics)
	view, truncated, err := architecture.BuildView(g, architecture.Options{
		View:     opts.view,
		Resource: opts.resource,
		MaxDepth: opts.maxDepth,
		MaxNodes: opts.maxNodes,
	})
	if err != nil {
		return nil, architecture.Summary{}, usageError(err.Error(), "Use --view account, network, public-exposure, data, iam, compute, or resource.")
	}
	summary := architecture.Summarize(snapshot, view, opts.view, allDiagnostics, truncated)
	return view, summary, nil
}

func appendArchitectureDiagnostics(left []model.Diagnostic, right []model.Diagnostic) []model.Diagnostic {
	out := append([]model.Diagnostic(nil), left...)
	out = append(out, right...)
	return out
}

func normalizeArchitectureLayout(layout string, view string) string {
	layout = strings.ToLower(strings.TrimSpace(layout))
	if layout == "" || layout == "auto" {
		if architecture.ViewPublicExposure == strings.ToLower(strings.TrimSpace(view)) {
			return "graph"
		}
		return "map"
	}
	return layout
}

func writeArchitectureSummary(state *appState, summary architecture.Summary) error {
	return writeCommandOutput(state, "architecture aws summary", summary, func(r renderer) {
		r.printf("AWS architecture: %s\n", summary.View)
		if summary.AccountID != "" {
			r.printf("Account: %s\n", summary.AccountID)
		}
		if len(summary.Regions) > 0 {
			r.printf("Regions: %s\n", strings.Join(summary.Regions, ", "))
		}
		r.printf("Nodes: %d\n", summary.Nodes)
		r.printf("Edges: %d\n", summary.Edges)
		if len(summary.PublicResources) > 0 {
			r.printf("Public resources: %d\n", len(summary.PublicResources))
		}
		if len(summary.SensitiveAssets) > 0 {
			r.printf("Sensitive assets: %d\n", len(summary.SensitiveAssets))
		}
		if summary.Truncated {
			r.printf("Truncated: %s\n", summary.TruncationReason)
		}
		if len(summary.Diagnostics) > 0 {
			r.printf("Diagnostics: %d\n", len(summary.Diagnostics))
		}
	})
}

func diffArchitectureViews(view string, beforeSummary architecture.Summary, afterSummary architecture.Summary, before *graphpkg.Graph, after *graphpkg.Graph) architectureDiffResult {
	result := architectureDiffResult{
		Version: cloudcontext.Version,
		View:    strings.TrimSpace(view),
		Before:  beforeSummary,
		After:   afterSummary,
	}
	if result.View == "" {
		result.View = architecture.ViewAccount
	}
	beforeNodes := nodeFingerprints(before)
	afterNodes := nodeFingerprints(after)
	for id, fingerprint := range afterNodes {
		beforeFingerprint, ok := beforeNodes[id]
		switch {
		case !ok:
			result.AddedNodes = append(result.AddedNodes, id)
		case beforeFingerprint != fingerprint:
			result.ChangedNodes = append(result.ChangedNodes, id)
		}
	}
	for id := range beforeNodes {
		if _, ok := afterNodes[id]; !ok {
			result.RemovedNodes = append(result.RemovedNodes, id)
		}
	}
	beforeEdges := edgeFingerprints(before)
	afterEdges := edgeFingerprints(after)
	for id := range afterEdges {
		if _, ok := beforeEdges[id]; !ok {
			result.AddedEdges = append(result.AddedEdges, id)
		}
	}
	for id := range beforeEdges {
		if _, ok := afterEdges[id]; !ok {
			result.RemovedEdges = append(result.RemovedEdges, id)
		}
	}
	sort.Strings(result.AddedNodes)
	sort.Strings(result.RemovedNodes)
	sort.Strings(result.ChangedNodes)
	sort.Strings(result.AddedEdges)
	sort.Strings(result.RemovedEdges)
	return result
}

func nodeFingerprints(g *graphpkg.Graph) map[string]string {
	out := make(map[string]string)
	if g == nil {
		return out
	}
	for id, node := range g.Nodes {
		if node == nil {
			continue
		}
		body, _ := json.Marshal(struct {
			Type   string            `json:"type"`
			Kind   graphpkg.NodeKind `json:"kind"`
			Name   string            `json:"name"`
			Values map[string]any    `json:"values"`
			Tags   map[string]string `json:"tags"`
		}{
			Type:   node.Type,
			Kind:   node.Kind,
			Name:   node.Name,
			Values: node.Values,
			Tags:   node.Tags,
		})
		out[string(id)] = string(body)
	}
	return out
}

func edgeFingerprints(g *graphpkg.Graph) map[string]bool {
	out := make(map[string]bool)
	if g == nil {
		return out
	}
	for _, edge := range g.Edges {
		out[string(edge.From)+" -> "+string(edge.To)+" ["+string(edge.Type)+"]"] = true
	}
	return out
}

func writeArchitectureDiff(state *appState, result architectureDiffResult) error {
	return writeCommandOutput(state, "architecture aws diff", result, func(r renderer) {
		r.printf("AWS architecture diff: %s\n", result.View)
		r.printf("Before: %d resources, %d relationships\n", result.Before.Nodes, result.Before.Edges)
		r.printf("After: %d resources, %d relationships\n", result.After.Nodes, result.After.Edges)
		r.printf("Added resources: %d\n", len(result.AddedNodes))
		r.printf("Removed resources: %d\n", len(result.RemovedNodes))
		r.printf("Changed resources: %d\n", len(result.ChangedNodes))
		r.printf("Added relationships: %d\n", len(result.AddedEdges))
		r.printf("Removed relationships: %d\n", len(result.RemovedEdges))
		writeList := func(label string, values []string) {
			if len(values) == 0 {
				return
			}
			r.printf("\n%s:\n", label)
			for _, value := range values {
				r.printf("  - %s\n", value)
			}
		}
		writeList("Added resources", result.AddedNodes)
		writeList("Removed resources", result.RemovedNodes)
		writeList("Changed resources", result.ChangedNodes)
		writeList("Added relationships", result.AddedEdges)
		writeList("Removed relationships", result.RemovedEdges)
	})
}
