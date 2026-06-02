package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	graphpkg "github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/visual"
	"github.com/spf13/cobra"
)

const graphOutputVersion = 2

type graphOptions struct {
	planPath string
	from     string
	to       string
	resource string
	maxDepth int
	maxPaths int
	view     string
	render   string
	engine   string
}

type graphSummaryResult struct {
	Version                  int                       `json:"version"`
	Plan                     graphPlanSummary          `json:"plan"`
	Nodes                    int                       `json:"nodes"`
	Edges                    int                       `json:"edges"`
	NodeKinds                map[graphpkg.NodeKind]int `json:"node_kinds"`
	PublicEntrypoints        []graphpkg.ResourceID     `json:"public_entrypoints,omitempty"`
	SensitiveAssets          []graphpkg.ResourceID     `json:"sensitive_assets,omitempty"`
	ChangedBoundaryCrossings []graphpkg.Path           `json:"changed_boundary_crossings,omitempty"`
}

type graphPathResult struct {
	Version int                   `json:"version"`
	From    graphpkg.ResourceID   `json:"from"`
	To      graphpkg.ResourceID   `json:"to"`
	Found   bool                  `json:"found"`
	Paths   []graphpkg.Path       `json:"paths,omitempty"`
	Nearest []graphpkg.ResourceID `json:"nearest,omitempty"`
}

type graphExposureResult struct {
	Version     int                     `json:"version"`
	Resource    graphpkg.ResourceID     `json:"resource"`
	Kind        graphpkg.NodeKind       `json:"kind"`
	Exposure    graphpkg.ExposureResult `json:"exposure"`
	BlastRadius graphpkg.BlastRadius    `json:"blast_radius"`
	Level       string                  `json:"level"`
	TopPath     []graphpkg.ResourceID   `json:"top_path,omitempty"`
}

type graphExportResult struct {
	Version int                                    `json:"version"`
	Nodes   map[graphpkg.ResourceID]*graphpkg.Node `json:"nodes"`
	Edges   []graphpkg.Edge                        `json:"edges"`
}

type graphPlanSummary struct {
	Path          string     `json:"path"`
	Tool          model.Tool `json:"tool"`
	FormatVersion string     `json:"format_version,omitempty"`
	Resources     int        `json:"resources"`
	Changes       int        `json:"changes"`
}

func newGraphCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "graph",
		Short: "Inspect blast-radius graph relationships without running policy",
		Long: `Inspect the Terraform/OpenTofu change graph directly.

Graph commands parse plan JSON and build relationship context without evaluating
policy rules or returning a deployment decision.`,
	}
	root.AddCommand(newGraphSummaryCommand())
	root.AddCommand(newGraphPathCommand())
	root.AddCommand(newGraphExposureCommand())
	root.AddCommand(newGraphExportCommand())
	root.AddCommand(newGraphVisualizeCommand())
	root.AddCommand(newGraphRenderCommand())
	return root
}

func newGraphSummaryCommand() *cobra.Command {
	opts := &graphOptions{}
	cmd := &cobra.Command{
		Use:   "summary --plan tfplan.json",
		Short: "Summarize graph nodes, edges, public entrypoints, and sensitive assets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			plan, resourceGraph, err := loadGraphPlan(cmd, state, opts.planPath)
			if err != nil {
				return err
			}
			result := buildGraphSummary(opts.planPath, plan, resourceGraph)
			return writeGraphSummary(state, result, resourceGraph)
		},
	}
	addGraphPlanFlag(cmd, opts)
	return cmd
}

func newGraphPathCommand() *cobra.Command {
	opts := &graphOptions{}
	cmd := &cobra.Command{
		Use:   "path --plan tfplan.json --from RESOURCE --to RESOURCE",
		Short: "Find graph paths between two resources",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			_, resourceGraph, err := loadGraphPlan(cmd, state, opts.planPath)
			if err != nil {
				return err
			}
			result, err := buildGraphPathResult(resourceGraph, opts)
			if err != nil {
				return err
			}
			return writeGraphPath(state, result, resourceGraph)
		},
	}
	addGraphPlanFlag(cmd, opts)
	cmd.Flags().StringVar(&opts.from, "from", "", "source graph resource address")
	cmd.Flags().StringVar(&opts.to, "to", "", "target graph resource address")
	cmd.Flags().IntVar(&opts.maxDepth, "max-depth", 12, "maximum graph path depth")
	cmd.Flags().IntVar(&opts.maxPaths, "max-paths", 5, "maximum paths to return")
	return cmd
}

func newGraphExposureCommand() *cobra.Command {
	opts := &graphOptions{}
	cmd := &cobra.Command{
		Use:   "exposure --plan tfplan.json --resource RESOURCE",
		Short: "Explain public exposure and blast radius for a resource",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			_, resourceGraph, err := loadGraphPlan(cmd, state, opts.planPath)
			if err != nil {
				return err
			}
			result, err := buildGraphExposureResult(resourceGraph, opts)
			if err != nil {
				return err
			}
			return writeGraphExposure(state, result, resourceGraph)
		},
	}
	addGraphPlanFlag(cmd, opts)
	cmd.Flags().StringVar(&opts.resource, "resource", "", "resource address to analyze")
	cmd.Flags().IntVar(&opts.maxDepth, "max-depth", 12, "maximum graph path depth")
	cmd.Flags().IntVar(&opts.maxPaths, "max-paths", 10, "maximum paths to return")
	return cmd
}

func newGraphExportCommand() *cobra.Command {
	opts := &graphOptions{}
	cmd := &cobra.Command{
		Use:   "export --plan tfplan.json --format json|dot|mermaid",
		Short: "Export the full graph as JSON or a renderable diagram",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			_, resourceGraph, err := loadGraphPlan(cmd, state, opts.planPath)
			if err != nil {
				return err
			}
			if state.opts.format == "dot" || state.opts.format == "mermaid" {
				diagram := visual.NewGraphDiagram(resourceGraph, visual.GraphOptions{
					Title:       "ChangeGate Graph Export",
					Description: "Full infrastructure relationship graph",
				})
				return writeGraphDiagram(state, diagram)
			}
			if state.opts.format != "json" {
				return usageError("graph export requires --format json, dot, or mermaid", "Run changegate graph export --plan tfplan.json --format json.")
			}
			result := graphExportResult{
				Version: graphOutputVersion,
				Nodes:   resourceGraph.Nodes,
				Edges:   resourceGraph.Edges,
			}
			return writeGraphJSON(state, result)
		},
	}
	addGraphPlanFlag(cmd, opts)
	return cmd
}

func newGraphVisualizeCommand() *cobra.Command {
	opts := &graphOptions{view: "graph"}
	cmd := &cobra.Command{
		Use:   "visualize --plan tfplan.json",
		Short: "Write a self-contained interactive HTML graph visualization",
		Long: `Write a self-contained HTML visualization for the full graph, a focused
path, or a blast-radius exposure view. The output does not require network
access, JavaScript packages, or a hosted service.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			_, resourceGraph, err := loadGraphPlan(cmd, state, opts.planPath)
			if err != nil {
				return err
			}
			diagram, err := graphVisualizationDiagram(resourceGraph, opts)
			if err != nil {
				return err
			}
			return writeBytes(state, visual.RenderHTML(diagram))
		},
	}
	addGraphPlanFlag(cmd, opts)
	addGraphViewFlags(cmd, opts)
	return cmd
}

func newGraphRenderCommand() *cobra.Command {
	opts := &graphOptions{view: "graph", render: "svg", engine: "graphviz"}
	cmd := &cobra.Command{
		Use:   "render --plan tfplan.json --out graph.svg",
		Short: "Render a graph visualization with an optional external renderer",
		Long: `Render a graph, path, or exposure diagram with an external Graphviz
installation. ChangeGate still emits DOT without this helper; render is a
convenience wrapper for teams that want committed SVG, PNG, or PDF artifacts.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if state.opts.outPath == "" {
				return usageError("graph render requires --out", "Pass an output file, for example --out graph.svg.")
			}
			if opts.engine != "graphviz" {
				return usageError("--engine must be graphviz", "Graphviz is the only external renderer supported by this release.")
			}
			if !isGraphvizRenderFormat(opts.render) {
				return usageError("--render-format must be svg, png, or pdf", "Use --render-format svg for CI-friendly review artifacts.")
			}
			_, resourceGraph, err := loadGraphPlan(cmd, state, opts.planPath)
			if err != nil {
				return err
			}
			diagram, err := graphVisualizationDiagram(resourceGraph, opts)
			if err != nil {
				return err
			}
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
	addGraphPlanFlag(cmd, opts)
	addGraphViewFlags(cmd, opts)
	cmd.Flags().StringVar(&opts.engine, "engine", opts.engine, "external renderer engine: graphviz")
	cmd.Flags().StringVar(&opts.render, "render-format", opts.render, "rendered artifact format: svg, png, or pdf")
	return cmd
}

func addGraphViewFlags(cmd *cobra.Command, opts *graphOptions) {
	cmd.Flags().StringVar(&opts.view, "view", opts.view, "visualization view: graph, path, or exposure")
	cmd.Flags().StringVar(&opts.from, "from", "", "source graph resource address for --view path")
	cmd.Flags().StringVar(&opts.to, "to", "", "target graph resource address for --view path")
	cmd.Flags().StringVar(&opts.resource, "resource", "", "resource address for --view exposure")
	cmd.Flags().IntVar(&opts.maxDepth, "max-depth", 12, "maximum graph path depth")
	cmd.Flags().IntVar(&opts.maxPaths, "max-paths", 10, "maximum paths to return")
}

func graphVisualizationDiagram(resourceGraph *graphpkg.Graph, opts *graphOptions) (visual.Diagram, error) {
	switch opts.view {
	case "", "graph":
		return visual.NewGraphDiagram(resourceGraph, visual.GraphOptions{
			Title:       "ChangeGate Graph",
			Description: "Full infrastructure relationship graph",
		}), nil
	case "path":
		result, err := buildGraphPathResult(resourceGraph, opts)
		if err != nil {
			return visual.Diagram{}, err
		}
		return visual.NewGraphPathDiagram(resourceGraph, result.From, result.To, result.Paths), nil
	case "exposure":
		result, err := buildGraphExposureResult(resourceGraph, opts)
		if err != nil {
			return visual.Diagram{}, err
		}
		return visual.NewGraphExposureDiagram(resourceGraph, result.Resource, result.BlastRadius), nil
	default:
		return visual.Diagram{}, usageError("--view must be graph, path, or exposure", "Run changegate graph visualize --view graph, --view path, or --view exposure.")
	}
}

func isGraphvizRenderFormat(format string) bool {
	switch format {
	case "svg", "png", "pdf":
		return true
	default:
		return false
	}
}

func runGraphviz(ctx context.Context, dotBinary string, format string, dot []byte) ([]byte, error) {
	path, err := exec.LookPath(dotBinary)
	if err != nil {
		return nil, usageError(
			"Graphviz dot executable not found",
			"Install Graphviz, or use --format dot / graph visualize for dependency-free artifacts.",
		)
	}
	command := exec.CommandContext(ctx, path, "-T"+format)
	command.Stdin = bytes.NewReader(dot)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return nil, inputError("Graphviz render failed: "+detail, "Validate the generated DOT with changegate graph export --format dot.")
	}
	return stdout.Bytes(), nil
}

func addGraphPlanFlag(cmd *cobra.Command, opts *graphOptions) {
	cmd.Flags().StringVar(&opts.planPath, "plan", "", "path to Terraform/OpenTofu plan JSON produced by show -json")
}

func loadGraphPlan(cmd *cobra.Command, state *appState, planPath string) (*model.Plan, *graphpkg.Graph, error) {
	if planPath == "" {
		return nil, nil, usageError("missing required --plan path", "Generate plan JSON with terraform show -json tfplan > tfplan.json, then run changegate graph summary --plan tfplan.json.")
	}
	plan, err := loadPlan(cmd.Context(), state.stdin, planPath)
	if err != nil {
		return nil, nil, mapPlanLoadError(err)
	}
	buildOpts, err := graphBuildOptions(state)
	if err != nil {
		return nil, nil, err
	}
	return plan, graphpkg.BuildWithOptions(plan, buildOpts), nil
}

func graphBuildOptions(state *appState) (graphpkg.BuildOptions, error) {
	if state == nil || state.opts == nil || state.opts.policy == "" {
		return graphpkg.BuildOptions{}, nil
	}
	policyConfig, _, _, err := loadPolicyForScan(state.opts)
	if err != nil {
		return graphpkg.BuildOptions{}, err
	}
	return graphpkg.BuildOptions{SensitiveAssets: policyConfig.SensitiveAssets}, nil
}

func buildGraphSummary(planPath string, plan *model.Plan, resourceGraph *graphpkg.Graph) graphSummaryResult {
	nodeKinds := make(map[graphpkg.NodeKind]int)
	for _, node := range resourceGraph.Nodes {
		nodeKinds[node.Kind]++
	}
	return graphSummaryResult{
		Version: graphOutputVersion,
		Plan: graphPlanSummary{
			Path:          planPath,
			Tool:          plan.Tool,
			FormatVersion: plan.FormatVersion,
			Resources:     len(plan.Resources) + len(plan.PriorResources),
			Changes:       len(plan.Changes),
		},
		Nodes:                    len(resourceGraph.Nodes),
		Edges:                    len(resourceGraph.Edges),
		NodeKinds:                nodeKinds,
		PublicEntrypoints:        resourceGraph.PublicEntrypoints(),
		SensitiveAssets:          resourceGraph.SensitiveAssets(),
		ChangedBoundaryCrossings: resourceGraph.ChangedBoundaryCrossings(),
	}
}

func buildGraphPathResult(resourceGraph *graphpkg.Graph, opts *graphOptions) (graphPathResult, error) {
	if opts.from == "" {
		return graphPathResult{}, usageError("graph path requires --from", "Pass the source resource address, for example --from aws_lb.admin.")
	}
	if opts.to == "" {
		return graphPathResult{}, usageError("graph path requires --to", "Pass the target resource address, for example --to aws_db_instance.customer.")
	}
	from := graphpkg.ResourceID(opts.from)
	to := graphpkg.ResourceID(opts.to)
	if err := requireGraphNode(resourceGraph, from, "--from"); err != nil {
		return graphPathResult{}, err
	}
	if err := requireGraphNode(resourceGraph, to, "--to"); err != nil {
		return graphPathResult{}, err
	}
	result := graphPathResult{
		Version: graphOutputVersion,
		From:    from,
		To:      to,
		Paths: resourceGraph.Paths(from, to, graphpkg.PathOptions{
			MaxDepth: opts.maxDepth,
			MaxPaths: opts.maxPaths,
		}),
	}
	result.Found = len(result.Paths) > 0
	return result, nil
}

func buildGraphExposureResult(resourceGraph *graphpkg.Graph, opts *graphOptions) (graphExposureResult, error) {
	if opts.resource == "" {
		return graphExposureResult{}, usageError("graph exposure requires --resource", "Pass the resource address to analyze, for example --resource aws_ecs_service.admin.")
	}
	resource := graphpkg.ResourceID(opts.resource)
	if err := requireGraphNode(resourceGraph, resource, "--resource"); err != nil {
		return graphExposureResult{}, err
	}
	radius := resourceGraph.BlastRadius(resource, graphpkg.BlastRadiusOptions{
		MaxDepth: opts.maxDepth,
		MaxPaths: opts.maxPaths,
	})
	return graphExposureResult{
		Version:     graphOutputVersion,
		Resource:    resource,
		Kind:        resourceGraph.Nodes[resource].Kind,
		Exposure:    radius.Exposure,
		BlastRadius: radius,
		Level:       exposureLevel(radius),
		TopPath:     topExposurePath(radius),
	}, nil
}

func writeGraphSummary(state *appState, result graphSummaryResult, resourceGraph *graphpkg.Graph) error {
	if state.opts.format == "json" {
		return writeGraphJSON(state, result)
	}
	if state.opts.format == "dot" || state.opts.format == "mermaid" {
		return writeGraphDiagram(state, visual.NewGraphDiagram(resourceGraph, visual.GraphOptions{
			Title:       "ChangeGate Graph Summary",
			Description: fmt.Sprintf("%d nodes, %d edges", result.Nodes, result.Edges),
		}))
	}
	if err := validateGraphTableFormat(state.opts.format); err != nil {
		return err
	}
	r := state.renderer
	r.printf("Graph Summary\n")
	r.printf("Plan: %s\n", result.Plan.Path)
	r.printf("Tool: %s\n", result.Plan.Tool)
	r.printf("Resources: %d\n", result.Plan.Resources)
	r.printf("Changes: %d\n", result.Plan.Changes)
	r.printf("Nodes: %d\n", result.Nodes)
	r.printf("Edges: %d\n", result.Edges)
	r.printf("Public entrypoints: %d\n", len(result.PublicEntrypoints))
	r.printf("Sensitive assets: %d\n", len(result.SensitiveAssets))
	r.printf("Changed boundary crossings: %d\n", len(result.ChangedBoundaryCrossings))
	r.printf("\nNode kinds:\n")
	for _, kind := range sortedNodeKinds(result.NodeKinds) {
		r.printf("  %s: %d\n", kind, result.NodeKinds[kind])
	}
	return nil
}

func writeGraphPath(state *appState, result graphPathResult, resourceGraph *graphpkg.Graph) error {
	if state.opts.format == "json" {
		return writeGraphJSON(state, result)
	}
	if state.opts.format == "dot" || state.opts.format == "mermaid" {
		return writeGraphDiagram(state, visual.NewGraphPathDiagram(resourceGraph, result.From, result.To, result.Paths))
	}
	if err := validateGraphTableFormat(state.opts.format); err != nil {
		return err
	}
	r := state.renderer
	if !result.Found {
		r.printf("Path: not found\n")
		r.printf("From: %s\n", result.From)
		r.printf("To: %s\n", result.To)
		return nil
	}
	r.printf("Path: found\n")
	r.printf("From: %s\n", result.From)
	r.printf("To: %s\n", result.To)
	r.printf("Paths: %d\n\n", len(result.Paths))
	for index, path := range result.Paths {
		r.printf("%d. %s\n", index+1, formatPath(path.Nodes))
		for _, edge := range path.Edges {
			r.printf("   %s --%s--> %s\n", edge.From, edge.Type, edge.To)
		}
	}
	return nil
}

func writeGraphExposure(state *appState, result graphExposureResult, resourceGraph *graphpkg.Graph) error {
	if state.opts.format == "json" {
		return writeGraphJSON(state, result)
	}
	if state.opts.format == "dot" || state.opts.format == "mermaid" {
		return writeGraphDiagram(state, visual.NewGraphExposureDiagram(resourceGraph, result.Resource, result.BlastRadius))
	}
	if err := validateGraphTableFormat(state.opts.format); err != nil {
		return err
	}
	r := state.renderer
	r.printf("Exposure: %s\n\n", result.Level)
	r.printf("Public entrypoints:\n")
	printResourceList(r, exposureEntrypoints(result.Exposure))
	r.printf("\nReachable workloads:\n")
	printResourceList(r, exposureWorkloads(result))
	r.printf("\nSensitive downstream assets:\n")
	printResourceList(r, result.BlastRadius.SensitiveAssets)
	if len(result.TopPath) > 0 {
		r.printf("\nTop path:\n")
		r.printf("  %s\n", formatPath(result.TopPath))
	}
	return nil
}

func writeGraphJSON(state *appState, result any) error {
	if state.opts.outPath != "" {
		file, err := os.Create(state.opts.outPath)
		if err != nil {
			return inputError(fmt.Sprintf("create output file %q: %v", state.opts.outPath, err), "Check the output path and directory permissions.")
		}
		if err := writeJSON(file, result); err != nil {
			if closeErr := file.Close(); closeErr != nil {
				return inputError(fmt.Sprintf("close output file %q after write error: %v", state.opts.outPath, closeErr), "Check the output path and directory permissions.")
			}
			return err
		}
		if err := file.Close(); err != nil {
			return inputError(fmt.Sprintf("close output file %q: %v", state.opts.outPath, err), "Check the output path and directory permissions.")
		}
		return nil
	}
	return writeJSON(state.renderer.out, result)
}

func writeGraphDiagram(state *appState, diagram visual.Diagram) error {
	var body []byte
	switch state.opts.format {
	case "dot":
		body = visual.RenderDOT(diagram)
	case "mermaid":
		body = visual.RenderMermaid(diagram)
	default:
		return usageError("--format for graph diagram must be dot or mermaid", "Run graph commands with --format dot or --format mermaid.")
	}
	return writeBytes(state, body)
}

func writeBytes(state *appState, body []byte) error {
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

func validateGraphTableFormat(format string) error {
	switch format {
	case "", "table":
		return nil
	default:
		return usageError("--format for graph must be table, json, dot, or mermaid", "Run graph commands with --format table, --format json, --format dot, or --format mermaid.")
	}
}

func requireGraphNode(resourceGraph *graphpkg.Graph, resource graphpkg.ResourceID, flag string) error {
	if resourceGraph.Nodes[resource] != nil {
		return nil
	}
	return usageError(
		fmt.Sprintf("unknown graph resource %q for %s", resource, flag),
		"Known nearby resources: "+strings.Join(resourceSuggestions(resourceGraph, string(resource), 5), ", "),
	)
}

func resourceSuggestions(resourceGraph *graphpkg.Graph, target string, limit int) []string {
	type candidate struct {
		address string
		score   int
	}
	candidates := make([]candidate, 0, len(resourceGraph.Nodes))
	for id := range resourceGraph.Nodes {
		address := string(id)
		score := levenshteinDistance(strings.ToLower(target), strings.ToLower(address))
		if strings.Contains(strings.ToLower(address), strings.ToLower(target)) || strings.Contains(strings.ToLower(target), strings.ToLower(address)) {
			score -= 4
		}
		candidates = append(candidates, candidate{address: address, score: score})
	}
	sort.SliceStable(candidates, func(i int, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score < candidates[j].score
		}
		return candidates[i].address < candidates[j].address
	})
	if limit > len(candidates) {
		limit = len(candidates)
	}
	out := make([]string, 0, limit)
	for _, candidate := range candidates[:limit] {
		out = append(out, candidate.address)
	}
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

func exposureLevel(radius graphpkg.BlastRadius) string {
	if !radius.Exposure.Exposed {
		return "NONE"
	}
	if len(radius.SensitiveAssets) > 0 {
		return "HIGH"
	}
	if len(radius.ReachableWorkloads) > 0 {
		return "MEDIUM"
	}
	return "LOW"
}

func topExposurePath(radius graphpkg.BlastRadius) []graphpkg.ResourceID {
	if len(radius.Paths) == 0 {
		if len(radius.Exposure.Paths) > 0 {
			return prependInternet(radius.Exposure.Paths[0].Nodes)
		}
		return nil
	}
	best := radius.Paths[0].Nodes
	if len(radius.Exposure.Paths) == 0 {
		return best
	}
	entryPath := radius.Exposure.Paths[0].Nodes
	combined := append([]graphpkg.ResourceID{}, entryPath...)
	if len(combined) == 0 || combined[len(combined)-1] != best[0] {
		combined = append(combined, best...)
	} else {
		combined = append(combined, best[1:]...)
	}
	return prependInternet(combined)
}

func prependInternet(nodes []graphpkg.ResourceID) []graphpkg.ResourceID {
	if len(nodes) == 0 {
		return nil
	}
	if nodes[0] == graphpkg.InternetNodeID {
		return append([]graphpkg.ResourceID{}, nodes...)
	}
	out := make([]graphpkg.ResourceID, 0, len(nodes)+1)
	out = append(out, graphpkg.InternetNodeID)
	out = append(out, nodes...)
	return out
}

func exposureEntrypoints(exposure graphpkg.ExposureResult) []graphpkg.ResourceID {
	out := make([]graphpkg.ResourceID, 0, len(exposure.Entrypoints))
	for _, node := range exposure.Entrypoints {
		out = append(out, node.ID)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func exposureWorkloads(result graphExposureResult) []graphpkg.ResourceID {
	out := append([]graphpkg.ResourceID{}, result.BlastRadius.ReachableWorkloads...)
	if result.Kind == graphpkg.NodeWorkload && result.Exposure.Exposed {
		if !containsGraphResource(out, result.Resource) {
			out = append([]graphpkg.ResourceID{result.Resource}, out...)
		}
	}
	return out
}

func containsGraphResource(values []graphpkg.ResourceID, resource graphpkg.ResourceID) bool {
	for _, value := range values {
		if value == resource {
			return true
		}
	}
	return false
}

func printResourceList(r renderer, resources []graphpkg.ResourceID) {
	if len(resources) == 0 {
		r.printf("  none\n")
		return
	}
	for _, resource := range resources {
		r.printf("  %s\n", resource)
	}
}

func formatPath(nodes []graphpkg.ResourceID) string {
	parts := make([]string, 0, len(nodes))
	for _, node := range nodes {
		parts = append(parts, string(node))
	}
	return strings.Join(parts, " -> ")
}

func sortedNodeKinds(values map[graphpkg.NodeKind]int) []graphpkg.NodeKind {
	out := make([]graphpkg.NodeKind, 0, len(values))
	for kind := range values {
		out = append(out, kind)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func levenshteinDistance(left string, right string) int {
	if left == right {
		return 0
	}
	if left == "" {
		return len(right)
	}
	if right == "" {
		return len(left)
	}
	prev := make([]int, len(right)+1)
	curr := make([]int, len(right)+1)
	for j := range prev {
		prev[j] = j
	}
	for i, leftRune := range left {
		curr[0] = i + 1
		for j, rightRune := range right {
			cost := 0
			if leftRune != rightRune {
				cost = 1
			}
			curr[j+1] = minInt(curr[j]+1, prev[j+1]+1, prev[j]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(right)]
}

func minInt(values ...int) int {
	best := values[0]
	for _, value := range values[1:] {
		if value < best {
			best = value
		}
	}
	return best
}
