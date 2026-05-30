package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	graphpkg "github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/spf13/cobra"
)

const graphOutputVersion = 1

type graphOptions struct {
	planPath string
	from     string
	to       string
	resource string
	maxDepth int
	maxPaths int
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
			return writeGraphSummary(state, result)
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
			if opts.from == "" {
				return usageError("graph path requires --from", "Pass the source resource address, for example --from aws_lb.admin.")
			}
			if opts.to == "" {
				return usageError("graph path requires --to", "Pass the target resource address, for example --to aws_db_instance.customer.")
			}
			if err := requireGraphNode(resourceGraph, graphpkg.ResourceID(opts.from), "--from"); err != nil {
				return err
			}
			if err := requireGraphNode(resourceGraph, graphpkg.ResourceID(opts.to), "--to"); err != nil {
				return err
			}
			result := graphPathResult{
				Version: graphOutputVersion,
				From:    graphpkg.ResourceID(opts.from),
				To:      graphpkg.ResourceID(opts.to),
				Paths: resourceGraph.Paths(graphpkg.ResourceID(opts.from), graphpkg.ResourceID(opts.to), graphpkg.PathOptions{
					MaxDepth: opts.maxDepth,
					MaxPaths: opts.maxPaths,
				}),
			}
			result.Found = len(result.Paths) > 0
			return writeGraphPath(state, result)
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
			if opts.resource == "" {
				return usageError("graph exposure requires --resource", "Pass the resource address to analyze, for example --resource aws_ecs_service.admin.")
			}
			resource := graphpkg.ResourceID(opts.resource)
			if err := requireGraphNode(resourceGraph, resource, "--resource"); err != nil {
				return err
			}
			radius := resourceGraph.BlastRadius(resource, graphpkg.BlastRadiusOptions{
				MaxDepth: opts.maxDepth,
				MaxPaths: opts.maxPaths,
			})
			result := graphExposureResult{
				Version:     graphOutputVersion,
				Resource:    resource,
				Kind:        resourceGraph.Nodes[resource].Kind,
				Exposure:    radius.Exposure,
				BlastRadius: radius,
				Level:       exposureLevel(radius),
				TopPath:     topExposurePath(radius),
			}
			return writeGraphExposure(state, result)
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
		Use:   "export --plan tfplan.json --format json",
		Short: "Export the full graph as JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			if state.opts.format != "json" {
				return usageError("graph export requires --format json", "Run changegate graph export --plan tfplan.json --format json.")
			}
			_, resourceGraph, err := loadGraphPlan(cmd, state, opts.planPath)
			if err != nil {
				return err
			}
			return writeGraphJSON(state, resourceGraph)
		},
	}
	addGraphPlanFlag(cmd, opts)
	return cmd
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
	return plan, graphpkg.Build(plan), nil
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

func writeGraphSummary(state *appState, result graphSummaryResult) error {
	if state.opts.format == "json" {
		return writeGraphJSON(state, result)
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

func writeGraphPath(state *appState, result graphPathResult) error {
	if state.opts.format == "json" {
		return writeGraphJSON(state, result)
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

func writeGraphExposure(state *appState, result graphExposureResult) error {
	if state.opts.format == "json" {
		return writeGraphJSON(state, result)
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

func validateGraphTableFormat(format string) error {
	switch format {
	case "", "table":
		return nil
	default:
		return usageError("--format for graph must be table or json", "Run graph commands with --format table or --format json.")
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
