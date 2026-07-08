// Package architecture builds account architecture views from cloud snapshots.
package architecture

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

const (
	// ViewAccount shows the collected account resource footprint.
	ViewAccount = "account"
	// ViewNetwork shows VPC, subnet, route, security-group, and edge networking.
	ViewNetwork = "network"
	// ViewPublicExposure focuses on internet-reachable resources and downstream paths.
	ViewPublicExposure = "public-exposure"
	// ViewData shows sensitive data stores, secrets, keys, and direct consumers.
	ViewData = "data"
	// ViewIAM shows IAM principals, policies, and trust/permission relationships.
	ViewIAM = "iam"
	// ViewCompute shows workloads and their attached network/data/IAM relationships.
	ViewCompute = "compute"
	// ViewResource shows a local neighborhood around one resource.
	ViewResource = "resource"
)

const (
	accountNodeIDPrefix = "aws-account:"
	regionNodeIDPrefix  = "aws-region:"
)

// Options controls architecture view construction.
type Options struct {
	View     string
	Resource string
	MaxDepth int
	MaxNodes int
}

// Summary describes the collected architecture graph.
type Summary struct {
	Version          int                    `json:"version"`
	Provider         string                 `json:"provider"`
	AccountID        string                 `json:"account_id,omitempty"`
	Regions          []string               `json:"regions,omitempty"`
	View             string                 `json:"view"`
	Nodes            int                    `json:"nodes"`
	Edges            int                    `json:"edges"`
	NodeKinds        map[graph.NodeKind]int `json:"node_kinds"`
	ResourceTypes    map[string]int         `json:"resource_types"`
	PublicResources  []graph.ResourceID     `json:"public_resources,omitempty"`
	SensitiveAssets  []graph.ResourceID     `json:"sensitive_assets,omitempty"`
	Diagnostics      []model.Diagnostic     `json:"diagnostics,omitempty"`
	Truncated        bool                   `json:"truncated,omitempty"`
	TruncationReason string                 `json:"truncation_reason,omitempty"`
}

// BuildGraph turns a redacted cloud-context snapshot into an architecture graph.
func BuildGraph(snapshot cloudcontext.Snapshot) (*graph.Graph, []model.Diagnostic) {
	base := &graph.Graph{Nodes: make(map[graph.ResourceID]*graph.Node)}
	g, diagnostics := graph.MergeContext(base, snapshot)
	addAccountRegionContext(g, snapshot)
	sortGraph(g)
	return g, diagnostics
}

// BuildView returns a focused graph view for architecture visualization.
func BuildView(g *graph.Graph, opts Options) (*graph.Graph, bool, error) {
	if g == nil {
		return &graph.Graph{Nodes: make(map[graph.ResourceID]*graph.Node)}, false, nil
	}
	normalized := normalizeOptions(opts)
	selected, err := selectedNodes(g, normalized)
	if err != nil {
		return nil, false, err
	}
	truncated := applyMaxNodes(g, selected, normalized.MaxNodes)
	out := subgraph(g, selected)
	sortGraph(out)
	return out, truncated, nil
}

// Summarize returns counts and key resources for the current view.
func Summarize(snapshot cloudcontext.Snapshot, g *graph.Graph, view string, diagnostics []model.Diagnostic, truncated bool) Summary {
	if g == nil {
		g = &graph.Graph{Nodes: make(map[graph.ResourceID]*graph.Node)}
	}
	summary := Summary{
		Version:       cloudcontext.Version,
		Provider:      snapshot.Provider,
		AccountID:     snapshot.Account.ID,
		Regions:       enabledRegions(snapshot.Regions),
		View:          normalizeView(view),
		Nodes:         len(g.Nodes),
		Edges:         len(g.Edges),
		NodeKinds:     make(map[graph.NodeKind]int),
		ResourceTypes: make(map[string]int),
		Diagnostics:   diagnostics,
		Truncated:     truncated,
	}
	if truncated {
		summary.TruncationReason = "view exceeded max node count; increase --max-nodes or choose a focused view"
	}
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if node == nil {
			continue
		}
		summary.NodeKinds[node.Kind]++
		if node.Type != "" {
			summary.ResourceTypes[node.Type]++
		}
		if isPublicNode(node) {
			summary.PublicResources = append(summary.PublicResources, id)
		}
		if isSensitiveNode(node) {
			summary.SensitiveAssets = append(summary.SensitiveAssets, id)
		}
	}
	return summary
}

// Title returns a user-facing diagram title for a view.
func Title(view string) string {
	switch normalizeView(view) {
	case ViewNetwork:
		return "AWS Network Architecture"
	case ViewPublicExposure:
		return "AWS Public Exposure Architecture"
	case ViewData:
		return "AWS Data Architecture"
	case ViewIAM:
		return "AWS IAM Architecture"
	case ViewCompute:
		return "AWS Compute Architecture"
	case ViewResource:
		return "AWS Resource Architecture"
	default:
		return "AWS Account Architecture"
	}
}

// Description returns a short user-facing diagram description.
func Description(snapshot cloudcontext.Snapshot, view string, truncated bool) string {
	parts := []string{"Read-only AWS architecture view"}
	if snapshot.Account.ID != "" {
		parts = append(parts, "account "+snapshot.Account.ID)
	}
	if regions := enabledRegions(snapshot.Regions); len(regions) > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", len(regions), pluralize(len(regions), "region", "regions")))
	}
	parts = append(parts, "view "+normalizeView(view))
	if truncated {
		parts = append(parts, "truncated by --max-nodes")
	}
	return strings.Join(parts, " | ")
}

// ValidViews returns the supported view names.
func ValidViews() []string {
	return []string{ViewAccount, ViewNetwork, ViewPublicExposure, ViewData, ViewIAM, ViewCompute, ViewResource}
}

func normalizeOptions(opts Options) Options {
	opts.View = normalizeView(opts.View)
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 4
	}
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = 300
	}
	return opts
}

func normalizeView(view string) string {
	view = strings.ToLower(strings.TrimSpace(view))
	if view == "" || view == "graph" || view == "all" {
		return ViewAccount
	}
	return view
}

func selectedNodes(g *graph.Graph, opts Options) (map[graph.ResourceID]bool, error) {
	switch opts.View {
	case ViewAccount:
		return selectMatching(g, isAccountArchitectureNode), nil
	case ViewNetwork:
		return selectMatching(g, isNetworkNode), nil
	case ViewPublicExposure:
		return selectPublicExposure(g, opts.MaxDepth), nil
	case ViewData:
		return selectByPredicate(g, opts.MaxDepth, isSensitiveNode), nil
	case ViewIAM:
		return selectByPredicate(g, opts.MaxDepth, isIAMNode), nil
	case ViewCompute:
		return selectByPredicate(g, opts.MaxDepth, isComputeNode), nil
	case ViewResource:
		if strings.TrimSpace(opts.Resource) == "" {
			return nil, fmt.Errorf("--resource is required when --view resource")
		}
		id, ok := resolveNodeID(g, opts.Resource)
		if !ok {
			return nil, fmt.Errorf("resource %q was not found in the architecture graph", opts.Resource)
		}
		return expandUndirectedFiltered(g, map[graph.ResourceID]bool{id: true}, opts.MaxDepth, isArchitectureViewNode), nil
	default:
		return nil, fmt.Errorf("--view must be one of: %s", strings.Join(ValidViews(), ", "))
	}
}

func addAccountRegionContext(g *graph.Graph, snapshot cloudcontext.Snapshot) {
	if g == nil {
		return
	}
	if g.Nodes == nil {
		g.Nodes = make(map[graph.ResourceID]*graph.Node)
	}
	accountID := strings.TrimSpace(snapshot.Account.ID)
	accountNodeID := graph.ResourceID(accountNodeIDPrefix + firstNonEmpty(accountID, "unknown"))
	if accountID != "" {
		g.Nodes[accountNodeID] = &graph.Node{
			ID:        accountNodeID,
			Address:   string(accountNodeID),
			Type:      "aws_account",
			Kind:      graph.NodeNetworkBoundary,
			Name:      "AWS account " + accountID,
			Provider:  "aws",
			Synthetic: true,
			Values:    map[string]any{"account_id": accountID},
		}
	}
	for _, region := range snapshot.Regions {
		if !region.Enabled || region.Name == "" {
			continue
		}
		regionID := graph.ResourceID(regionNodeIDPrefix + region.Name)
		g.Nodes[regionID] = &graph.Node{
			ID:        regionID,
			Address:   string(regionID),
			Type:      "aws_region",
			Kind:      graph.NodeNetworkBoundary,
			Name:      region.Name,
			Provider:  "aws",
			Synthetic: true,
			Values:    map[string]any{"region": region.Name},
		}
		if accountID != "" {
			g.Edges = append(g.Edges, graph.Edge{
				From:       regionID,
				To:         accountNodeID,
				Type:       graph.EdgeContainedIn,
				Source:     graph.SourceCloudContext,
				Confidence: graph.ConfidenceHigh,
			})
		}
	}
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if node == nil || node.Type == "aws_account" || node.Type == "aws_region" {
			continue
		}
		if id == graph.InternetNodeID {
			continue
		}
		if region := stringValue(node.Values, "region"); region != "" {
			regionID := graph.ResourceID(regionNodeIDPrefix + region)
			if g.Nodes[regionID] != nil {
				g.Edges = append(g.Edges, graph.Edge{
					From:       id,
					To:         regionID,
					Type:       graph.EdgeContainedIn,
					Source:     graph.SourceCloudContext,
					Confidence: graph.ConfidenceHigh,
				})
			}
		} else if accountID != "" {
			g.Edges = append(g.Edges, graph.Edge{
				From:       id,
				To:         accountNodeID,
				Type:       graph.EdgeContainedIn,
				Source:     graph.SourceCloudContext,
				Confidence: graph.ConfidenceMedium,
			})
		}
	}
}

func selectByPredicate(g *graph.Graph, depth int, pred func(*graph.Node) bool) map[graph.ResourceID]bool {
	seeds := selectMatching(g, pred)
	return expandUndirectedFiltered(g, seeds, depth, isArchitectureViewNode)
}

func selectMatching(g *graph.Graph, pred func(*graph.Node) bool) map[graph.ResourceID]bool {
	seeds := make(map[graph.ResourceID]bool)
	for id, node := range g.Nodes {
		if pred(node) {
			seeds[id] = true
		}
	}
	return seeds
}

func selectPublicExposure(g *graph.Graph, depth int) map[graph.ResourceID]bool {
	seeds := make(map[graph.ResourceID]bool)
	for id, node := range g.Nodes {
		if isPublicNode(node) || id == graph.InternetNodeID {
			seeds[id] = true
		}
	}
	return expandDirectedFiltered(g, seeds, depth, isArchitectureViewNode)
}

func expandUndirectedFiltered(g *graph.Graph, seeds map[graph.ResourceID]bool, depth int, allowed func(*graph.Node) bool) map[graph.ResourceID]bool {
	selected := copySelection(seeds)
	frontier := copySelection(seeds)
	for step := 0; step < depth; step++ {
		next := make(map[graph.ResourceID]bool)
		for _, edge := range g.Edges {
			if frontier[edge.From] && !selected[edge.To] && allowed(g.Nodes[edge.To]) {
				selected[edge.To] = true
				next[edge.To] = true
			}
			if frontier[edge.To] && !selected[edge.From] && allowed(g.Nodes[edge.From]) {
				selected[edge.From] = true
				next[edge.From] = true
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = next
	}
	return selected
}

func expandDirectedFiltered(g *graph.Graph, seeds map[graph.ResourceID]bool, depth int, allowed func(*graph.Node) bool) map[graph.ResourceID]bool {
	selected := copySelection(seeds)
	frontier := copySelection(seeds)
	for step := 0; step < depth; step++ {
		next := make(map[graph.ResourceID]bool)
		for _, edge := range g.Edges {
			if frontier[edge.From] && !selected[edge.To] && allowed(g.Nodes[edge.To]) {
				selected[edge.To] = true
				next[edge.To] = true
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = next
	}
	return selected
}

func isAccountArchitectureNode(node *graph.Node) bool {
	if !isArchitectureViewNode(node) {
		return false
	}
	if node.ID == graph.InternetNodeID || node.Type == "aws_account" || node.Type == "aws_region" {
		return true
	}
	if isIAMNode(node) {
		return false
	}
	return isNetworkNode(node) || isPublicNode(node) || isSensitiveNode(node) || isComputeNode(node) || strings.HasPrefix(node.Type, "aws_")
}

func isArchitectureViewNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	if isPolicyDetailNode(node) {
		return false
	}
	return true
}

func isPolicyDetailNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	id := string(node.ID)
	if node.Type == "external" {
		return true
	}
	return id == "*" || strings.HasPrefix(id, "action:")
}

func applyMaxNodes(g *graph.Graph, selected map[graph.ResourceID]bool, maxNodes int) bool {
	if maxNodes <= 0 || len(selected) <= maxNodes {
		return false
	}
	ids := make([]graph.ResourceID, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.SliceStable(ids, func(i int, j int) bool {
		return nodePriority(g.Nodes[ids[i]]) > nodePriority(g.Nodes[ids[j]]) || nodePriority(g.Nodes[ids[i]]) == nodePriority(g.Nodes[ids[j]]) && ids[i] < ids[j]
	})
	for _, id := range ids[maxNodes:] {
		delete(selected, id)
	}
	return true
}

func subgraph(g *graph.Graph, selected map[graph.ResourceID]bool) *graph.Graph {
	out := &graph.Graph{
		Nodes: make(map[graph.ResourceID]*graph.Node, len(selected)),
		Edges: make([]graph.Edge, 0),
	}
	for id := range selected {
		if node := g.Nodes[id]; node != nil {
			out.Nodes[id] = copyNode(node)
		}
	}
	for _, edge := range g.Edges {
		if selected[edge.From] && selected[edge.To] {
			out.Edges = append(out.Edges, copyEdge(edge))
		}
	}
	return out
}

func isNetworkNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == graph.NodeNetworkBoundary || node.Type == "aws_region" || node.Type == "aws_account" {
		return true
	}
	return strings.Contains(node.Type, "vpc") ||
		strings.Contains(node.Type, "subnet") ||
		strings.Contains(node.Type, "route") ||
		strings.Contains(node.Type, "security_group") ||
		strings.Contains(node.Type, "internet_gateway") ||
		strings.Contains(node.Type, "nat_gateway") ||
		strings.Contains(node.Type, "transit_gateway") ||
		strings.Contains(node.Type, "network_interface") ||
		strings.Contains(node.Type, "lb")
}

func isIAMNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	return node.Kind == graph.NodePrincipal ||
		node.Kind == graph.NodePolicy ||
		strings.Contains(node.Type, "iam_") ||
		strings.Contains(node.Type, "oidc")
}

func isComputeNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	return node.Kind == graph.NodeWorkload ||
		strings.Contains(node.Type, "instance") ||
		strings.Contains(node.Type, "ecs_") ||
		strings.Contains(node.Type, "eks_") ||
		strings.Contains(node.Type, "lambda")
}

func isPublicNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	return node.Kind == graph.NodePublicEntrypoint || boolValue(node.Values, "public") || boolValue(node.Values, "endpoint_public_access")
}

func isSensitiveNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	return node.Kind == graph.NodeDataStore ||
		node.Kind == graph.NodeSecret ||
		node.Kind == graph.NodeKMSKey ||
		boolValue(node.Values, "sensitive_data")
}

func resolveNodeID(g *graph.Graph, value string) (graph.ResourceID, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	id := graph.ResourceID(value)
	if g.Nodes[id] != nil {
		return id, true
	}
	for candidate, node := range g.Nodes {
		if node == nil {
			continue
		}
		if node.Address == value || node.Name == value || stringValue(node.Values, "arn") == value || stringValue(node.Values, "id") == value {
			return candidate, true
		}
	}
	return "", false
}

func nodePriority(node *graph.Node) int {
	switch {
	case node == nil:
		return 0
	case isPublicNode(node):
		return 100
	case isSensitiveNode(node):
		return 90
	case isComputeNode(node):
		return 80
	case isIAMNode(node):
		return 70
	case isNetworkNode(node):
		return 60
	default:
		return 10
	}
}

func sortGraph(g *graph.Graph) {
	if g == nil {
		return
	}
	sort.SliceStable(g.Edges, func(i int, j int) bool {
		left := edgeSortKey(g.Edges[i])
		right := edgeSortKey(g.Edges[j])
		return left < right
	})
}

func sortedNodeIDs(g *graph.Graph) []graph.ResourceID {
	ids := make([]graph.ResourceID, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.SliceStable(ids, func(i int, j int) bool { return ids[i] < ids[j] })
	return ids
}

func copySelection(values map[graph.ResourceID]bool) map[graph.ResourceID]bool {
	out := make(map[graph.ResourceID]bool, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func copyNode(node *graph.Node) *graph.Node {
	out := *node
	out.ModulePath = append([]string(nil), node.ModulePath...)
	out.Actions = append([]model.Action(nil), node.Actions...)
	out.Tags = copyStringMap(node.Tags)
	out.Values = copyAnyMap(node.Values)
	return &out
}

func copyEdge(edge graph.Edge) graph.Edge {
	out := edge
	out.Evidence = append([]model.Evidence(nil), edge.Evidence...)
	out.Metadata = copyStringMap(edge.Metadata)
	return out
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func copyAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func edgeSortKey(edge graph.Edge) string {
	return string(edge.From) + "\x00" + string(edge.To) + "\x00" + string(edge.Type)
}

func stringValue(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, ok := values[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func boolValue(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	value, ok := values[key]
	if !ok {
		return false
	}
	typed, ok := value.(bool)
	return ok && typed
}

func enabledRegions(regions []cloudcontext.Region) []string {
	out := make([]string, 0, len(regions))
	for _, region := range regions {
		if region.Enabled && region.Name != "" {
			out = append(out, region.Name)
		}
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func pluralize(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}
