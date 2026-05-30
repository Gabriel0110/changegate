// Package graph builds and queries resource relationship graphs.
package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
)

// ResourceID is a stable graph node identifier.
type ResourceID string

// EdgeType describes the relationship between two graph nodes.
type EdgeType string

const (
	// EdgeDependsOn represents explicit Terraform/OpenTofu dependency ordering.
	EdgeDependsOn EdgeType = "depends_on"
	// EdgeRoutesTo represents traffic routing between resources.
	EdgeRoutesTo EdgeType = "routes_to"
	// EdgeAllowsIngress represents inbound network reachability.
	EdgeAllowsIngress EdgeType = "allows_ingress"
	// EdgeAllowsEgress represents outbound network reachability.
	EdgeAllowsEgress EdgeType = "allows_egress"
	// EdgeCanAssume represents sts:AssumeRole capability.
	EdgeCanAssume EdgeType = "can_assume"
	// EdgeCanPassRole represents iam:PassRole capability.
	EdgeCanPassRole EdgeType = "can_pass_role"
	// EdgeCanReadData represents read access to sensitive data.
	EdgeCanReadData EdgeType = "can_read_data"
	// EdgeCanWriteData represents write access to data resources.
	EdgeCanWriteData EdgeType = "can_write_data"
	// EdgeAttachedTo represents resource attachment or association.
	EdgeAttachedTo EdgeType = "attached_to"
	// EdgeContainedIn represents subnet/VPC/container membership.
	EdgeContainedIn EdgeType = "contained_in"
	// EdgeHasPublicAccess represents public exposure on a resource.
	EdgeHasPublicAccess EdgeType = "has_public_access"
	// EdgeAssumes represents an identity or workload assuming a role.
	EdgeAssumes EdgeType = EdgeCanAssume
	// EdgePassesRole represents iam:PassRole capability.
	EdgePassesRole EdgeType = EdgeCanPassRole
	// EdgeGrantsPermission represents an IAM grant to a principal.
	EdgeGrantsPermission EdgeType = "grants_permission"
	// EdgeReadsSecret represents secret read capability.
	EdgeReadsSecret EdgeType = "reads_secret"
	// EdgeEncryptsWith represents use of a KMS key for encryption.
	EdgeEncryptsWith EdgeType = "encrypts_with"
	// EdgeWritesTo represents write capability to a downstream resource.
	EdgeWritesTo EdgeType = "writes_to"
	// EdgeReplicatesTo represents data replication to another resource.
	EdgeReplicatesTo EdgeType = "replicates_to"
	// EdgeProtects represents a guardrail or protection applied to a resource.
	EdgeProtects EdgeType = "protects"
)

// NodeKind describes the security role of a graph node.
type NodeKind string

const (
	// NodeUnknown is used when ChangeGate has no stronger classification.
	NodeUnknown NodeKind = "unknown"
	// NodePublicEntrypoint is an internet-facing routing or ingress node.
	NodePublicEntrypoint NodeKind = "public_entrypoint"
	// NodeWorkload is a compute workload or executable service.
	NodeWorkload NodeKind = "workload"
	// NodeDataStore is a persistent data store.
	NodeDataStore NodeKind = "data_store"
	// NodeSecret is a secret value or secret container.
	NodeSecret NodeKind = "secret"
	// NodeKMSKey is a cryptographic key.
	NodeKMSKey NodeKind = "kms_key"
	// NodePrincipal is an IAM principal.
	NodePrincipal NodeKind = "principal"
	// NodePolicy is an IAM or resource policy.
	NodePolicy NodeKind = "policy"
	// NodeNetworkBoundary is a network control, boundary, or routing node.
	NodeNetworkBoundary NodeKind = "network_boundary"
)

// Graph is a deterministic resource relationship graph.
type Graph struct {
	Nodes map[ResourceID]*Node `json:"nodes"`
	Edges []Edge               `json:"edges"`
}

// Node is a resource or synthetic graph node.
type Node struct {
	ID          ResourceID        `json:"id"`
	Address     string            `json:"address"`
	Type        string            `json:"type"`
	Kind        NodeKind          `json:"kind"`
	Name        string            `json:"name"`
	Provider    string            `json:"provider,omitempty"`
	ModulePath  []string          `json:"module_path,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Values      map[string]any    `json:"values,omitempty"`
	Changed     bool              `json:"changed,omitempty"`
	Actions     []model.Action    `json:"actions,omitempty"`
	Synthetic   bool              `json:"synthetic,omitempty"`
}

// Edge connects two graph nodes with evidence.
type Edge struct {
	From     ResourceID        `json:"from"`
	To       ResourceID        `json:"to"`
	Type     EdgeType          `json:"type"`
	Evidence []model.Evidence  `json:"evidence,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Path is an ordered graph path.
type Path struct {
	Nodes []ResourceID `json:"nodes"`
	Edges []Edge       `json:"edges"`
}

// PathOptions controls graph path expansion.
type PathOptions struct {
	MaxDepth     int
	MaxPaths     int
	AllowedEdges []EdgeType
}

// ExposureResult explains whether and how a resource is internet exposed.
type ExposureResult struct {
	Resource     ResourceID `json:"resource"`
	Exposed      bool       `json:"exposed"`
	Entrypoints  []Node     `json:"entrypoints,omitempty"`
	Paths        []Path     `json:"paths,omitempty"`
	DirectPublic bool       `json:"direct_public,omitempty"`
}

// BlastRadiusOptions controls blast-radius traversal.
type BlastRadiusOptions struct {
	MaxDepth int
	MaxPaths int
}

// BlastRadius summarizes reachable assets from a resource.
type BlastRadius struct {
	Resource           ResourceID     `json:"resource"`
	Exposure           ExposureResult `json:"exposure"`
	ReachableWorkloads []ResourceID   `json:"reachable_workloads,omitempty"`
	SensitiveAssets    []ResourceID   `json:"sensitive_assets,omitempty"`
	Paths              []Path         `json:"paths,omitempty"`
}

// Build constructs a graph from a normalized plan.
func Build(plan *model.Plan) *Graph {
	g := &Graph{Nodes: make(map[ResourceID]*Node)}
	if plan == nil {
		return g
	}

	for _, resource := range plan.Resources {
		g.addResource(resource)
	}
	for _, resource := range plan.PriorResources {
		g.addResource(resource)
	}
	for _, change := range plan.Changes {
		g.addChange(change)
	}

	inferExplicitDependencies(g, plan)
	inferGenericReferences(g)
	inferAWSNetwork(g)
	inferAWSLoadBalancing(g)
	inferAWSECS(g)
	inferAWSLambda(g)
	inferAWSRDS(g)
	inferAWSS3(g)
	inferAWSDataProtection(g)
	inferAWSIAM(g)
	propagateEnvironment(g)
	g.sort()
	return g
}

// Path finds the shortest directed path between two nodes.
func (g *Graph) Path(from ResourceID, to ResourceID) (Path, bool) {
	if g == nil || g.Nodes[from] == nil || g.Nodes[to] == nil {
		return Path{}, false
	}
	if from == to {
		return Path{Nodes: []ResourceID{from}}, true
	}

	adj := g.adjacency()
	queue := []ResourceID{from}
	visited := map[ResourceID]bool{from: true}
	prevNode := make(map[ResourceID]ResourceID)
	prevEdge := make(map[ResourceID]Edge)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range adj[current] {
			if visited[edge.To] {
				continue
			}
			visited[edge.To] = true
			prevNode[edge.To] = current
			prevEdge[edge.To] = edge
			if edge.To == to {
				return reconstructPath(from, to, prevNode, prevEdge), true
			}
			queue = append(queue, edge.To)
		}
	}
	return Path{}, false
}

// Paths returns deterministic directed paths between two nodes.
func (g *Graph) Paths(from ResourceID, to ResourceID, opts PathOptions) []Path {
	if g == nil || g.Nodes[from] == nil || g.Nodes[to] == nil {
		return nil
	}
	if from == to {
		return []Path{{Nodes: []ResourceID{from}}}
	}
	opts = normalizePathOptions(opts)
	allowed := allowedEdgeSet(opts.AllowedEdges)
	adj := g.adjacency()
	type item struct {
		node  ResourceID
		path  Path
		seen  map[ResourceID]bool
		depth int
	}
	queue := []item{{
		node: from,
		path: Path{Nodes: []ResourceID{from}},
		seen: map[ResourceID]bool{from: true},
	}}
	paths := make([]Path, 0)
	for len(queue) > 0 && len(paths) < opts.MaxPaths {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= opts.MaxDepth {
			continue
		}
		for _, edge := range adj[current.node] {
			if len(allowed) > 0 && !allowed[edge.Type] {
				continue
			}
			if current.seen[edge.To] {
				continue
			}
			nextPath := Path{
				Nodes: append(append([]ResourceID{}, current.path.Nodes...), edge.To),
				Edges: append(append([]Edge{}, current.path.Edges...), edge),
			}
			if edge.To == to {
				paths = append(paths, nextPath)
				if len(paths) >= opts.MaxPaths {
					break
				}
				continue
			}
			nextSeen := copySeen(current.seen)
			nextSeen[edge.To] = true
			queue = append(queue, item{node: edge.To, path: nextPath, seen: nextSeen, depth: current.depth + 1})
		}
	}
	sort.SliceStable(paths, func(i int, j int) bool {
		return pathKey(paths[i]) < pathKey(paths[j])
	})
	return paths
}

// Exposure explains public reachability for a resource.
func (g *Graph) Exposure(resource ResourceID) ExposureResult {
	result := ExposureResult{Resource: resource}
	if g == nil || g.Nodes[resource] == nil {
		return result
	}
	for _, edge := range g.Edges {
		if edge.From == InternetNodeID && edge.To == resource && publicEdge(edge.Type) {
			result.DirectPublic = true
			result.Exposed = true
			break
		}
	}
	for _, entrypoint := range g.PublicEntrypoints() {
		paths := g.Paths(entrypoint, resource, PathOptions{
			MaxDepth:     12,
			MaxPaths:     3,
			AllowedEdges: exposureEdges(),
		})
		if len(paths) == 0 && entrypoint != resource {
			continue
		}
		if entrypoint == resource && len(paths) == 0 {
			paths = []Path{{Nodes: []ResourceID{resource}}}
		}
		if node := g.Nodes[entrypoint]; node != nil {
			result.Entrypoints = append(result.Entrypoints, *copyNode(node))
		}
		result.Paths = append(result.Paths, paths...)
		result.Exposed = true
	}
	sort.SliceStable(result.Entrypoints, func(i int, j int) bool {
		return result.Entrypoints[i].ID < result.Entrypoints[j].ID
	})
	sort.SliceStable(result.Paths, func(i int, j int) bool {
		return pathKey(result.Paths[i]) < pathKey(result.Paths[j])
	})
	return result
}

// BlastRadius summarizes workloads and sensitive assets reachable from a resource.
func (g *Graph) BlastRadius(resource ResourceID, opts BlastRadiusOptions) BlastRadius {
	opts = normalizeBlastRadiusOptions(opts)
	result := BlastRadius{
		Resource: resource,
		Exposure: g.Exposure(resource),
	}
	if g == nil || g.Nodes[resource] == nil {
		return result
	}
	seenWorkloads := make(map[ResourceID]bool)
	seenSensitive := make(map[ResourceID]bool)
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if id == resource {
			continue
		}
		if node.Kind != NodeWorkload && !isSensitiveKind(node.Kind) {
			continue
		}
		paths := g.Paths(resource, id, PathOptions{
			MaxDepth:     opts.MaxDepth,
			MaxPaths:     opts.MaxPaths,
			AllowedEdges: reachabilityEdges(),
		})
		if len(paths) == 0 {
			continue
		}
		if node.Kind == NodeWorkload && !seenWorkloads[id] {
			seenWorkloads[id] = true
			result.ReachableWorkloads = append(result.ReachableWorkloads, id)
		}
		if isSensitiveKind(node.Kind) && !seenSensitive[id] {
			seenSensitive[id] = true
			result.SensitiveAssets = append(result.SensitiveAssets, id)
		}
		result.Paths = append(result.Paths, paths...)
	}
	sortResourceIDs(result.ReachableWorkloads)
	sortResourceIDs(result.SensitiveAssets)
	sort.SliceStable(result.Paths, func(i int, j int) bool {
		return pathKey(result.Paths[i]) < pathKey(result.Paths[j])
	})
	if len(result.Paths) > opts.MaxPaths {
		result.Paths = append([]Path{}, result.Paths[:opts.MaxPaths]...)
	}
	return result
}

// PublicEntrypoints returns resources that introduce public reachability.
func (g *Graph) PublicEntrypoints() []ResourceID {
	if g == nil {
		return nil
	}
	seen := make(map[ResourceID]bool)
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if node.Kind == NodePublicEntrypoint && !node.Synthetic && g.hasPublicInboundEdge(id) {
			seen[id] = true
		}
	}
	for _, edge := range g.Edges {
		if edge.From == InternetNodeID && publicEdge(edge.Type) {
			if node := g.Nodes[edge.To]; node != nil && node.Kind != NodeNetworkBoundary {
				seen[edge.To] = true
			}
		}
	}
	out := make([]ResourceID, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sortResourceIDs(out)
	return out
}

// SensitiveAssets returns data stores, secrets, and KMS keys.
func (g *Graph) SensitiveAssets() []ResourceID {
	if g == nil {
		return nil
	}
	out := make([]ResourceID, 0)
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if isSensitiveKind(node.Kind) {
			out = append(out, id)
		}
	}
	sortResourceIDs(out)
	return out
}

// ChangedBoundaryCrossings returns public-to-sensitive paths affected by this plan.
func (g *Graph) ChangedBoundaryCrossings() []Path {
	if g == nil {
		return nil
	}
	paths := make([]Path, 0)
	for _, entrypoint := range g.PublicEntrypoints() {
		for _, asset := range g.SensitiveAssets() {
			for _, path := range g.Paths(entrypoint, asset, PathOptions{MaxDepth: 12, MaxPaths: 3, AllowedEdges: reachabilityEdges()}) {
				if g.pathTouchesChangedNode(path) {
					paths = append(paths, path)
				}
			}
		}
	}
	sort.SliceStable(paths, func(i int, j int) bool {
		return pathKey(paths[i]) < pathKey(paths[j])
	})
	return paths
}

// IsInternetExposed reports whether a resource has public exposure evidence.
func (g *Graph) IsInternetExposed(resource ResourceID) bool {
	if g == nil {
		return false
	}
	if _, ok := g.pathWithTypes(InternetNodeID, resource, map[EdgeType]bool{
		EdgeRoutesTo:        true,
		EdgeAllowsIngress:   true,
		EdgeHasPublicAccess: true,
		EdgeAttachedTo:      true,
	}); ok {
		return true
	}
	for _, edge := range g.Edges {
		if edge.To == resource && edge.Type == EdgeHasPublicAccess && edge.From == InternetNodeID {
			return true
		}
		if edge.From == InternetNodeID && edge.To == resource && (edge.Type == EdgeAllowsIngress || edge.Type == EdgeRoutesTo) {
			return true
		}
	}
	return false
}

// CanReach reports whether source can reach target through network/routing/data edges.
func (g *Graph) CanReach(source ResourceID, target ResourceID) bool {
	_, ok := g.pathWithTypes(source, target, map[EdgeType]bool{
		EdgeRoutesTo:      true,
		EdgeAllowsIngress: true,
		EdgeAllowsEgress:  true,
		EdgeAttachedTo:    true,
		EdgeContainedIn:   true,
		EdgeCanReadData:   true,
		EdgeCanWriteData:  true,
	})
	return ok
}

// CanAssumeRole reports whether principal can assume role.
func (g *Graph) CanAssumeRole(principal ResourceID, role ResourceID) bool {
	return g.hasEdge(principal, role, EdgeCanAssume)
}

// CanPassRole reports whether principal can pass role.
func (g *Graph) CanPassRole(principal ResourceID, role ResourceID) bool {
	return g.hasEdge(principal, role, EdgeCanPassRole)
}

// HasSensitiveDataAccess reports whether resource can read or write sensitive data.
func (g *Graph) HasSensitiveDataAccess(resource ResourceID) bool {
	if g == nil {
		return false
	}
	for _, edge := range g.Edges {
		if edge.From == resource && (edge.Type == EdgeCanReadData || edge.Type == EdgeCanWriteData) {
			if target := g.Nodes[edge.To]; target != nil && isSensitiveDataNode(target) {
				return true
			}
		}
	}
	return false
}

// OutgoingEdges returns deterministic outgoing edges for a node.
func (g *Graph) OutgoingEdges(resource ResourceID) []Edge {
	if g == nil {
		return nil
	}
	out := make([]Edge, 0)
	for _, edge := range g.Edges {
		if edge.From == resource {
			out = append(out, edge)
		}
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return edgeKey(out[i]) < edgeKey(out[j])
	})
	return out
}

// IncomingEdges returns deterministic incoming edges for a node.
func (g *Graph) IncomingEdges(resource ResourceID) []Edge {
	if g == nil {
		return nil
	}
	out := make([]Edge, 0)
	for _, edge := range g.Edges {
		if edge.To == resource {
			out = append(out, edge)
		}
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return edgeKey(out[i]) < edgeKey(out[j])
	})
	return out
}

// ExplainConnection returns evidence lines for a path between resources.
func (g *Graph) ExplainConnection(from ResourceID, to ResourceID) ([]string, bool) {
	path, ok := g.Path(from, to)
	if !ok {
		return nil, false
	}
	lines := make([]string, 0)
	for _, edge := range path.Edges {
		for _, evidence := range edge.Evidence {
			lines = append(lines, model.RenderEvidence([]model.Evidence{evidence})...)
		}
	}
	sort.Strings(lines)
	return lines, true
}

func (g *Graph) addResource(resource model.Resource) {
	if resource.Address == "" {
		return
	}
	id := ResourceID(resource.Address)
	if existing := g.Nodes[id]; existing != nil {
		mergeTags(existing.Tags, resource.Tags)
		if existing.Environment == "" {
			existing.Environment = environmentFromTags(existing.Tags)
		}
		return
	}
	node := &Node{
		ID:          id,
		Address:     resource.Address,
		Type:        resource.Type,
		Kind:        classifyNodeKind(resource.Type, resource.Values),
		Name:        resource.Name,
		Provider:    resource.Provider,
		ModulePath:  append([]string(nil), resource.ModulePath...),
		Environment: environmentFromTags(resource.Tags),
		Tags:        copyTags(resource.Tags),
		Values:      copyValues(resource.Values),
	}
	g.Nodes[id] = node
}

func (g *Graph) addChange(change model.Change) {
	if change.Address == "" {
		return
	}
	id := ResourceID(change.Address)
	if existing := g.Nodes[id]; existing != nil {
		if existing.Tags == nil {
			existing.Tags = make(map[string]string, len(change.Tags))
		}
		mergeTags(existing.Tags, change.Tags)
		if existing.Environment == "" {
			existing.Environment = environmentFromTags(existing.Tags)
		}
		if len(existing.Values) == 0 {
			existing.Values = copyValues(change.After)
		}
		existing.Changed = hasMaterialAction(change.Actions)
		existing.Actions = append([]model.Action(nil), change.Actions...)
		existing.Kind = classifyNodeKind(existing.Type, existing.Values)
		return
	}
	g.Nodes[id] = &Node{
		ID:          id,
		Address:     change.Address,
		Type:        change.Type,
		Kind:        classifyNodeKind(change.Type, change.After),
		Name:        change.Name,
		Provider:    change.Provider,
		ModulePath:  append([]string(nil), change.ModulePath...),
		Environment: environmentFromTags(change.Tags),
		Tags:        copyTags(change.Tags),
		Values:      copyValues(change.After),
		Changed:     hasMaterialAction(change.Actions),
		Actions:     append([]model.Action(nil), change.Actions...),
	}
}

func (g *Graph) ensureSynthetic(id ResourceID, typ string, name string) {
	if g.Nodes[id] != nil {
		return
	}
	g.Nodes[id] = &Node{
		ID:        id,
		Address:   string(id),
		Type:      typ,
		Kind:      classifyNodeKind(typ, nil),
		Name:      name,
		Synthetic: true,
	}
}

func (g *Graph) addEdge(from ResourceID, to ResourceID, edgeType EdgeType, evidence []model.Evidence, metadata map[string]string) {
	if from == "" || to == "" || from == to {
		return
	}
	if g.Nodes[from] == nil {
		g.ensureSynthetic(from, "external", string(from))
	}
	if g.Nodes[to] == nil {
		g.ensureSynthetic(to, "external", string(to))
	}
	edge := Edge{
		From:     from,
		To:       to,
		Type:     edgeType,
		Evidence: model.RedactEvidence(evidence),
		Metadata: metadata,
	}
	for _, existing := range g.Edges {
		if edgeKey(existing) == edgeKey(edge) {
			return
		}
	}
	g.Edges = append(g.Edges, edge)
}

func (g *Graph) sort() {
	for _, node := range g.Nodes {
		sort.Strings(node.ModulePath)
	}
	sort.SliceStable(g.Edges, func(i int, j int) bool {
		return edgeKey(g.Edges[i]) < edgeKey(g.Edges[j])
	})
}

func (g *Graph) adjacency() map[ResourceID][]Edge {
	adj := make(map[ResourceID][]Edge)
	for _, edge := range g.Edges {
		adj[edge.From] = append(adj[edge.From], edge)
	}
	for node := range adj {
		sort.SliceStable(adj[node], func(i int, j int) bool {
			return edgeKey(adj[node][i]) < edgeKey(adj[node][j])
		})
	}
	return adj
}

func (g *Graph) pathWithTypes(from ResourceID, to ResourceID, allowed map[EdgeType]bool) (Path, bool) {
	if g == nil || g.Nodes[from] == nil || g.Nodes[to] == nil {
		return Path{}, false
	}
	adj := make(map[ResourceID][]Edge)
	for _, edge := range g.Edges {
		if allowed[edge.Type] {
			adj[edge.From] = append(adj[edge.From], edge)
		}
	}
	queue := []ResourceID{from}
	visited := map[ResourceID]bool{from: true}
	prevNode := make(map[ResourceID]ResourceID)
	prevEdge := make(map[ResourceID]Edge)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range adj[current] {
			if visited[edge.To] {
				continue
			}
			visited[edge.To] = true
			prevNode[edge.To] = current
			prevEdge[edge.To] = edge
			if edge.To == to {
				return reconstructPath(from, to, prevNode, prevEdge), true
			}
			queue = append(queue, edge.To)
		}
	}
	return Path{}, false
}

func (g *Graph) hasEdge(from ResourceID, to ResourceID, edgeType EdgeType) bool {
	if g == nil {
		return false
	}
	for _, edge := range g.Edges {
		if edge.From == from && edge.To == to && edge.Type == edgeType {
			return true
		}
	}
	return false
}

func reconstructPath(from ResourceID, to ResourceID, prevNode map[ResourceID]ResourceID, prevEdge map[ResourceID]Edge) Path {
	nodes := []ResourceID{to}
	edges := make([]Edge, 0)
	for current := to; current != from; current = prevNode[current] {
		edges = append([]Edge{prevEdge[current]}, edges...)
		nodes = append([]ResourceID{prevNode[current]}, nodes...)
	}
	return Path{Nodes: nodes, Edges: edges}
}

func edgeKey(edge Edge) string {
	return string(edge.From) + "\x00" + string(edge.Type) + "\x00" + string(edge.To)
}

func pathKey(path Path) string {
	parts := make([]string, 0, len(path.Nodes)+len(path.Edges))
	for _, node := range path.Nodes {
		parts = append(parts, string(node))
	}
	for _, edge := range path.Edges {
		parts = append(parts, edgeKey(edge))
	}
	return strings.Join(parts, "\x00")
}

func sortedNodeIDs(g *Graph) []ResourceID {
	if g == nil {
		return nil
	}
	out := make([]ResourceID, 0, len(g.Nodes))
	for id := range g.Nodes {
		out = append(out, id)
	}
	sortResourceIDs(out)
	return out
}

func evidence(resource string, path string, value any, message string) []model.Evidence {
	return []model.Evidence{{
		Type:     "graph",
		Resource: resource,
		Path:     path,
		Value:    value,
		Message:  message,
	}}
}

func environmentFromTags(tags map[string]string) string {
	for _, key := range []string{"env", "environment", "stage"} {
		value := strings.ToLower(tags[key])
		switch value {
		case "prod", "production":
			return "production"
		case "stage", "staging":
			return "staging"
		case "dev", "development":
			return "development"
		}
	}
	return ""
}

func copyTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for key, value := range tags {
		out[key] = value
	}
	return out
}

func mergeTags(target map[string]string, source map[string]string) {
	if target == nil {
		return
	}
	for key, value := range source {
		target[key] = value
	}
}

func copyValues(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func isSensitiveDataNode(node *Node) bool {
	if node == nil {
		return false
	}
	return isSensitiveKind(node.Kind)
}

func classifyNodeKind(resourceType string, values map[string]any) NodeKind {
	switch resourceType {
	case "internet":
		return NodePublicEntrypoint
	case "aws_lb", "aws_elb", "aws_cloudfront_distribution", "aws_api_gateway_rest_api", "aws_apigatewayv2_api", "aws_api_gateway_stage", "aws_apigatewayv2_stage":
		return NodePublicEntrypoint
	case "aws_instance", "aws_launch_template", "aws_autoscaling_group", "aws_ecs_service", "aws_ecs_task_definition", "aws_lambda_function", "aws_eks_cluster", "aws_eks_node_group":
		return NodeWorkload
	case "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_dynamodb_table", "aws_efs_file_system", "aws_elasticache_cluster", "aws_elasticache_replication_group", "aws_opensearch_domain", "aws_elasticsearch_domain":
		return NodeDataStore
	case "aws_secretsmanager_secret", "aws_ssm_parameter":
		return NodeSecret
	case "aws_kms_key", "aws_kms_alias":
		return NodeKMSKey
	case "aws_iam_role", "aws_iam_user", "aws_iam_group", "aws_iam_instance_profile":
		return NodePrincipal
	case "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_s3_bucket_policy", "aws_kms_key_policy":
		return NodePolicy
	case "aws_security_group", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule", "aws_subnet", "aws_route", "aws_route_table", "aws_route_table_association", "aws_internet_gateway", "aws_nat_gateway", "aws_vpc", "aws_vpc_peering_connection", "aws_ec2_transit_gateway", "aws_ec2_transit_gateway_route":
		return NodeNetworkBoundary
	default:
		if publicBool(values["publicly_accessible"]) || asString(values["scheme"]) == "internet-facing" {
			return NodePublicEntrypoint
		}
		return NodeUnknown
	}
}

func isSensitiveKind(kind NodeKind) bool {
	switch kind {
	case NodeDataStore, NodeSecret, NodeKMSKey:
		return true
	default:
		return false
	}
}

func hasMaterialAction(actions []model.Action) bool {
	for _, action := range actions {
		switch action {
		case model.ActionCreate, model.ActionUpdate, model.ActionDelete, model.ActionReplace:
			return true
		}
	}
	return false
}

func normalizePathOptions(opts PathOptions) PathOptions {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 12
	}
	if opts.MaxPaths <= 0 {
		opts.MaxPaths = 10
	}
	return opts
}

func normalizeBlastRadiusOptions(opts BlastRadiusOptions) BlastRadiusOptions {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 12
	}
	if opts.MaxPaths <= 0 {
		opts.MaxPaths = 25
	}
	return opts
}

func allowedEdgeSet(edges []EdgeType) map[EdgeType]bool {
	if len(edges) == 0 {
		return nil
	}
	out := make(map[EdgeType]bool, len(edges))
	for _, edge := range edges {
		out[edge] = true
	}
	return out
}

func reachabilityEdges() []EdgeType {
	return []EdgeType{
		EdgeRoutesTo,
		EdgeAllowsIngress,
		EdgeAllowsEgress,
		EdgeAttachedTo,
		EdgeContainedIn,
		EdgeCanReadData,
		EdgeCanWriteData,
		EdgeReadsSecret,
		EdgeWritesTo,
		EdgeReplicatesTo,
	}
}

func exposureEdges() []EdgeType {
	return []EdgeType{
		EdgeRoutesTo,
		EdgeAllowsIngress,
		EdgeAttachedTo,
		EdgeContainedIn,
		EdgeHasPublicAccess,
	}
}

func publicEdge(edgeType EdgeType) bool {
	switch edgeType {
	case EdgeRoutesTo, EdgeAllowsIngress, EdgeHasPublicAccess, EdgeCanReadData:
		return true
	default:
		return false
	}
}

func copySeen(in map[ResourceID]bool) map[ResourceID]bool {
	out := make(map[ResourceID]bool, len(in)+1)
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyNode(node *Node) *Node {
	if node == nil {
		return nil
	}
	out := *node
	out.ModulePath = append([]string(nil), node.ModulePath...)
	out.Tags = copyTags(node.Tags)
	out.Values = copyValues(node.Values)
	out.Actions = append([]model.Action(nil), node.Actions...)
	return &out
}

func sortResourceIDs(values []ResourceID) {
	sort.SliceStable(values, func(i int, j int) bool {
		return values[i] < values[j]
	})
}

func (g *Graph) pathTouchesChangedNode(path Path) bool {
	for _, id := range path.Nodes {
		if node := g.Nodes[id]; node != nil && node.Changed {
			return true
		}
	}
	return false
}

func (g *Graph) hasPublicInboundEdge(id ResourceID) bool {
	for _, edge := range g.Edges {
		if edge.From == InternetNodeID && edge.To == id && publicEdge(edge.Type) {
			return true
		}
	}
	return false
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(value)
	}
}
