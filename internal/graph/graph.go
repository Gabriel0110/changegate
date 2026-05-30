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
	Name        string            `json:"name"`
	Provider    string            `json:"provider,omitempty"`
	ModulePath  []string          `json:"module_path,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Values      map[string]any    `json:"values,omitempty"`
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
	node := &Node{
		ID:          id,
		Address:     resource.Address,
		Type:        resource.Type,
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
		return
	}
	g.Nodes[id] = &Node{
		ID:          id,
		Address:     change.Address,
		Type:        change.Type,
		Name:        change.Name,
		Provider:    change.Provider,
		ModulePath:  append([]string(nil), change.ModulePath...),
		Environment: environmentFromTags(change.Tags),
		Tags:        copyTags(change.Tags),
		Values:      copyValues(change.After),
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
	switch node.Type {
	case "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_secretsmanager_secret", "aws_dynamodb_table":
		return true
	default:
		return false
	}
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
