// Package visual renders ChangeGate graph evidence as human-readable diagrams.
package visual

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/attackpath"
	graphpkg "github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

// Role describes the visual and security role of a diagram element.
type Role string

const (
	RoleDefault   Role = "default"
	RoleChanged   Role = "changed"
	RolePublic    Role = "public"
	RoleWorkload  Role = "workload"
	RoleSensitive Role = "sensitive"
	RolePrincipal Role = "principal"
	RolePolicy    Role = "policy"
	RoleNetwork   Role = "network"
	RolePath      Role = "path"
	RoleBlock     Role = "block"
	RoleWarn      Role = "warn"
	RoleAllow     Role = "allow"
	RoleInternet  Role = "internet"
)

// Node is a renderable graph vertex.
type Node struct {
	ID       string
	Label    string
	Kind     string
	Type     string
	Role     Role
	Changed  bool
	Decision model.Decision
	Severity model.Severity
	Details  []string
}

// Edge is a renderable directed relationship.
type Edge struct {
	From       string
	To         string
	Label      string
	Role       Role
	Confidence string
	Details    []string
}

// Diagram is a renderer-neutral visualization model.
type Diagram struct {
	Title       string
	Description string
	Nodes       []Node
	Edges       []Edge
	FocusPaths  [][]string
}

// GraphOptions controls graph diagram construction.
type GraphOptions struct {
	Title       string
	Description string
	Paths       []graphpkg.Path
	FocusNodes  []graphpkg.ResourceID
	FocusEdges  []graphpkg.Edge
	FocusOnly   bool
}

// NewGraphDiagram adapts a ChangeGate graph and optional focus paths to a diagram.
func NewGraphDiagram(g *graphpkg.Graph, opts GraphOptions) Diagram {
	title := opts.Title
	if title == "" {
		title = "ChangeGate Graph"
	}
	if g == nil {
		return Diagram{Title: title, Description: opts.Description}
	}
	focusNodes := make(map[string]bool)
	focusEdges := make(map[string]bool)
	focusPaths := make([][]string, 0, len(opts.Paths))
	for _, id := range opts.FocusNodes {
		focusNodes[string(id)] = true
	}
	for _, edge := range opts.FocusEdges {
		focusEdges[edgeKey(string(edge.From), string(edge.To), string(edge.Type))] = true
	}
	for _, path := range opts.Paths {
		renderPath := make([]string, 0, len(path.Nodes))
		for _, id := range path.Nodes {
			focusNodes[string(id)] = true
			renderPath = append(renderPath, string(id))
		}
		for _, edge := range path.Edges {
			focusEdges[edgeKey(string(edge.From), string(edge.To), string(edge.Type))] = true
		}
		if len(renderPath) > 0 {
			focusPaths = append(focusPaths, renderPath)
		}
	}

	nodes := make([]Node, 0, len(g.Nodes))
	for _, id := range sortedGraphNodeIDs(g) {
		source := g.Nodes[id]
		if opts.FocusOnly && !focusNodes[string(source.ID)] {
			continue
		}
		node := Node{
			ID:      string(source.ID),
			Label:   labelForGraphNode(source),
			Kind:    displayGraphKind(source.Kind),
			Type:    source.Type,
			Role:    roleForGraphNode(source),
			Changed: source.Changed,
			Details: graphNodeDetails(source),
		}
		if focusNodes[node.ID] && node.Role == RoleDefault {
			node.Role = RolePath
		}
		nodes = append(nodes, node)
	}

	edges := make([]Edge, 0, len(g.Edges))
	for _, source := range g.Edges {
		isFocusEdge := focusEdges[edgeKey(string(source.From), string(source.To), string(source.Type))]
		if opts.FocusOnly && !isFocusEdge {
			continue
		}
		edge := Edge{
			From:       string(source.From),
			To:         string(source.To),
			Label:      humanizeEdgeLabel(string(source.Type)),
			Role:       RoleDefault,
			Confidence: string(source.Confidence),
			Details:    graphEdgeDetails(source),
		}
		if isFocusEdge {
			edge.Role = RolePath
		}
		edges = append(edges, edge)
	}
	sortEdges(edges)
	return Diagram{
		Title:       title,
		Description: opts.Description,
		Nodes:       nodes,
		Edges:       edges,
		FocusPaths:  focusPaths,
	}
}

// NewGraphPathDiagram adapts path search output to a focused path diagram.
func NewGraphPathDiagram(g *graphpkg.Graph, from graphpkg.ResourceID, to graphpkg.ResourceID, paths []graphpkg.Path) Diagram {
	return NewGraphDiagram(g, GraphOptions{
		Title:       "ChangeGate Graph Path",
		Description: fmt.Sprintf("%s to %s", from, to),
		Paths:       paths,
		FocusNodes:  []graphpkg.ResourceID{from, to},
		FocusOnly:   true,
	})
}

// NewGraphExposureDiagram adapts blast-radius output to a focused exposure diagram.
func NewGraphExposureDiagram(g *graphpkg.Graph, resource graphpkg.ResourceID, radius graphpkg.BlastRadius) Diagram {
	paths := combinedExposurePaths(resource, radius)
	focus := []graphpkg.ResourceID{resource}
	focus = append(focus, radius.ReachableWorkloads...)
	focus = append(focus, radius.SensitiveAssets...)
	for _, entry := range radius.Exposure.Entrypoints {
		focus = append(focus, entry.ID)
	}
	return NewGraphDiagram(g, GraphOptions{
		Title:       "ChangeGate Exposure Graph",
		Description: fmt.Sprintf("Blast radius for %s", resource),
		Paths:       paths,
		FocusNodes:  dedupeResourceIDs(focus),
		FocusOnly:   true,
	})
}

func combinedExposurePaths(resource graphpkg.ResourceID, radius graphpkg.BlastRadius) []graphpkg.Path {
	if len(radius.Exposure.Paths) == 0 || len(radius.Paths) == 0 {
		paths := append([]graphpkg.Path{}, radius.Exposure.Paths...)
		paths = append(paths, radius.Paths...)
		return paths
	}
	combined := make([]graphpkg.Path, 0, len(radius.Exposure.Paths)*len(radius.Paths))
	for _, exposurePath := range radius.Exposure.Paths {
		for _, blastPath := range radius.Paths {
			if len(exposurePath.Nodes) == 0 || len(blastPath.Nodes) == 0 {
				continue
			}
			if exposurePath.Nodes[len(exposurePath.Nodes)-1] != resource || blastPath.Nodes[0] != resource {
				continue
			}
			nodes := append([]graphpkg.ResourceID{}, exposurePath.Nodes...)
			nodes = append(nodes, blastPath.Nodes[1:]...)
			edges := append([]graphpkg.Edge{}, exposurePath.Edges...)
			edges = append(edges, blastPath.Edges...)
			combined = append(combined, graphpkg.Path{Nodes: nodes, Edges: edges})
		}
	}
	if len(combined) > 0 {
		return combined
	}
	paths := append([]graphpkg.Path{}, radius.Exposure.Paths...)
	paths = append(paths, radius.Paths...)
	return paths
}

// NewAttackPathDiagram adapts attack path evidence to a diagram.
func NewAttackPathDiagram(paths []attackpath.AttackPath) Diagram {
	nodesByID := make(map[string]Node)
	edgesByKey := make(map[string]Edge)
	focusPaths := make([][]string, 0, len(paths))
	for _, path := range paths {
		route := make([]string, 0, len(path.Steps)+1)
		for index, step := range path.Steps {
			from := strings.TrimSpace(step.From)
			to := strings.TrimSpace(step.To)
			if from == "" || to == "" {
				continue
			}
			if index == 0 {
				route = append(route, from)
			}
			route = append(route, to)
			upsertAttackNode(nodesByID, from, path)
			upsertAttackNode(nodesByID, to, path)
			label := step.Action
			if label == "" {
				label = string(step.EdgeType)
			}
			label = humanizeEdgeLabel(label)
			key := edgeKey(from, to, label)
			edgesByKey[key] = Edge{
				From:    from,
				To:      to,
				Label:   label,
				Role:    roleForDecision(path.Decision),
				Details: attackStepDetails(path, step),
			}
		}
		if len(route) > 0 {
			focusPaths = append(focusPaths, route)
		}
	}
	nodes := make([]Node, 0, len(nodesByID))
	for _, id := range sortedStringKeys(nodesByID) {
		nodes = append(nodes, nodesByID[id])
	}
	edges := make([]Edge, 0, len(edgesByKey))
	for _, key := range sortedStringKeys(edgesByKey) {
		edges = append(edges, edgesByKey[key])
	}
	return Diagram{
		Title:       "ChangeGate Attack Paths",
		Description: fmt.Sprintf("%d detected %s", len(paths), pluralizeNoun(len(paths), "attack path", "attack paths")),
		Nodes:       nodes,
		Edges:       edges,
		FocusPaths:  focusPaths,
	}
}

func upsertAttackNode(nodes map[string]Node, id string, path attackpath.AttackPath) {
	node := nodes[id]
	role := roleForAttackNode(id, path)
	if node.ID == "" {
		node = Node{
			ID:       id,
			Label:    id,
			Kind:     "",
			Role:     role,
			Decision: path.Decision,
			Severity: path.Severity,
		}
	}
	if roleRank(role) > roleRank(node.Role) {
		node.Role = role
	}
	node.Details = appendUniqueString(node.Details, path.Title)
	nodes[id] = node
}

func roleForGraphNode(node *graphpkg.Node) Role {
	if node == nil {
		return RoleDefault
	}
	if node.ID == graphpkg.InternetNodeID {
		return RoleInternet
	}
	switch node.Kind {
	case graphpkg.NodePublicEntrypoint:
		return RolePublic
	case graphpkg.NodeWorkload:
		return RoleWorkload
	case graphpkg.NodeDataStore, graphpkg.NodeSecret, graphpkg.NodeKMSKey:
		return RoleSensitive
	case graphpkg.NodePrincipal:
		return RolePrincipal
	case graphpkg.NodePolicy:
		return RolePolicy
	case graphpkg.NodeNetworkBoundary:
		return RoleNetwork
	default:
		if node.Changed {
			return RoleChanged
		}
		return RoleDefault
	}
}

func roleForAttackNode(id string, path attackpath.AttackPath) Role {
	switch {
	case id == string(graphpkg.InternetNodeID):
		return RoleInternet
	case id == path.Principal:
		return RolePrincipal
	case id == path.Entrypoint:
		return RolePublic
	case id == path.Target:
		return roleForDecision(path.Decision)
	default:
		return RolePath
	}
}

func roleForDecision(decision model.Decision) Role {
	switch decision {
	case model.DecisionBlock, model.DecisionError:
		return RoleBlock
	case model.DecisionWarn:
		return RoleWarn
	case model.DecisionAllow:
		return RoleAllow
	default:
		return RolePath
	}
}

func roleRank(role Role) int {
	switch role {
	case RoleBlock:
		return 100
	case RoleWarn:
		return 90
	case RolePublic, RoleSensitive, RolePrincipal:
		return 80
	case RoleChanged:
		return 70
	case RolePath:
		return 60
	default:
		return 0
	}
}

func labelForGraphNode(node *graphpkg.Node) string {
	if node == nil {
		return ""
	}
	if node.Address != "" {
		return node.Address
	}
	if node.Name != "" {
		return node.Name
	}
	return string(node.ID)
}

func graphNodeDetails(node *graphpkg.Node) []string {
	if node == nil {
		return nil
	}
	details := make([]string, 0, 4)
	if node.Name != "" && node.Name != node.Address && node.Name != string(node.ID) {
		details = append(details, "name: "+node.Name)
	}
	if node.Type != "" {
		details = append(details, "type: "+node.Type)
	}
	if kind := displayGraphKind(node.Kind); kind != "" {
		details = append(details, "kind: "+kind)
	}
	if node.Environment != "" {
		details = append(details, "environment: "+node.Environment)
	}
	details = append(details, graphIdentityDetails(node.Values)...)
	if node.Changed {
		actions := make([]string, 0, len(node.Actions))
		for _, action := range node.Actions {
			actions = append(actions, string(action))
		}
		if len(actions) > 0 {
			details = append(details, "actions: "+strings.Join(actions, ", "))
		} else {
			details = append(details, "changed")
		}
	}
	return details
}

func graphIdentityDetails(values map[string]any) []string {
	if len(values) == 0 {
		return nil
	}
	details := make([]string, 0, 8)
	for _, key := range []string{"account_id", "region", "availability_zone", "arn", "id", "cidr_block", "state", "vpc_id", "subnet_id"} {
		if value := detailString(values, key); value != "" {
			details = append(details, strings.ReplaceAll(key, "_", " ")+": "+value)
		}
	}
	for _, key := range []string{"public", "endpoint_public_access", "sensitive_data", "encryption_enabled", "public_access_blocked", "deletion_protection"} {
		if value, ok := detailBool(values, key); ok {
			details = append(details, strings.ReplaceAll(key, "_", " ")+": "+fmt.Sprintf("%t", value))
		}
	}
	if value := detailString(values, "sensitivity_reason"); value != "" {
		details = append(details, "sensitivity: "+value)
	}
	return details
}

func detailString(values map[string]any, key string) string {
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

func detailBool(values map[string]any, key string) (bool, bool) {
	value, ok := values[key]
	if !ok {
		return false, false
	}
	typed, ok := value.(bool)
	return typed, ok
}

func graphEdgeDetails(edge graphpkg.Edge) []string {
	details := []string{fmt.Sprintf("%s -> %s", edge.From, edge.To)}
	if edge.Type != "" {
		details = append(details, "type: "+humanizeEdgeLabel(string(edge.Type)))
	}
	if edge.Source != "" {
		details = append(details, "source: "+string(edge.Source))
	}
	if edge.Confidence != "" {
		details = append(details, "confidence: "+string(edge.Confidence))
	}
	return details
}

func attackStepDetails(path attackpath.AttackPath, step attackpath.Step) []string {
	details := []string{path.Title}
	if step.Explanation != "" {
		details = append(details, step.Explanation)
	}
	if step.EdgeType != "" {
		details = append(details, "edge: "+humanizeEdgeLabel(string(step.EdgeType)))
	}
	if path.Decision != "" {
		details = append(details, "decision: "+string(path.Decision))
	}
	return details
}

func displayGraphKind(kind graphpkg.NodeKind) string {
	switch kind {
	case "", graphpkg.NodeUnknown:
		return "resource"
	default:
		return strings.ReplaceAll(string(kind), "_", " ")
	}
}

func humanizeEdgeLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	switch value {
	case "iam:PassRole", "sts:AssumeRole", "lambda:UpdateFunctionCode", "lambda:CreateFunction", "ecs:UpdateService":
		return value
	default:
		value = strings.ReplaceAll(value, "_", " ")
		return strings.Join(strings.Fields(value), " ")
	}
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func pluralizeNoun(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func dedupeResourceIDs(values []graphpkg.ResourceID) []graphpkg.ResourceID {
	seen := make(map[graphpkg.ResourceID]bool, len(values))
	out := make([]graphpkg.ResourceID, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func sortedGraphNodeIDs(g *graphpkg.Graph) []graphpkg.ResourceID {
	ids := make([]graphpkg.ResourceID, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.SliceStable(ids, func(i int, j int) bool {
		return ids[i] < ids[j]
	})
	return ids
}

func sortEdges(edges []Edge) {
	sort.SliceStable(edges, func(i int, j int) bool {
		left := edges[i]
		right := edges[j]
		for _, cmp := range []int{
			strings.Compare(left.From, right.From),
			strings.Compare(left.To, right.To),
			strings.Compare(left.Label, right.Label),
		} {
			if cmp != 0 {
				return cmp < 0
			}
		}
		return false
	})
}

func sortedStringKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func edgeKey(from string, to string, label string) string {
	return from + "\x00" + to + "\x00" + label
}
