package attackpath

import (
	"fmt"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

// DetectionOptions controls attack path detection.
type DetectionOptions struct {
	MaxDepth                int
	MaxPaths                int
	DisableWorkloadWarnings bool
}

// DetectPublicToSensitive finds internet/public-entrypoint paths to workloads and sensitive assets.
func DetectPublicToSensitive(g *graph.Graph, opts DetectionOptions) []AttackPath {
	if g == nil {
		return nil
	}
	opts = normalizeDetectionOptions(opts)
	paths := make([]AttackPath, 0)
	for _, entrypoint := range g.PublicEntrypoints() {
		radius := g.BlastRadius(entrypoint, graph.BlastRadiusOptions{MaxDepth: opts.MaxDepth, MaxPaths: opts.MaxPaths})
		sensitivePaths := detectSensitivePaths(g, entrypoint, radius)
		if len(sensitivePaths) > 0 {
			paths = append(paths, sensitivePaths...)
			continue
		}
		if opts.DisableWorkloadWarnings || expectedPublicNode(g.Nodes[entrypoint]) {
			continue
		}
		paths = append(paths, detectPublicWorkloadWarnings(g, entrypoint, radius)...)
	}
	return Normalize(paths)
}

func detectSensitivePaths(g *graph.Graph, entrypoint graph.ResourceID, radius graph.BlastRadius) []AttackPath {
	out := make([]AttackPath, 0)
	for _, path := range radius.Paths {
		target := pathTarget(path)
		targetNode := g.Nodes[target]
		if targetNode == nil || !isSensitiveNodeKind(targetNode.Kind) || !pathHasWorkload(g, path) {
			continue
		}
		fullPath := withPublicIngress(g, entrypoint, path)
		confidence := confidenceForPath(fullPath)
		decision := publicSensitiveDecision(targetNode, confidence)
		out = append(out, AttackPath{
			Type:       TypePublicToSensitiveData,
			Title:      publicSensitiveTitle(entrypoint, target),
			Severity:   publicSensitiveSeverity(decision, confidence),
			Confidence: confidence,
			Decision:   decision,
			Entrypoint: string(entrypoint),
			Target:     string(target),
			Steps:      stepsFromGraphPath(fullPath),
			Evidence: []model.Evidence{
				pathEvidence(target, fullPath, "public entrypoint reaches sensitive asset"),
			},
			Mitigations: publicSensitiveMitigations(targetNode),
			References:  []string{"https://changegate.dev/docs/attack-paths"},
			Metadata:    map[string]string{"graph_path_id": graphPathID(fullPath)},
		})
	}
	return out
}

func detectPublicWorkloadWarnings(g *graph.Graph, entrypoint graph.ResourceID, radius graph.BlastRadius) []AttackPath {
	out := make([]AttackPath, 0)
	for _, path := range radius.Paths {
		id := pathTarget(path)
		node := g.Nodes[id]
		if node == nil || node.Kind != graph.NodeWorkload {
			continue
		}
		fullPath := withPublicIngress(g, entrypoint, path)
		confidence := confidenceForPath(fullPath)
		out = append(out, AttackPath{
			Type:       TypePublicToSensitiveData,
			Title:      publicWorkloadTitle(entrypoint, id),
			Severity:   model.SeverityMedium,
			Confidence: confidence,
			Decision:   model.DecisionWarn,
			Entrypoint: string(entrypoint),
			Target:     string(id),
			Steps:      stepsFromGraphPath(fullPath),
			Evidence: []model.Evidence{
				pathEvidence(id, fullPath, "public entrypoint reaches workload with no sensitive downstream context"),
			},
			Mitigations: []string{
				"Confirm this workload is intended to be public.",
				"Attach cloud context or tags for downstream sensitive data when available.",
			},
			References: []string{"https://changegate.dev/docs/attack-paths"},
			Metadata:   map[string]string{"graph_path_id": graphPathID(fullPath)},
		})
	}
	return out
}

func graphPathID(path graph.Path) string {
	nodes := make([]string, 0, len(path.Nodes))
	for _, node := range path.Nodes {
		nodes = append(nodes, string(node))
	}
	if len(nodes) == 0 {
		return ""
	}
	return "graph-path-" + strings.ReplaceAll(strings.Join(nodes, "-"), ".", "-")
}

func withPublicIngress(g *graph.Graph, entrypoint graph.ResourceID, path graph.Path) graph.Path {
	if len(path.Nodes) == 0 || path.Nodes[0] != entrypoint {
		return path
	}
	for _, edge := range g.IncomingEdges(entrypoint) {
		if edge.From != graph.InternetNodeID {
			continue
		}
		return graph.Path{
			Nodes: append([]graph.ResourceID{graph.InternetNodeID}, path.Nodes...),
			Edges: append([]graph.Edge{edge}, path.Edges...),
		}
	}
	return path
}

func normalizeDetectionOptions(opts DetectionOptions) DetectionOptions {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 12
	}
	if opts.MaxPaths <= 0 {
		opts.MaxPaths = 5
	}
	return opts
}

func pathTarget(path graph.Path) graph.ResourceID {
	if len(path.Nodes) == 0 {
		return ""
	}
	return path.Nodes[len(path.Nodes)-1]
}

func isSensitiveNodeKind(kind graph.NodeKind) bool {
	switch kind {
	case graph.NodeDataStore, graph.NodeSecret, graph.NodeKMSKey:
		return true
	default:
		return false
	}
}

func pathHasWorkload(g *graph.Graph, path graph.Path) bool {
	for _, id := range path.Nodes {
		if node := g.Nodes[id]; node != nil && node.Kind == graph.NodeWorkload {
			return true
		}
	}
	return false
}

func confidenceForPath(path graph.Path) model.Confidence {
	confidence := model.ConfidenceHigh
	for _, edge := range path.Edges {
		switch edge.Confidence {
		case graph.ConfidenceLow:
			return model.ConfidenceLow
		case graph.ConfidenceMedium:
			confidence = model.ConfidenceMedium
		}
		if edge.Source == graph.SourceInferred && confidence == model.ConfidenceHigh {
			confidence = model.ConfidenceMedium
		}
	}
	return confidence
}

func publicSensitiveDecision(target *graph.Node, confidence model.Confidence) model.Decision {
	if confidence != model.ConfidenceHigh {
		return model.DecisionWarn
	}
	if target == nil {
		return model.DecisionWarn
	}
	if target.Kind == graph.NodeSecret || target.Kind == graph.NodeKMSKey || target.Environment == "production" || boolValue(target.Values, "sensitive_data") {
		return model.DecisionBlock
	}
	return model.DecisionBlock
}

func publicSensitiveSeverity(decision model.Decision, confidence model.Confidence) model.Severity {
	if decision == model.DecisionBlock && confidence == model.ConfidenceHigh {
		return model.SeverityCritical
	}
	return model.SeverityHigh
}

func publicSensitiveTitle(entrypoint graph.ResourceID, target graph.ResourceID) string {
	return fmt.Sprintf("Public entrypoint %s reaches sensitive asset %s", entrypoint, target)
}

func publicWorkloadTitle(entrypoint graph.ResourceID, target graph.ResourceID) string {
	return fmt.Sprintf("Public entrypoint %s reaches workload %s", entrypoint, target)
}

func stepsFromGraphPath(path graph.Path) []Step {
	steps := make([]Step, 0, len(path.Edges))
	for _, edge := range path.Edges {
		steps = append(steps, Step{
			From:        string(edge.From),
			To:          string(edge.To),
			Action:      string(edge.Type),
			EdgeType:    edge.Type,
			Explanation: edgeExplanation(edge),
		})
	}
	return steps
}

func edgeExplanation(edge graph.Edge) string {
	for _, evidence := range edge.Evidence {
		if evidence.Message != "" {
			return evidence.Message
		}
	}
	if edge.Source != "" {
		return fmt.Sprintf("%s relationship from %s evidence", edge.Type, edge.Source)
	}
	return string(edge.Type)
}

func pathEvidence(target graph.ResourceID, path graph.Path, message string) model.Evidence {
	nodes := make([]string, 0, len(path.Nodes))
	for _, node := range path.Nodes {
		nodes = append(nodes, string(node))
	}
	return model.Evidence{
		Type:     "attack_path.graph_path",
		Resource: string(target),
		Path:     "graph.path",
		Value:    nodes,
		Message:  message,
	}
}

func publicSensitiveMitigations(target *graph.Node) []string {
	mitigations := []string{
		"Remove the public route to the workload or restrict ingress to approved CIDRs.",
		"Segment the workload from sensitive data stores and secrets.",
	}
	if target != nil && target.Kind == graph.NodeSecret {
		mitigations = append(mitigations, "Limit secret access to the smallest required workload role.")
	}
	return mitigations
}

func expectedPublicNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	for _, key := range []string{"expected_public", "public_expected"} {
		if boolValue(node.Values, key) {
			return true
		}
		if strings.EqualFold(node.Tags[key], "true") || strings.EqualFold(node.Tags[key], "yes") {
			return true
		}
	}
	for _, key := range []string{"compensating_controls", "controls"} {
		if expectedPublicControl(node.Values[key]) || expectedPublicControl(node.Tags[key]) {
			return true
		}
	}
	return false
}

func expectedPublicControl(value any) bool {
	switch typed := value.(type) {
	case string:
		for _, part := range strings.Split(typed, ",") {
			if isExpectedPublicControl(strings.TrimSpace(part)) {
				return true
			}
		}
	case []string:
		for _, item := range typed {
			if isExpectedPublicControl(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if isExpectedPublicControl(fmt.Sprint(item)) {
				return true
			}
		}
	}
	return false
}

func isExpectedPublicControl(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "expected_public_tls_edge", "edge_tls", "waf", "cloudfront_oac", "ip_allowlist":
		return true
	default:
		return false
	}
}

func boolValue(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	switch value := values[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
	default:
		return false
	}
}
