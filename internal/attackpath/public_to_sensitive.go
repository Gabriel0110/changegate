package attackpath

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

const attackPathsDocsURL = "https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md"

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
		if authenticatedAPIGatewayEntrypoint(g, entrypoint) {
			continue
		}
		paths = append(paths, detectPublicEKSClusterAdminRisk(g, entrypoint, opts)...)
		radius := g.BlastRadius(entrypoint, graph.BlastRadiusOptions{MaxDepth: opts.MaxDepth, MaxPaths: opts.MaxPaths})
		sensitivePaths := detectSensitivePaths(g, entrypoint, radius)
		if len(sensitivePaths) > 0 {
			paths = append(paths, sensitivePaths...)
			continue
		}
		if node := g.Nodes[entrypoint]; node != nil && isSensitiveNodeKind(node.Kind) {
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
		entrypointNode := g.Nodes[entrypoint]
		out = append(out, AttackPath{
			Type:             TypePublicToSensitiveData,
			Title:            publicSensitiveTitle(entrypointNode, entrypoint, targetNode, target),
			Severity:         publicSensitiveSeverity(decision, confidence),
			Confidence:       confidence,
			ConfidenceReason: publicPathConfidenceReason(confidence),
			Decision:         decision,
			Entrypoint:       string(entrypoint),
			Target:           string(target),
			Steps:            stepsFromGraphPath(fullPath),
			Evidence: []model.Evidence{
				pathEvidence(target, fullPath, "public entrypoint reaches sensitive asset"),
			},
			Mitigations: publicSensitiveMitigations(targetNode),
			References:  []string{attackPathsDocsURL},
			Metadata: map[string]string{
				"graph_path_id":   graphPathID(fullPath),
				"entrypoint_type": nodeType(entrypointNode),
				"target_type":     nodeType(targetNode),
				"attack_pattern":  publicPathPattern(entrypointNode, targetNode),
			},
		})
	}
	return out
}

func detectPublicEKSClusterAdminRisk(g *graph.Graph, entrypoint graph.ResourceID, opts DetectionOptions) []AttackPath {
	node := g.Nodes[entrypoint]
	if node == nil || node.Type != "aws_eks_cluster" {
		return nil
	}
	if expectedPublicNode(node) {
		return nil
	}
	out := make([]AttackPath, 0)
	for _, role := range clusterAdminRoles(g, entrypoint) {
		path, ok := g.Path(entrypoint, role)
		if len(path.Nodes) == 0 {
			path = graph.Path{
				Nodes: []graph.ResourceID{entrypoint, role},
				Edges: []graph.Edge{{
					From:       entrypoint,
					To:         role,
					Type:       graph.EdgeCanAssume,
					Source:     graph.SourceInferred,
					Confidence: graph.ConfidenceMedium,
				}},
			}
		} else if !ok {
			continue
		}
		fullPath := withPublicIngress(g, entrypoint, path)
		confidence := confidenceForPath(fullPath)
		decision, severity := iamDecision(confidence, g.Nodes[role])
		if decision == model.DecisionWarn && opts.DisableWorkloadWarnings {
			continue
		}
		out = append(out, AttackPath{
			Type:             TypePublicToSensitiveData,
			Title:            fmt.Sprintf("Public EKS endpoint %s reaches cluster-admin role %s", entrypoint, role),
			Severity:         severity,
			Confidence:       confidence,
			ConfidenceReason: publicPathConfidenceReason(confidence),
			Decision:         decision,
			Entrypoint:       string(entrypoint),
			Target:           string(role),
			FindingRuleIDs:   []string{RulePublicEKSClusterAdminPath},
			Steps:            stepsFromGraphPath(fullPath),
			Evidence: []model.Evidence{{
				Type:     "attack_path.eks",
				Resource: string(entrypoint),
				Path:     "graph.public_eks_cluster_admin",
				Value:    []string{string(entrypoint), string(role)},
				Message:  "public EKS control-plane endpoint has graph evidence of cluster-admin or privileged role access",
			}},
			Mitigations: []string{
				"Disable public EKS endpoint access or restrict it to approved CIDRs.",
				"Remove cluster-admin role bindings from publicly reachable automation paths.",
			},
			References: []string{attackPathsDocsURL},
			Metadata: map[string]string{
				"graph_path_id":   graphPathID(fullPath),
				"entrypoint_type": nodeType(node),
				"target_type":     nodeType(g.Nodes[role]),
				"attack_pattern":  "public_eks_cluster_admin",
			},
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
			References: []string{attackPathsDocsURL},
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

func publicSensitiveTitle(entrypointNode *graph.Node, entrypoint graph.ResourceID, targetNode *graph.Node, target graph.ResourceID) string {
	switch {
	case entrypointNode != nil && strings.Contains(entrypointNode.Type, "api_gateway") && targetNode != nil && targetNode.Kind == graph.NodeSecret:
		return fmt.Sprintf("Public API Gateway route %s reaches secret %s", entrypoint, target)
	case entrypointNode != nil && strings.Contains(entrypointNode.Type, "api_gateway"):
		return fmt.Sprintf("Public API Gateway route %s reaches sensitive asset %s", entrypoint, target)
	case entrypointNode != nil && entrypointNode.Type == "aws_lambda_function_url" && targetNode != nil && targetNode.Kind == graph.NodeSecret:
		return fmt.Sprintf("Public Lambda Function URL %s reaches secret %s", entrypoint, target)
	case entrypointNode != nil && entrypointNode.Type == "aws_lambda_function_url":
		return fmt.Sprintf("Public Lambda Function URL %s reaches sensitive asset %s", entrypoint, target)
	case targetNode != nil && targetNode.Type == "aws_s3_bucket":
		return fmt.Sprintf("Public workload path from %s reaches S3 bucket %s", entrypoint, target)
	case targetNode != nil && targetNode.Kind == graph.NodeKMSKey:
		return fmt.Sprintf("Public workload path from %s reaches KMS key %s", entrypoint, target)
	case targetNode != nil && targetNode.Kind == graph.NodeSecret:
		return fmt.Sprintf("Public workload path from %s reaches secret %s", entrypoint, target)
	default:
		return fmt.Sprintf("Public entrypoint %s reaches sensitive asset %s", entrypoint, target)
	}
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
			Source:      edge.Source,
			Confidence:  edge.Confidence,
			Explanation: edgeExplanation(edge),
			Evidence:    append([]model.Evidence(nil), edge.Evidence...),
			Metadata:    copyStepMetadata(edge.Metadata),
		})
	}
	return steps
}

func copyStepMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		out[key] = value
	}
	return out
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

func publicPathConfidenceReason(confidence model.Confidence) string {
	switch confidence {
	case model.ConfidenceHigh:
		return "high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence"
	case model.ConfidenceMedium:
		return "medium confidence: the path reaches a sensitive target, but one or more relationships are inferred or partial"
	case model.ConfidenceLow:
		return "low confidence: the path is plausible but depends on low-confidence relationship evidence"
	default:
		return "path confidence is based on available graph evidence"
	}
}

func publicPathPattern(entrypoint *graph.Node, target *graph.Node) string {
	switch {
	case entrypoint != nil && strings.Contains(entrypoint.Type, "api_gateway"):
		return "public_api_gateway_to_sensitive_access"
	case entrypoint != nil && entrypoint.Type == "aws_lambda_function_url":
		return "public_lambda_url_to_sensitive_access"
	case target != nil && target.Kind == graph.NodeSecret:
		return "public_workload_to_secret_access"
	case target != nil && target.Kind == graph.NodeKMSKey:
		return "public_workload_to_kms_access"
	case target != nil && target.Type == "aws_s3_bucket":
		return "public_workload_to_s3_access"
	default:
		return "public_workload_to_sensitive_asset"
	}
}

func clusterAdminRoles(g *graph.Graph, cluster graph.ResourceID) []graph.ResourceID {
	seen := make(map[graph.ResourceID]bool)
	for _, edge := range g.OutgoingEdges(cluster) {
		if edge.Type == graph.EdgeCanAssume || edge.Type == graph.EdgeAttachedTo || edge.Type == graph.EdgeGrantsPermission {
			if node := g.Nodes[edge.To]; node != nil && node.Kind == graph.NodePrincipal && privilegedOrSensitivePrincipal(g, edge.To) {
				seen[edge.To] = true
			}
		}
	}
	for _, id := range sortedNodesByKind(g, graph.NodePrincipal) {
		node := g.Nodes[id]
		if node == nil {
			continue
		}
		if !principalReferencesCluster(node, cluster) {
			continue
		}
		lower := strings.ToLower(string(id) + " " + node.Address + " " + node.Name + " " + asString(node.Values["kubernetes_groups"]) + " " + asString(node.Values["groups"]))
		if strings.Contains(lower, "system:masters") || strings.Contains(lower, "cluster-admin") || strings.Contains(lower, "cluster_admin") {
			seen[id] = true
		}
	}
	out := make([]graph.ResourceID, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.SliceStable(out, func(i int, j int) bool { return out[i] < out[j] })
	return out
}

func principalReferencesCluster(node *graph.Node, cluster graph.ResourceID) bool {
	if node == nil {
		return false
	}
	clusterText := strings.ToLower(string(cluster))
	for _, key := range []string{"cluster", "cluster_name", "eks_cluster", "eks_cluster_arn"} {
		value := strings.ToLower(asString(node.Values[key]))
		if value != "" && (strings.Contains(clusterText, value) || strings.Contains(value, clusterText)) {
			return true
		}
	}
	return false
}

func nodeType(node *graph.Node) string {
	if node == nil {
		return ""
	}
	return node.Type
}

func expectedPublicNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	for _, key := range []string{"service", "tier", "exposure", "visibility"} {
		value := strings.ToLower(tagValue(node.Tags, key) + " " + asString(node.Values[key]))
		if strings.Contains(value, "public-web") || value == "edge" || value == "public" || value == "internet" {
			return true
		}
	}
	for _, key := range []string{"expected_public", "public_expected"} {
		if boolValue(node.Values, key) {
			return true
		}
		value := tagValue(node.Tags, key)
		if strings.EqualFold(value, "true") || strings.EqualFold(value, "yes") {
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

func authenticatedAPIGatewayEntrypoint(g *graph.Graph, entrypoint graph.ResourceID) bool {
	node := g.Nodes[entrypoint]
	if node == nil || (node.Type != "aws_apigatewayv2_api" && node.Type != "aws_api_gateway_rest_api") {
		return false
	}
	routeEvidence := 0
	for _, candidate := range g.Nodes {
		if candidate == nil {
			continue
		}
		switch candidate.Type {
		case "aws_apigatewayv2_route":
			if !referencesAPI(candidate, node, "api_id") {
				continue
			}
			routeEvidence++
			if apiGatewayV2RouteAnonymous(candidate) {
				return false
			}
		case "aws_api_gateway_method":
			if !referencesAPI(candidate, node, "rest_api_id") {
				continue
			}
			routeEvidence++
			if apiGatewayMethodAnonymous(candidate) {
				return false
			}
		}
	}
	return routeEvidence > 0
}

func referencesAPI(candidate *graph.Node, api *graph.Node, key string) bool {
	value := asString(candidate.Values[key])
	if value == "" {
		return false
	}
	return value == string(api.ID) ||
		value == api.Address ||
		value == api.Name ||
		value == asString(api.Values["id"]) ||
		value == asString(api.Values["api_id"]) ||
		value == asString(api.Values["rest_api_id"])
}

func apiGatewayV2RouteAnonymous(node *graph.Node) bool {
	auth := strings.ToLower(strings.TrimSpace(asString(node.Values["authorization_type"])))
	return auth == "" || auth == "none"
}

func apiGatewayMethodAnonymous(node *graph.Node) bool {
	auth := strings.ToLower(strings.TrimSpace(asString(node.Values["authorization"])))
	return auth == "" || auth == "none"
}

func tagValue(tags map[string]string, key string) string {
	for candidate, value := range tags {
		if strings.EqualFold(candidate, key) {
			return value
		}
	}
	return ""
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
