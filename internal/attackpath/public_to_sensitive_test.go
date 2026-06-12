package attackpath

import (
	"testing"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

func TestDetectPublicToSensitiveAllowsExpectedPublicWeb(t *testing.T) {
	t.Parallel()
	g := graphForPublicWeb()

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 0 {
		t.Fatalf("expected no attack paths for expected public web app, got %#v", paths)
	}
}

func TestDetectPublicToSensitiveBlocksPublicAdminToRDS(t *testing.T) {
	t.Parallel()
	g := graphForPublicAdminToSensitive("aws_db_instance.customer", graph.NodeDataStore)
	g.Nodes["aws_db_instance.customer"].Environment = "production"

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 1 {
		t.Fatalf("paths len = %d, want 1: %#v", len(paths), paths)
	}
	path := paths[0]
	if path.Type != TypePublicToSensitiveData {
		t.Fatalf("type = %q, want %q", path.Type, TypePublicToSensitiveData)
	}
	if path.Decision != model.DecisionBlock {
		t.Fatalf("decision = %q, want block", path.Decision)
	}
	if path.Severity != model.SeverityCritical {
		t.Fatalf("severity = %q, want critical", path.Severity)
	}
	if path.Confidence != model.ConfidenceHigh {
		t.Fatalf("confidence = %q, want high", path.Confidence)
	}
	if path.Entrypoint != "aws_lb.admin" || path.Target != "aws_db_instance.customer" {
		t.Fatalf("unexpected endpoints: %#v", path)
	}
	if len(path.Steps) != 3 {
		t.Fatalf("steps len = %d, want 3: %#v", len(path.Steps), path.Steps)
	}
}

func TestDetectPublicToSensitiveBlocksPublicWorkloadToSecret(t *testing.T) {
	t.Parallel()
	g := graphForPublicAdminToSensitive("aws_secretsmanager_secret.customer", graph.NodeSecret)

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 1 {
		t.Fatalf("paths len = %d, want 1: %#v", len(paths), paths)
	}
	if paths[0].Decision != model.DecisionBlock {
		t.Fatalf("decision = %q, want block", paths[0].Decision)
	}
	if paths[0].Target != "aws_secretsmanager_secret.customer" {
		t.Fatalf("target = %q, want secret", paths[0].Target)
	}
}

func TestDetectPublicToSensitiveBlocksLambdaURLToSecret(t *testing.T) {
	t.Parallel()
	g := &graph.Graph{
		Nodes: map[graph.ResourceID]*graph.Node{
			graph.InternetNodeID: {
				ID:        graph.InternetNodeID,
				Address:   string(graph.InternetNodeID),
				Type:      "internet",
				Kind:      graph.NodePublicEntrypoint,
				Name:      "internet",
				Synthetic: true,
			},
			"aws_lambda_function_url.public_handler": {
				ID:      "aws_lambda_function_url.public_handler",
				Address: "aws_lambda_function_url.public_handler",
				Type:    "aws_lambda_function_url",
				Kind:    graph.NodePublicEntrypoint,
				Name:    "public_handler",
				Changed: true,
			},
			"aws_lambda_function.public_handler": {
				ID:      "aws_lambda_function.public_handler",
				Address: "aws_lambda_function.public_handler",
				Type:    "aws_lambda_function",
				Kind:    graph.NodeWorkload,
				Name:    "public_handler",
			},
			"aws_secretsmanager_secret.customer": {
				ID:          "aws_secretsmanager_secret.customer",
				Address:     "aws_secretsmanager_secret.customer",
				Type:        "aws_secretsmanager_secret",
				Kind:        graph.NodeSecret,
				Name:        "customer",
				Environment: "production",
			},
		},
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, "aws_lambda_function_url.public_handler", graph.EdgeRoutesTo),
			edge("aws_lambda_function_url.public_handler", "aws_lambda_function.public_handler", graph.EdgeInvokes),
			edge("aws_lambda_function.public_handler", "aws_secretsmanager_secret.customer", graph.EdgeReadsSecret),
		},
	}

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 1 {
		t.Fatalf("paths len = %d, want 1: %#v", len(paths), paths)
	}
	path := paths[0]
	if path.Decision != model.DecisionBlock {
		t.Fatalf("decision = %q, want block", path.Decision)
	}
	if path.Entrypoint != "aws_lambda_function_url.public_handler" || path.Target != "aws_secretsmanager_secret.customer" {
		t.Fatalf("unexpected endpoints: %#v", path)
	}
	if path.Title != "Public Lambda Function URL aws_lambda_function_url.public_handler reaches secret aws_secretsmanager_secret.customer" {
		t.Fatalf("title = %q", path.Title)
	}
	if path.Metadata["attack_pattern"] != "public_lambda_url_to_sensitive_access" {
		t.Fatalf("attack pattern = %#v", path.Metadata)
	}
	if len(path.Steps) != 3 || path.Steps[1].EdgeType != graph.EdgeInvokes || path.Steps[2].EdgeType != graph.EdgeReadsSecret {
		t.Fatalf("unexpected path steps: %#v", path.Steps)
	}
}

func TestDetectPublicToSensitiveBlocksAPIGatewayToSecret(t *testing.T) {
	t.Parallel()
	g := &graph.Graph{
		Nodes: map[graph.ResourceID]*graph.Node{
			graph.InternetNodeID: internetNode(),
			"aws_api_gateway_stage.public": {
				ID:      "aws_api_gateway_stage.public",
				Address: "aws_api_gateway_stage.public",
				Type:    "aws_api_gateway_stage",
				Kind:    graph.NodePublicEntrypoint,
				Name:    "public",
			},
			"aws_lambda_function.admin": workloadNode("aws_lambda_function.admin", "aws_lambda_function"),
			"aws_secretsmanager_secret.customer": {
				ID:          "aws_secretsmanager_secret.customer",
				Address:     "aws_secretsmanager_secret.customer",
				Type:        "aws_secretsmanager_secret",
				Kind:        graph.NodeSecret,
				Name:        "customer",
				Environment: "production",
			},
		},
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, "aws_api_gateway_stage.public", graph.EdgeRoutesTo),
			edge("aws_api_gateway_stage.public", "aws_lambda_function.admin", graph.EdgeInvokes),
			edge("aws_lambda_function.admin", "aws_secretsmanager_secret.customer", graph.EdgeReadsSecret),
		},
	}

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 1 {
		t.Fatalf("paths len = %d, want 1: %#v", len(paths), paths)
	}
	if paths[0].Title != "Public API Gateway route aws_api_gateway_stage.public reaches secret aws_secretsmanager_secret.customer" {
		t.Fatalf("title = %q", paths[0].Title)
	}
	if paths[0].Decision != model.DecisionBlock || paths[0].Metadata["attack_pattern"] != "public_api_gateway_to_sensitive_access" {
		t.Fatalf("unexpected path: %#v", paths[0])
	}
}

func TestDetectPublicToSensitiveSkipsAuthenticatedAPIGatewayRoute(t *testing.T) {
	t.Parallel()
	g := &graph.Graph{
		Nodes: map[graph.ResourceID]*graph.Node{
			graph.InternetNodeID: internetNode(),
			"aws_apigatewayv2_api.authenticated": {
				ID:      "aws_apigatewayv2_api.authenticated",
				Address: "aws_apigatewayv2_api.authenticated",
				Type:    "aws_apigatewayv2_api",
				Kind:    graph.NodePublicEntrypoint,
				Name:    "authenticated",
				Values:  map[string]any{"id": "api-authenticated"},
			},
			"aws_apigatewayv2_route.authenticated": {
				ID:      "aws_apigatewayv2_route.authenticated",
				Address: "aws_apigatewayv2_route.authenticated",
				Type:    "aws_apigatewayv2_route",
				Kind:    graph.NodeUnknown,
				Name:    "authenticated",
				Values:  map[string]any{"api_id": "api-authenticated", "authorization_type": "JWT"},
			},
			"aws_lambda_function.authenticated": workloadNode("aws_lambda_function.authenticated", "aws_lambda_function"),
			"aws_secretsmanager_secret.customer": {
				ID:          "aws_secretsmanager_secret.customer",
				Address:     "aws_secretsmanager_secret.customer",
				Type:        "aws_secretsmanager_secret",
				Kind:        graph.NodeSecret,
				Name:        "customer",
				Environment: "production",
			},
		},
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, "aws_apigatewayv2_api.authenticated", graph.EdgeRoutesTo),
			edge("aws_apigatewayv2_api.authenticated", "aws_lambda_function.authenticated", graph.EdgeInvokes),
			edge("aws_lambda_function.authenticated", "aws_secretsmanager_secret.customer", graph.EdgeReadsSecret),
		},
	}

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 0 {
		t.Fatalf("authenticated API route should not produce attack paths: %#v", paths)
	}
}

func TestDetectPublicEKSClusterAdminRiskBlocks(t *testing.T) {
	t.Parallel()
	g := &graph.Graph{
		Nodes: map[graph.ResourceID]*graph.Node{
			graph.InternetNodeID: internetNode(),
			"aws_eks_cluster.prod": {
				ID:          "aws_eks_cluster.prod",
				Address:     "aws_eks_cluster.prod",
				Type:        "aws_eks_cluster",
				Kind:        graph.NodePublicEntrypoint,
				Name:        "prod",
				Environment: "production",
				Values:      map[string]any{"endpoint_public_access": true},
			},
			"aws_iam_role.cluster_admin": {
				ID:          "aws_iam_role.cluster_admin",
				Address:     "aws_iam_role.cluster_admin",
				Type:        "aws_iam_role",
				Kind:        graph.NodePrincipal,
				Name:        "cluster-admin",
				Environment: "production",
				Values:      map[string]any{"kubernetes_groups": []string{"system:masters"}},
			},
		},
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, "aws_eks_cluster.prod", graph.EdgeHasPublicAccess),
			edge("aws_eks_cluster.prod", "aws_iam_role.cluster_admin", graph.EdgeCanAssume),
		},
	}

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	var eksPath *AttackPath
	for i := range paths {
		if paths[i].Metadata["attack_pattern"] == "public_eks_cluster_admin" {
			eksPath = &paths[i]
			break
		}
	}
	if eksPath == nil {
		t.Fatalf("missing EKS admin path: %#v", paths)
	}
	if eksPath.Decision != model.DecisionBlock || eksPath.FindingRuleIDs[0] != RulePublicEKSClusterAdminPath {
		t.Fatalf("unexpected EKS path: %#v", eksPath)
	}
}

func TestDetectPublicToSensitiveWarnsWhenSensitivePathConfidenceIsMedium(t *testing.T) {
	t.Parallel()
	g := graphForPublicAdminToSensitive("aws_db_instance.customer", graph.NodeDataStore)
	g.Edges[2].Confidence = graph.ConfidenceMedium

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 1 {
		t.Fatalf("paths len = %d, want 1: %#v", len(paths), paths)
	}
	if paths[0].Decision != model.DecisionWarn {
		t.Fatalf("decision = %q, want warn", paths[0].Decision)
	}
	if paths[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("confidence = %q, want medium", paths[0].Confidence)
	}
}

func TestDetectPublicToSensitiveSurfacesMixedCloudContextSource(t *testing.T) {
	t.Parallel()
	g := graphForPublicAdminToSensitive("aws_db_instance.customer", graph.NodeDataStore)
	g.Nodes["aws_db_instance.customer"].Environment = "production"
	g.Edges[2].Source = graph.SourceMixed
	g.Edges[2].Confidence = graph.ConfidenceHigh
	g.Edges[2].Metadata = map[string]string{"sources": "cloud_context,plan"}

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 1 {
		t.Fatalf("paths len = %d, want 1: %#v", len(paths), paths)
	}
	if paths[0].Source != graph.SourceMixed {
		t.Fatalf("source = %q, want mixed", paths[0].Source)
	}
	if paths[0].Confidence != model.ConfidenceHigh || paths[0].Decision != model.DecisionBlock {
		t.Fatalf("unexpected decision context: confidence=%s decision=%s", paths[0].Confidence, paths[0].Decision)
	}
	if paths[0].Steps[2].Metadata["sources"] != "cloud_context,plan" {
		t.Fatalf("step metadata missing merged sources: %#v", paths[0].Steps[2].Metadata)
	}
}

func TestDetectPublicToSensitiveWarnsOnPublicWorkloadWithoutSensitiveContext(t *testing.T) {
	t.Parallel()
	g := graphForPublicWorkload(false)

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	if len(paths) != 1 {
		t.Fatalf("paths len = %d, want 1: %#v", len(paths), paths)
	}
	if paths[0].Decision != model.DecisionWarn {
		t.Fatalf("decision = %q, want warn", paths[0].Decision)
	}
	if paths[0].Target != "aws_ecs_service.web" {
		t.Fatalf("target = %q, want workload", paths[0].Target)
	}
}

func TestDetectPublicToSensitiveSkipsDirectPublicDatastoreWorkloadWarning(t *testing.T) {
	t.Parallel()
	g := graphForPublicWorkload(false)
	g.Nodes["aws_db_instance.customer"] = &graph.Node{
		ID:      "aws_db_instance.customer",
		Address: "aws_db_instance.customer",
		Type:    "aws_db_instance",
		Kind:    graph.NodeDataStore,
		Name:    "customer",
		Values:  map[string]any{"publicly_accessible": true},
	}
	g.Edges = append(g.Edges,
		edge(graph.InternetNodeID, "aws_db_instance.customer", graph.EdgeHasPublicAccess),
		edge("aws_db_instance.customer", "aws_ecs_service.web", graph.EdgeAllowsEgress),
	)

	paths := DetectPublicToSensitive(g, DetectionOptions{})
	for _, path := range paths {
		if path.Entrypoint == "aws_db_instance.customer" {
			t.Fatalf("direct public datastore should not produce workload warning attack path: %#v", path)
		}
	}
}

func graphForPublicAdminToSensitive(target graph.ResourceID, targetKind graph.NodeKind) *graph.Graph {
	nodes := basePublicNodes("aws_ecs_service.admin")
	nodes[target] = &graph.Node{
		ID:          target,
		Address:     string(target),
		Type:        targetType(targetKind),
		Kind:        targetKind,
		Name:        "customer",
		Environment: "production",
		Values:      map[string]any{"sensitive_data": true},
	}
	return &graph.Graph{
		Nodes: nodes,
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, "aws_lb.admin", graph.EdgeRoutesTo),
			edge("aws_lb.admin", "aws_ecs_service.admin", graph.EdgeRoutesTo),
			edge("aws_ecs_service.admin", target, graph.EdgeRoutesTo),
		},
	}
}

func graphForPublicWeb() *graph.Graph {
	return graphForPublicWorkload(true)
}

func graphForPublicWorkload(expectedPublic bool) *graph.Graph {
	nodes := basePublicNodes("aws_ecs_service.web")
	if expectedPublic {
		nodes["aws_lb.admin"].Values = map[string]any{"compensating_controls": []string{"expected_public_tls_edge"}}
	}
	return &graph.Graph{
		Nodes: nodes,
		Edges: []graph.Edge{
			edge(graph.InternetNodeID, "aws_lb.admin", graph.EdgeRoutesTo),
			edge("aws_lb.admin", "aws_ecs_service.web", graph.EdgeRoutesTo),
		},
	}
}

func basePublicNodes(workload graph.ResourceID) map[graph.ResourceID]*graph.Node {
	return map[graph.ResourceID]*graph.Node{
		graph.InternetNodeID: internetNode(),
		"aws_lb.admin": {
			ID:      "aws_lb.admin",
			Address: "aws_lb.admin",
			Type:    "aws_lb",
			Kind:    graph.NodePublicEntrypoint,
			Name:    "admin",
		},
		workload: {
			ID:      workload,
			Address: string(workload),
			Type:    "aws_ecs_service",
			Kind:    graph.NodeWorkload,
			Name:    "service",
		},
	}
}

func internetNode() *graph.Node {
	return &graph.Node{
		ID:        graph.InternetNodeID,
		Address:   string(graph.InternetNodeID),
		Type:      "internet",
		Kind:      graph.NodePublicEntrypoint,
		Name:      "internet",
		Synthetic: true,
	}
}

func edge(from graph.ResourceID, to graph.ResourceID, edgeType graph.EdgeType) graph.Edge {
	return graph.Edge{
		From:       from,
		To:         to,
		Type:       edgeType,
		Source:     graph.SourcePlan,
		Confidence: graph.ConfidenceHigh,
	}
}

func targetType(kind graph.NodeKind) string {
	switch kind {
	case graph.NodeSecret:
		return "aws_secretsmanager_secret"
	case graph.NodeKMSKey:
		return "aws_kms_key"
	default:
		return "aws_db_instance"
	}
}
