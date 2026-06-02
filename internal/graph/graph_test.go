package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestGraphALBToECSPathAndExposure(t *testing.T) {
	t.Parallel()

	g := Build(testPlan())
	if !g.IsInternetExposed("aws_ecs_service.admin") {
		t.Fatalf("ECS service should be internet exposed through ALB path")
	}
	if !g.CanReach(InternetNodeID, "aws_ecs_service.admin") {
		t.Fatalf("internet should reach ECS service")
	}

	path, ok := g.Path("aws_lb.admin", "aws_ecs_service.admin")
	if !ok {
		t.Fatalf("path not found")
	}
	got := stringifyPath(path)
	want := "aws_lb.admin -> aws_lb_listener.admin -> aws_lb_target_group.admin -> aws_ecs_service.admin"
	if got != want {
		t.Fatalf("path = %s, want %s", got, want)
	}

	lines, ok := g.ExplainConnection(InternetNodeID, "aws_ecs_service.admin")
	if !ok {
		t.Fatalf("explain path not found")
	}
	if len(lines) == 0 {
		t.Fatalf("expected explanation evidence")
	}

	exposure := g.Exposure("aws_ecs_service.admin")
	if !exposure.Exposed {
		t.Fatalf("expected exposure result to report exposed ECS service")
	}
	if len(exposure.Entrypoints) == 0 || exposure.Entrypoints[0].ID != "aws_lb.admin" {
		t.Fatalf("entrypoints = %#v, want aws_lb.admin first", exposure.Entrypoints)
	}
	if got := g.PublicEntrypoints(); !containsResourceID(got, "aws_lb.admin") || !containsResourceID(got, "aws_cloudfront_distribution.cdn") || !containsResourceID(got, "aws_apigatewayv2_api.public") || !containsResourceID(got, "aws_lambda_function_url.worker") {
		t.Fatalf("public entrypoints = %#v, missing expected public entrypoint", got)
	}
}

func TestGraphSGToInstanceAndRDS(t *testing.T) {
	t.Parallel()

	g := Build(testPlan())
	if !g.CanReach(InternetNodeID, "aws_instance.web") {
		t.Fatalf("internet should reach instance through public SG")
	}
	if !g.CanReach(InternetNodeID, "aws_db_instance.customer") {
		t.Fatalf("internet should reach public RDS")
	}
	if node := g.Nodes["aws_instance.web"]; node.Environment != "production" {
		t.Fatalf("instance environment = %q, want production", node.Environment)
	}
}

func TestGraphLambdaAndIAMRelationships(t *testing.T) {
	t.Parallel()

	g := Build(testPlan())
	if !g.CanAssumeRole("aws_lambda_function.worker", "aws_iam_role.worker") {
		t.Fatalf("lambda should assume execution role")
	}
	if !g.CanPassRole("aws_iam_role.worker", "aws_iam_role.deployer") {
		t.Fatalf("role should be able to pass role from policy")
	}
	if !g.HasSensitiveDataAccess("aws_iam_role.worker") {
		t.Fatalf("role should have sensitive data access through policy")
	}
	if !g.hasEdge("aws_iam_role.worker", "aws_secretsmanager_secret.customer", EdgeReadsSecret) {
		t.Fatalf("role should have explicit secret-read edge")
	}
}

func TestGraphPublicS3(t *testing.T) {
	t.Parallel()

	g := Build(testPlan())
	if !g.IsInternetExposed("aws_s3_bucket.logs") {
		t.Fatalf("bucket should be internet exposed through bucket policy")
	}
	if !g.HasSensitiveDataAccess(InternetNodeID) {
		t.Fatalf("internet should have sensitive data access to public bucket")
	}
}

func TestGraphV2ClassifiesNodesAndEdgeFamilies(t *testing.T) {
	t.Parallel()

	g := Build(testPlan())
	tests := []struct {
		resource ResourceID
		kind     NodeKind
	}{
		{resource: "aws_lb.admin", kind: NodePublicEntrypoint},
		{resource: "aws_ecs_service.admin", kind: NodeWorkload},
		{resource: "aws_db_instance.customer", kind: NodeDataStore},
		{resource: "aws_secretsmanager_secret.customer", kind: NodeSecret},
		{resource: "aws_kms_key.data", kind: NodeKMSKey},
		{resource: "aws_iam_role.worker", kind: NodePrincipal},
		{resource: "aws_iam_policy.worker", kind: NodePolicy},
		{resource: "aws_security_group.public", kind: NodeNetworkBoundary},
	}
	for _, tt := range tests {
		node := g.Nodes[tt.resource]
		if node == nil {
			t.Fatalf("missing node %s", tt.resource)
		}
		if node.Kind != tt.kind {
			t.Fatalf("%s kind = %s, want %s", tt.resource, node.Kind, tt.kind)
		}
	}
	for _, edge := range []struct {
		from ResourceID
		to   ResourceID
		typ  EdgeType
	}{
		{from: "aws_db_instance.customer", to: "aws_kms_key.data", typ: EdgeEncryptsWith},
		{from: "aws_secretsmanager_secret.customer", to: "aws_kms_key.data", typ: EdgeEncryptsWith},
		{from: "aws_iam_policy.worker", to: "aws_iam_role.worker", typ: EdgeGrantsPermission},
		{from: "aws_s3_bucket_public_access_block.logs", to: "aws_s3_bucket.logs", typ: EdgeProtects},
		{from: InternetNodeID, to: "aws_cloudfront_distribution.cdn", typ: EdgeRoutesTo},
		{from: InternetNodeID, to: "aws_apigatewayv2_api.public", typ: EdgeRoutesTo},
		{from: InternetNodeID, to: "aws_lambda_function_url.worker", typ: EdgeRoutesTo},
		{from: "aws_lambda_function_url.worker", to: "aws_lambda_function.worker", typ: EdgeInvokes},
		{from: "aws_apigatewayv2_api.public", to: "aws_apigatewayv2_integration.worker", typ: EdgeRoutesTo},
		{from: "aws_apigatewayv2_integration.worker", to: "aws_lambda_function.worker", typ: EdgeInvokes},
		{from: "aws_lambda_function.worker", to: "aws_secretsmanager_secret.customer", typ: EdgeReadsSecret},
		{from: "aws_lambda_function.worker", to: "aws_kms_key.data", typ: EdgeEncryptsWith},
	} {
		if !g.hasEdge(edge.from, edge.to, edge.typ) {
			t.Fatalf("missing edge %s --%s--> %s", edge.from, edge.typ, edge.to)
		}
	}
}

func TestBuildWithOptionsClassifiesSensitiveAssetsConservatively(t *testing.T) {
	t.Parallel()

	plan := &model.Plan{
		Resources: []model.Resource{
			resource("custom_service.cardholder_ledger", "custom_service", "cardholder_ledger", map[string]any{
				"tags": map[string]any{"env": "prod"},
			}),
			resource("custom_bucket.restricted", "custom_bucket", "restricted", map[string]any{
				"tags": map[string]any{"classification": "restricted"},
			}),
			resource("custom_vault.payments", "custom_vault", "payments", map[string]any{
				"tags": map[string]any{"env": "prod"},
			}),
			resource("custom_report.regulated", "custom_report", "regulated", map[string]any{
				"tags": map[string]any{"data_domain": "regulated"},
			}),
			resource("aws_backup_vault.customer", "aws_backup_vault", "customer", map[string]any{
				"tags": map[string]any{"env": "prod"},
			}),
		},
	}
	g := BuildWithOptions(plan, BuildOptions{SensitiveAssets: model.SensitiveAssetPolicy{
		ResourceTypes: []string{"aws_backup_vault"},
		NameContains:  []string{"cardholder"},
		Tags:          map[string]string{"data_domain": "regulated"},
	}})

	if kind := g.Nodes["custom_service.cardholder_ledger"].Kind; kind != NodeDataStore {
		t.Fatalf("name selector kind = %s, want data_store", kind)
	}
	if kind := g.Nodes["custom_bucket.restricted"].Kind; kind != NodeDataStore {
		t.Fatalf("default sensitive tag kind = %s, want data_store", kind)
	}
	if kind := g.Nodes["aws_backup_vault.customer"].Kind; kind != NodeDataStore {
		t.Fatalf("type selector kind = %s, want data_store", kind)
	}
	if kind := g.Nodes["custom_report.regulated"].Kind; kind != NodeDataStore {
		t.Fatalf("tag selector kind = %s, want data_store", kind)
	}
	if kind := g.Nodes["custom_vault.payments"].Kind; kind != NodeUnknown {
		t.Fatalf("env=prod alone kind = %s, want unknown", kind)
	}
}

func TestGraphV2PathsBlastRadiusAndBoundaryCrossings(t *testing.T) {
	t.Parallel()

	g := Build(testPlan())
	paths := g.Paths("aws_lb.admin", "aws_db_instance.customer", PathOptions{MaxDepth: 8, MaxPaths: 2, AllowedEdges: reachabilityEdges()})
	if len(paths) == 0 {
		t.Fatalf("expected path from public ALB to customer DB")
	}
	if got := stringifyPath(paths[0]); got != "aws_lb.admin -> aws_lb_listener.admin -> aws_lb_target_group.admin -> aws_ecs_service.admin -> aws_security_group.public -> aws_db_instance.customer" {
		t.Fatalf("path = %s", got)
	}
	if shallow := g.Paths("aws_lb.admin", "aws_db_instance.customer", PathOptions{MaxDepth: 2, MaxPaths: 2, AllowedEdges: reachabilityEdges()}); len(shallow) != 0 {
		t.Fatalf("shallow paths = %d, want 0", len(shallow))
	}

	radius := g.BlastRadius("aws_lb.admin", BlastRadiusOptions{MaxDepth: 8, MaxPaths: 10})
	if !containsResourceID(radius.ReachableWorkloads, "aws_ecs_service.admin") {
		t.Fatalf("reachable workloads = %#v, missing ECS service", radius.ReachableWorkloads)
	}
	if !containsResourceID(radius.SensitiveAssets, "aws_db_instance.customer") {
		t.Fatalf("sensitive assets = %#v, missing DB", radius.SensitiveAssets)
	}

	crossings := g.ChangedBoundaryCrossings()
	if len(crossings) == 0 {
		t.Fatalf("expected changed public-to-sensitive boundary crossing")
	}
	if got := stringifyPath(crossings[0]); !strings.Contains(got, "aws_db_instance.customer") {
		t.Fatalf("boundary crossing path = %s, want sensitive DB", got)
	}
}

func TestGraphDeterministicAndUnknownTolerant(t *testing.T) {
	t.Parallel()

	first := Build(testPlan())
	second := Build(testPlan())

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("graph output is not deterministic")
	}

	unknownPlan := &model.Plan{
		Resources: []model.Resource{{
			Address: "aws_instance.unknown",
			Type:    "aws_instance",
			Name:    "unknown",
			Values: map[string]any{
				"subnet_id": nil,
			},
		}},
	}
	if graph := Build(unknownPlan); graph.Nodes["aws_instance.unknown"] == nil {
		t.Fatalf("unknown values should not prevent node creation")
	}
}

func TestGraphV2GoldenSummary(t *testing.T) {
	t.Parallel()

	g := Build(testPlan())
	radius := g.BlastRadius("aws_lb.admin", BlastRadiusOptions{MaxDepth: 8, MaxPaths: 3})
	got := graphV2GoldenSummary{
		PublicEntrypoints:        g.PublicEntrypoints(),
		SensitiveAssets:          g.SensitiveAssets(),
		ChangedBoundaryCrossings: stringifyPaths(g.ChangedBoundaryCrossings()),
		BlastRadius: graphV2GoldenBlastRadius{
			Resource:           radius.Resource,
			Exposed:            radius.Exposure.Exposed,
			ReachableWorkloads: radius.ReachableWorkloads,
			SensitiveAssets:    radius.SensitiveAssets,
			Paths:              stringifyPaths(radius.Paths),
		},
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(got); err != nil {
		t.Fatalf("marshal graph v2 summary: %v", err)
	}
	assertGraphGolden(t, "testdata/golden/graph-v2-summary.json", body.String())
}

func BenchmarkGraphV2PathSearchLargeGraph(b *testing.B) {
	g := &Graph{Nodes: make(map[ResourceID]*Node)}
	const nodeCount = 1000
	for i := 0; i < nodeCount; i++ {
		id := ResourceID(fmt.Sprintf("aws_instance.workload_%04d", i))
		g.Nodes[id] = &Node{
			ID:      id,
			Address: string(id),
			Type:    "aws_instance",
			Kind:    NodeWorkload,
			Name:    fmt.Sprintf("workload_%04d", i),
		}
		if i > 0 {
			from := ResourceID(fmt.Sprintf("aws_instance.workload_%04d", i-1))
			g.addEdge(from, id, EdgeRoutesTo, nil, nil)
		}
	}
	g.sort()

	from := ResourceID("aws_instance.workload_0000")
	to := ResourceID("aws_instance.workload_0999")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		paths := g.Paths(from, to, PathOptions{MaxDepth: nodeCount, MaxPaths: 1, AllowedEdges: []EdgeType{EdgeRoutesTo}})
		if len(paths) != 1 {
			b.Fatalf("paths = %d, want 1", len(paths))
		}
	}
}

func TestGraphEnablesContextualFindings(t *testing.T) {
	t.Parallel()

	g := Build(testPlan())
	contextual := []struct {
		name string
		ok   bool
	}{
		{name: "internet_to_admin_service", ok: g.CanReach(InternetNodeID, "aws_ecs_service.admin")},
		{name: "admin_service_to_customer_database", ok: g.CanReach("aws_ecs_service.admin", "aws_db_instance.customer")},
		{name: "lambda_role_sensitive_data", ok: g.HasSensitiveDataAccess("aws_iam_role.worker")},
	}
	for _, item := range contextual {
		if !item.ok {
			t.Fatalf("contextual graph signal %s was false", item.name)
		}
	}
}

func stringifyPath(path Path) string {
	parts := make([]string, 0, len(path.Nodes))
	for _, node := range path.Nodes {
		parts = append(parts, string(node))
	}
	return strings.Join(parts, " -> ")
}

func stringifyPaths(paths []Path) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, stringifyPath(path))
	}
	sort.Strings(out)
	return out
}

func containsResourceID(values []ResourceID, want ResourceID) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertGraphGolden(t *testing.T, path string, got string) {
	t.Helper()

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\ngot:\n%s", path, err, got)
	}
	wantText := strings.ReplaceAll(string(want), "\r\n", "\n")
	gotText := strings.ReplaceAll(got, "\r\n", "\n")
	if wantText != gotText {
		t.Fatalf("golden mismatch for %s\nwant:\n%s\ngot:\n%s", path, wantText, gotText)
	}
}

type graphV2GoldenSummary struct {
	PublicEntrypoints        []ResourceID             `json:"public_entrypoints"`
	SensitiveAssets          []ResourceID             `json:"sensitive_assets"`
	ChangedBoundaryCrossings []string                 `json:"changed_boundary_crossings"`
	BlastRadius              graphV2GoldenBlastRadius `json:"blast_radius"`
}

type graphV2GoldenBlastRadius struct {
	Resource           ResourceID   `json:"resource"`
	Exposed            bool         `json:"exposed"`
	ReachableWorkloads []ResourceID `json:"reachable_workloads"`
	SensitiveAssets    []ResourceID `json:"sensitive_assets"`
	Paths              []string     `json:"paths"`
}

func testPlan() *model.Plan {
	return &model.Plan{
		Resources: []model.Resource{
			resource("aws_security_group.public", "aws_security_group", "public", map[string]any{
				"id": "sg-public",
				"ingress": []any{map[string]any{
					"cidr_blocks": []any{"0.0.0.0/0"},
					"from_port":   443,
					"to_port":     443,
				}},
				"tags": map[string]any{"env": "prod"},
			}),
			resource("aws_lb.admin", "aws_lb", "admin", map[string]any{
				"arn":                "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/admin/1",
				"scheme":             "internet-facing",
				"load_balancer_type": "application",
				"security_groups":    []any{"sg-public"},
				"tags":               map[string]any{"env": "prod"},
			}),
			resource("aws_lb_listener.admin", "aws_lb_listener", "admin", map[string]any{
				"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/admin/1",
				"default_action": []any{map[string]any{
					"type":             "forward",
					"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/admin/1",
				}},
			}),
			resource("aws_lb_target_group.admin", "aws_lb_target_group", "admin", map[string]any{
				"arn": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/admin/1",
			}),
			resource("aws_ecs_service.admin", "aws_ecs_service", "admin", map[string]any{
				"load_balancer": []any{map[string]any{
					"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/admin/1",
				}},
				"task_definition": "arn:aws:ecs:us-east-1:123:task-definition/admin:1",
				"security_groups": []any{"sg-public"},
				"tags":            map[string]any{"env": "prod"},
			}),
			resource("aws_ecs_task_definition.admin", "aws_ecs_task_definition", "admin", map[string]any{
				"arn":           "arn:aws:ecs:us-east-1:123:task-definition/admin:1",
				"task_role_arn": "arn:aws:iam::123:role/worker",
			}),
			resource("aws_instance.web", "aws_instance", "web", map[string]any{
				"id":              "i-web",
				"security_groups": []any{"sg-public"},
			}),
			resource("aws_db_instance.customer", "aws_db_instance", "customer", map[string]any{
				"id":                     "db-customer",
				"identifier":             "customer",
				"publicly_accessible":    true,
				"vpc_security_group_ids": []any{"sg-public"},
				"kms_key_id":             "arn:aws:kms:us-east-1:123:key/data",
				"tags":                   map[string]any{"env": "prod"},
			}),
			resource("aws_kms_key.data", "aws_kms_key", "data", map[string]any{
				"arn": "arn:aws:kms:us-east-1:123:key/data",
			}),
			resource("aws_secretsmanager_secret.customer", "aws_secretsmanager_secret", "customer", map[string]any{
				"arn":        "arn:aws:secretsmanager:us-east-1:123:secret:customer",
				"kms_key_id": "arn:aws:kms:us-east-1:123:key/data",
			}),
			resource("aws_lambda_function.worker", "aws_lambda_function", "worker", map[string]any{
				"arn":         "arn:aws:lambda:us-east-1:123:function:worker",
				"role":        "arn:aws:iam::123:role/worker",
				"kms_key_arn": "arn:aws:kms:us-east-1:123:key/data",
				"environment": []any{map[string]any{"variables": map[string]any{
					"CUSTOMER_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:customer",
				}}},
			}),
			resource("aws_lambda_function_url.worker", "aws_lambda_function_url", "worker", map[string]any{
				"authorization_type": "NONE",
				"function_name":      "worker",
			}),
			resource("aws_iam_role.worker", "aws_iam_role", "worker", map[string]any{
				"arn":  "arn:aws:iam::123:role/worker",
				"name": "worker",
			}),
			resource("aws_iam_role.deployer", "aws_iam_role", "deployer", map[string]any{
				"arn":  "arn:aws:iam::123:role/deployer",
				"name": "deployer",
			}),
			resource("aws_iam_policy.worker", "aws_iam_policy", "worker", map[string]any{
				"arn":    "arn:aws:iam::123:policy/worker",
				"policy": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","iam:PassRole"],"Resource":"*"}]}`,
			}),
			resource("aws_iam_role_policy_attachment.worker", "aws_iam_role_policy_attachment", "worker", map[string]any{
				"role":       "worker",
				"policy_arn": "arn:aws:iam::123:policy/worker",
			}),
			resource("aws_s3_bucket.logs", "aws_s3_bucket", "logs", map[string]any{
				"bucket": "logs",
				"tags":   map[string]any{"env": "prod"},
			}),
			resource("aws_s3_bucket_public_access_block.logs", "aws_s3_bucket_public_access_block", "logs", map[string]any{
				"bucket": "logs",
			}),
			resource("aws_s3_bucket_policy.logs", "aws_s3_bucket_policy", "logs", map[string]any{
				"bucket": "logs",
				"policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`,
			}),
			resource("aws_cloudfront_distribution.cdn", "aws_cloudfront_distribution", "cdn", map[string]any{
				"enabled": true,
				"origin":  []any{map[string]any{"domain_name": "logs"}},
			}),
			resource("aws_apigatewayv2_api.public", "aws_apigatewayv2_api", "public", map[string]any{
				"id":            "api-public",
				"protocol_type": "HTTP",
			}),
			resource("aws_apigatewayv2_integration.worker", "aws_apigatewayv2_integration", "worker", map[string]any{
				"api_id":           "api-public",
				"integration_type": "AWS_PROXY",
				"integration_uri":  "arn:aws:lambda:us-east-1:123:function:worker",
			}),
		},
		Changes: []model.Change{
			change("aws_lb.admin", "aws_lb", "admin", []model.Action{model.ActionUpdate}),
			change("aws_ecs_service.admin", "aws_ecs_service", "admin", []model.Action{model.ActionUpdate}),
			change("aws_db_instance.customer", "aws_db_instance", "customer", []model.Action{model.ActionUpdate}),
		},
	}
}

func resource(address string, typ string, name string, values map[string]any) model.Resource {
	tags := make(map[string]string)
	if rawTags, ok := values["tags"].(map[string]any); ok {
		for key, value := range rawTags {
			tags[key] = value.(string)
		}
	}
	return model.Resource{
		Address:  address,
		Type:     typ,
		Name:     name,
		Provider: "registry.terraform.io/hashicorp/aws",
		Values:   values,
		Tags:     tags,
	}
}

func change(address string, typ string, name string, actions []model.Action) model.Change {
	return model.Change{
		Address:  address,
		Type:     typ,
		Name:     name,
		Provider: "registry.terraform.io/hashicorp/aws",
		Actions:  actions,
	}
}
