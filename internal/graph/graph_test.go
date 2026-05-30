package graph

import (
	"encoding/json"
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
				"tags":                   map[string]any{"env": "prod"},
			}),
			resource("aws_lambda_function.worker", "aws_lambda_function", "worker", map[string]any{
				"role": "arn:aws:iam::123:role/worker",
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
			resource("aws_s3_bucket_policy.logs", "aws_s3_bucket_policy", "logs", map[string]any{
				"bucket": "logs",
				"policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`,
			}),
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
