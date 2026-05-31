package rules

import (
	"context"
	"testing"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

func TestAWSRulePackCounts(t *testing.T) {
	t.Parallel()

	registry, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}

	stable := 0
	graphRules := 0
	iamRules := 0
	publicRules := 0
	statefulRules := 0
	for _, rule := range registry.Rules() {
		meta := rule.Metadata()
		if meta.Status == StatusStable {
			stable++
		}
		for _, capability := range meta.Capabilities {
			if capability == CapabilityGraph {
				graphRules++
				break
			}
		}
		switch meta.Category {
		case model.RiskCategoryPrivilegeEscalation:
			iamRules++
		case model.RiskCategoryPublicExposure:
			publicRules++
		case model.RiskCategoryAvailability, model.RiskCategorySensitiveData:
			statefulRules++
		}
		if len(meta.Documentation.Remediation) == 0 {
			t.Fatalf("rule %s has no remediation documentation", meta.ID)
		}
	}

	if stable < 20 {
		t.Fatalf("stable rules = %d, want at least 20", stable)
	}
	if graphRules < 10 {
		t.Fatalf("graph rules = %d, want at least 10", graphRules)
	}
	if iamRules < 5 {
		t.Fatalf("IAM rules = %d, want at least 5", iamRules)
	}
	if publicRules < 5 {
		t.Fatalf("public exposure rules = %d, want at least 5", publicRules)
	}
	if statefulRules < 5 {
		t.Fatalf("stateful/sensitive rules = %d, want at least 5", statefulRules)
	}
}

func TestAWSRulesPassOnEmptyPlan(t *testing.T) {
	t.Parallel()

	registry, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	plan := &model.Plan{}
	result := NewRunner(registry).Evaluate(context.Background(), RuleInput{
		Plan:  plan,
		Graph: graph.Build(plan),
	}, Selection{})
	if len(result.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Findings))
	}
}

func TestAWSRulesFailingFixture(t *testing.T) {
	t.Parallel()

	registry, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	plan := awsFailingPlan()
	result := NewRunner(registry).Evaluate(context.Background(), RuleInput{
		Plan:  plan,
		Graph: graph.Build(plan),
	}, Selection{})
	if len(result.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}

	seen := make(map[string]model.Finding)
	for _, finding := range result.Findings {
		seen[finding.RuleID] = finding
		if len(finding.Evidence) == 0 {
			t.Fatalf("finding %s has no evidence", finding.RuleID)
		}
		if finding.Remediation.Summary == "" {
			t.Fatalf("finding %s has no remediation", finding.RuleID)
		}
	}

	for _, rule := range registry.Rules() {
		if _, generated := rule.(generatedAttackPathRule); generated {
			continue
		}
		ruleID := rule.Metadata().ID
		if _, ok := seen[ruleID]; !ok {
			t.Errorf("expected fixture to trigger %s", ruleID)
		}
	}
}

func awsFailingPlan() *model.Plan {
	resources := []model.Resource{
		res("aws_security_group.public", "aws_security_group", "public", map[string]any{
			"id": "sg-public",
			"ingress": []any{
				map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": 22, "to_port": 22},
				map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": 5432, "to_port": 5432},
			},
			"egress": []any{map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": 0, "to_port": 0}},
			"tags":   map[string]any{"env": "prod"},
		}),
		res("aws_lb.admin", "aws_lb", "admin", map[string]any{"arn": "alb-arn", "scheme": "internet-facing", "security_groups": []any{"sg-public"}, "tags": map[string]any{"env": "prod"}}),
		res("aws_lb_listener.admin", "aws_lb_listener", "admin", map[string]any{"load_balancer_arn": "alb-arn", "default_action": []any{map[string]any{"target_group_arn": "tg-arn"}}}),
		res("aws_lb_target_group.admin", "aws_lb_target_group", "admin", map[string]any{"arn": "tg-arn"}),
		res("aws_ecs_service.admin", "aws_ecs_service", "admin", map[string]any{"load_balancer": []any{map[string]any{"target_group_arn": "tg-arn"}}, "security_groups": []any{"sg-public"}, "task_definition": "task-arn", "tags": map[string]any{"env": "prod", "service": "internal"}}),
		res("aws_ecs_task_definition.admin", "aws_ecs_task_definition", "admin", map[string]any{"arn": "task-arn", "task_role_arn": "worker-role-arn"}),
		res("aws_instance.admin", "aws_instance", "admin", map[string]any{"associate_public_ip_address": true, "security_groups": []any{"sg-public"}, "tags": map[string]any{"env": "prod"}}),
		res("aws_db_instance.customer", "aws_db_instance", "customer", map[string]any{"id": "db-customer", "identifier": "customer", "publicly_accessible": true, "storage_encrypted": false, "backup_retention_period": 0, "deletion_protection": false, "vpc_security_group_ids": []any{"sg-public"}, "tags": map[string]any{"env": "prod"}}),
		res("aws_opensearch_domain.search", "aws_opensearch_domain", "search", map[string]any{"access_policies": `{"Statement":[{"Principal":"*"}]}`}),
		res("aws_eks_cluster.prod", "aws_eks_cluster", "prod", map[string]any{"endpoint_public_access": true, "tags": map[string]any{"env": "prod"}}),
		res("aws_s3_bucket_public_access_block.logs", "aws_s3_bucket_public_access_block", "logs", map[string]any{"bucket": "logs", "block_public_acls": false, "block_public_policy": false, "ignore_public_acls": false, "restrict_public_buckets": false, "tags": map[string]any{"env": "prod"}}),
		res("aws_cloudfront_distribution.cdn", "aws_cloudfront_distribution", "cdn", map[string]any{"enabled": true}),
		res("aws_s3_bucket.logs", "aws_s3_bucket", "logs", map[string]any{"bucket": "logs", "server_side_encryption_configuration": []any{}, "tags": map[string]any{"env": "prod", "data": "sensitive"}}),
		res("aws_s3_bucket_policy.logs", "aws_s3_bucket_policy", "logs", map[string]any{"bucket": "logs", "policy": `{"Statement":[{"Principal":"*","Action":"s3:GetObject"}]}`}),
		res("aws_lambda_function.worker", "aws_lambda_function", "worker", map[string]any{"role": "worker-role-arn"}),
		res("aws_iam_role.worker", "aws_iam_role", "worker", map[string]any{"arn": "worker-role-arn", "name": "worker", "assume_role_policy": `{"Statement":[{"Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::999999999999:root"}}]}`}),
		res("aws_iam_role.admin", "aws_iam_role", "admin", map[string]any{"arn": "admin-role-arn", "name": "admin"}),
		res("aws_iam_policy.admin", "aws_iam_policy", "admin", map[string]any{"arn": "admin-policy-arn", "policy": `{"Statement":[{"Action":"*","Resource":"*"},{"Action":["iam:PassRole","sts:AssumeRole","kms:Decrypt","secretsmanager:GetSecretValue","lambda:CreateFunction"],"Resource":"*"}]}`}),
		res("aws_iam_role_policy_attachment.worker", "aws_iam_role_policy_attachment", "worker", map[string]any{"role": "worker", "policy_arn": "admin-policy-arn"}),
		res("aws_iam_role_policy_attachment.admin", "aws_iam_role_policy_attachment", "admin", map[string]any{"role": "admin", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
		res("aws_iam_role.github", "aws_iam_role", "github", map[string]any{"assume_role_policy": `{"Statement":[{"Principal":{"Federated":"token.actions.githubusercontent.com"},"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}}]}`}),
		res("aws_route.private_default", "aws_route", "private_default", map[string]any{"gateway_id": "igw-123", "destination_cidr_block": "0.0.0.0/0"}),
		res("aws_route.private_nat", "aws_route", "private_nat", map[string]any{"nat_gateway_id": "nat-123", "destination_cidr_block": "0.0.0.0/0", "tags": map[string]any{"tier": "private", "env": "prod"}}),
		res("aws_route.sensitive_tgw", "aws_route", "sensitive_tgw", map[string]any{"transit_gateway_id": "tgw-123", "destination_cidr_block": "10.20.0.0/16", "tags": map[string]any{"data": "sensitive", "env": "prod"}}),
	}
	changes := make([]model.Change, 0, len(resources)+2)
	for _, resource := range resources {
		changes = append(changes, changeFromResource(resource, []model.Action{model.ActionCreate}))
	}
	changes = append(changes,
		model.Change{Address: "aws_db_instance.customer_replace", Type: "aws_db_instance", Name: "customer_replace", Provider: "registry.terraform.io/hashicorp/aws", Actions: []model.Action{model.ActionReplace}, After: map[string]any{"tags": map[string]any{"env": "prod"}, "backup_retention_period": 7, "deletion_protection": true, "storage_encrypted": true}, Tags: map[string]string{"env": "prod"}},
		model.Change{Address: "aws_dynamodb_table.stateful_replace", Type: "aws_dynamodb_table", Name: "stateful_replace", Provider: "registry.terraform.io/hashicorp/aws", Actions: []model.Action{model.ActionReplace}, After: map[string]any{"server_side_encryption_configuration": []any{map[string]any{"enabled": true}}, "tags": map[string]any{"env": "prod"}}, Tags: map[string]string{"env": "prod"}},
	)
	return &model.Plan{Resources: resources, Changes: changes}
}

func res(address string, typ string, name string, values map[string]any) model.Resource {
	return model.Resource{Address: address, Type: typ, Name: name, Provider: "registry.terraform.io/hashicorp/aws", Values: values, Tags: tags(values)}
}

func changeFromResource(resource model.Resource, actions []model.Action) model.Change {
	return model.Change{Address: resource.Address, Type: resource.Type, Name: resource.Name, Provider: resource.Provider, Actions: actions, After: resource.Values, Tags: resource.Tags}
}

func tags(values map[string]any) map[string]string {
	raw, ok := values["tags"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for key, value := range raw {
		if text, ok := value.(string); ok {
			out[key] = text
		}
	}
	return out
}
