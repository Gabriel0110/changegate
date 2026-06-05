package graph

import (
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
)

func inferConfigurationReferences(g *Graph, plan *model.Plan) {
	if g == nil || plan == nil || plan.Configuration == nil {
		return
	}
	index := newConfigNodeIndex(g)
	for _, resource := range plan.Configuration.Resources {
		id := ResourceID(resource.Address)
		node := g.Nodes[id]
		if node == nil {
			continue
		}
		switch node.Type {
		case "aws_lb":
			for _, sg := range configTargets(index, resource.Expressions, "security_groups", "aws_security_group") {
				g.addEdge(sg, id, EdgeAllowsIngress, configEvidence(resource.Address, "security_groups", sg, "security group allows traffic to load balancer"), nil)
			}
		case "aws_lb_listener":
			for _, lb := range configTargets(index, resource.Expressions, "load_balancer_arn", "aws_lb") {
				g.addEdge(lb, id, EdgeRoutesTo, configEvidence(resource.Address, "load_balancer_arn", lb, "load balancer routes to listener"), nil)
			}
			for _, tg := range configTargets(index, resource.Expressions, "target_group_arn", "aws_lb_target_group") {
				g.addEdge(id, tg, EdgeRoutesTo, configEvidence(resource.Address, "default_action.target_group_arn", tg, "listener forwards to target group"), nil)
			}
		case "aws_ecs_service":
			for _, sg := range configTargets(index, resource.Expressions, "security_groups", "aws_security_group") {
				g.addEdge(sg, id, EdgeAllowsIngress, configEvidence(resource.Address, "network_configuration.security_groups", sg, "security group applies to ECS service"), nil)
				g.addEdge(id, sg, EdgeAllowsEgress, configEvidence(resource.Address, "network_configuration.security_groups", sg, "ECS service can send traffic through security group"), nil)
			}
			for _, tg := range configTargets(index, resource.Expressions, "target_group_arn", "aws_lb_target_group") {
				g.addEdge(tg, id, EdgeRoutesTo, configEvidence(resource.Address, "load_balancer.target_group_arn", tg, "target group routes to ECS service"), nil)
			}
			for _, task := range configTargets(index, resource.Expressions, "task_definition", "aws_ecs_task_definition") {
				g.addEdge(id, task, EdgeDependsOn, configEvidence(resource.Address, "task_definition", task, "ECS service uses task definition"), nil)
			}
		case "aws_db_instance", "aws_rds_cluster":
			for _, sg := range configTargets(index, resource.Expressions, "vpc_security_group_ids", "aws_security_group") {
				g.addEdge(sg, id, EdgeAllowsIngress, configEvidence(resource.Address, "vpc_security_group_ids", sg, "security group allows traffic to database"), nil)
			}
		case "aws_lambda_function":
			for _, role := range configTargets(index, resource.Expressions, "role", "aws_iam_role") {
				g.addEdge(id, role, EdgeCanAssume, configEvidence(resource.Address, "role", role, "Lambda function assumes execution role"), nil)
			}
		case "aws_lambda_function_url":
			for _, fn := range configTargets(index, resource.Expressions, "function_name", "aws_lambda_function") {
				g.addEdge(id, fn, EdgeInvokes, configEvidence(resource.Address, "function_name", fn, "Lambda function URL invokes Lambda function"), nil)
			}
		case "aws_s3_bucket_public_access_block":
			for _, bucket := range configTargets(index, resource.Expressions, "bucket", "aws_s3_bucket") {
				g.addEdge(id, bucket, EdgeProtects, configEvidence(resource.Address, "bucket", bucket, "public access block protects bucket"), nil)
			}
		case "aws_s3_bucket_policy":
			for _, bucket := range configTargets(index, resource.Expressions, "bucket", "aws_s3_bucket") {
				g.addEdge(id, bucket, EdgeAttachedTo, configEvidence(resource.Address, "bucket", bucket, "bucket policy applies to bucket"), nil)
			}
		case "aws_s3_bucket_versioning", "aws_s3_bucket_logging", "aws_s3_bucket_server_side_encryption_configuration":
			for _, bucket := range configTargets(index, resource.Expressions, "bucket", "aws_s3_bucket") {
				g.addEdge(id, bucket, EdgeProtects, configEvidence(resource.Address, "bucket", bucket, "bucket control applies to bucket"), nil)
			}
		case "aws_iam_role_policy_attachment":
			principals := configTargets(index, resource.Expressions, "role", "aws_iam_role")
			policies := configTargets(index, resource.Expressions, "policy_arn", "aws_iam_policy")
			for _, principal := range principals {
				for _, policy := range policies {
					g.addEdge(principal, policy, EdgeAttachedTo, configEvidence(resource.Address, "policy_arn", policy, "IAM policy is attached to role"), nil)
					g.addEdge(policy, principal, EdgeGrantsPermission, configEvidence(resource.Address, "policy_arn", principal, "IAM policy grants permissions to role"), nil)
					inferPolicyAccess(g, principal, policy)
				}
			}
		case "aws_iam_role_policy":
			for _, principal := range configTargets(index, resource.Expressions, "role", "aws_iam_role") {
				inferInlinePolicyAccess(g, principal, resource.Address, asString(node.Values["policy"]))
			}
		}
	}
}

type configNodeIndex map[string][]ResourceID

func newConfigNodeIndex(g *Graph) configNodeIndex {
	index := make(configNodeIndex)
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if node == nil {
			continue
		}
		index[node.Type] = append(index[node.Type], id)
	}
	return index
}

func configTargets(index configNodeIndex, expressions map[string]any, key string, resourceType string) []ResourceID {
	references := expressionReferencesForKey(expressions, key)
	out := make([]ResourceID, 0, len(references))
	for _, ref := range references {
		if target := nodeFromConfigReference(index, ref, resourceType); target != "" {
			out = append(out, target)
		}
	}
	sortResourceIDs(out)
	return dedupeResourceIDs(out)
}

func expressionReferencesForKey(value any, key string) []string {
	out := make([]string, 0)
	switch typed := value.(type) {
	case map[string]any:
		if nested, ok := typed[key]; ok {
			out = append(out, referencesInConfigExpression(nested)...)
		}
		for _, nested := range typed {
			out = append(out, expressionReferencesForKey(nested, key)...)
		}
	case []any:
		for _, nested := range typed {
			out = append(out, expressionReferencesForKey(nested, key)...)
		}
	}
	sort.Strings(out)
	return dedupeStrings(out)
}

func referencesInConfigExpression(value any) []string {
	out := make([]string, 0)
	switch typed := value.(type) {
	case map[string]any:
		out = append(out, stringList(typed["references"])...)
		for key, nested := range typed {
			if key == "references" {
				continue
			}
			out = append(out, referencesInConfigExpression(nested)...)
		}
	case []any:
		for _, nested := range typed {
			out = append(out, referencesInConfigExpression(nested)...)
		}
	}
	sort.Strings(out)
	return dedupeStrings(out)
}

func nodeFromConfigReference(index configNodeIndex, ref string, resourceType string) ResourceID {
	if ref == "" {
		return ""
	}
	var best ResourceID
	for _, id := range index[resourceType] {
		address := string(id)
		if ref == address || strings.HasPrefix(ref, address+".") {
			if len(address) > len(string(best)) {
				best = id
			}
		}
	}
	return best
}

func configEvidence(resource string, path string, target ResourceID, message string) []model.Evidence {
	return evidence(resource, path, target, message)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func dedupeResourceIDs(values []ResourceID) []ResourceID {
	seen := make(map[ResourceID]bool, len(values))
	out := make([]ResourceID, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
