package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
)

// InternetNodeID is the synthetic node representing the public internet.
const InternetNodeID ResourceID = "internet"

func inferExplicitDependencies(g *Graph, plan *model.Plan) {
	resourceByAddress := make(map[string]model.Resource)
	for _, resource := range append(append([]model.Resource{}, plan.PriorResources...), plan.Resources...) {
		resourceByAddress[resource.Address] = resource
	}
	for _, resource := range resourceByAddress {
		for _, dep := range resource.DependsOn {
			g.addEdge(ResourceID(resource.Address), ResourceID(dep), EdgeDependsOn, evidence(resource.Address, "depends_on", dep, "resource declares explicit dependency"), nil)
		}
	}
}

func inferGenericReferences(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if node.Synthetic {
			continue
		}
		for ref := range referencesInNode(g, id) {
			g.addEdge(id, ref, EdgeDependsOn, evidence(node.Address, "values", ref, "resource value references another resource"), nil)
		}
	}
}

func inferAWSNetwork(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		switch node.Type {
		case "aws_security_group":
			values := resourceValues(g, id)
			if isPublicIngress(values["ingress"]) {
				g.ensureSynthetic(InternetNodeID, "internet", "internet")
				g.addEdge(InternetNodeID, id, EdgeAllowsIngress, evidence(node.Address, "ingress", "0.0.0.0/0", "security group allows public ingress"), nil)
				g.addEdge(InternetNodeID, id, EdgeHasPublicAccess, evidence(node.Address, "ingress", "0.0.0.0/0", "security group is internet exposed"), nil)
			}
			for _, sg := range stringList(values["security_groups"]) {
				if target := findByIDLike(g, sg, "aws_security_group"); target != "" {
					g.addEdge(id, target, EdgeAttachedTo, evidence(node.Address, "security_groups", sg, "security group references another security group"), nil)
				}
			}
		case "aws_vpc_security_group_ingress_rule":
			values := resourceValues(g, id)
			target := securityGroupTarget(g, values)
			if target != "" && cidrIsPublic(values["cidr_ipv4"], values["cidr_ipv6"]) {
				g.ensureSynthetic(InternetNodeID, "internet", "internet")
				g.addEdge(InternetNodeID, target, EdgeAllowsIngress, evidence(node.Address, "cidr", "public", "ingress rule allows public traffic"), nil)
				g.addEdge(InternetNodeID, target, EdgeHasPublicAccess, evidence(node.Address, "cidr", "public", "security group is internet exposed"), nil)
			}
		case "aws_instance", "aws_network_interface", "aws_lambda_function", "aws_ecs_service", "aws_db_instance":
			values := resourceValues(g, id)
			for _, sg := range append(stringList(values["security_groups"]), stringList(values["vpc_security_group_ids"])...) {
				if target := findByIDLike(g, sg, "aws_security_group"); target != "" {
					g.addEdge(target, id, EdgeAllowsIngress, evidence(node.Address, "security_groups", sg, "security group applies to resource"), nil)
					g.addEdge(id, target, EdgeAllowsEgress, evidence(node.Address, "security_groups", sg, "resource can send traffic through security group"), nil)
				}
			}
			if subnet := findByIDLike(g, asString(values["subnet_id"]), "aws_subnet"); subnet != "" {
				g.addEdge(id, subnet, EdgeContainedIn, evidence(node.Address, "subnet_id", subnet, "resource is placed in subnet"), nil)
			}
			for _, subnetID := range nestedStrings(values["network_configuration"], "subnets") {
				if subnet := findByIDLike(g, subnetID, "aws_subnet"); subnet != "" {
					g.addEdge(id, subnet, EdgeContainedIn, evidence(node.Address, "network_configuration.subnets", subnet, "resource is placed in subnet"), nil)
				}
			}
			for _, sg := range nestedStrings(values["network_configuration"], "security_groups") {
				if target := findByIDLike(g, sg, "aws_security_group"); target != "" {
					g.addEdge(target, id, EdgeAllowsIngress, evidence(node.Address, "network_configuration.security_groups", sg, "security group applies to resource"), nil)
					g.addEdge(id, target, EdgeAllowsEgress, evidence(node.Address, "network_configuration.security_groups", sg, "resource can send traffic through security group"), nil)
				}
			}
		case "aws_subnet":
			values := resourceValues(g, id)
			if vpc := findByIDLike(g, asString(values["vpc_id"]), "aws_vpc"); vpc != "" {
				g.addEdge(id, vpc, EdgeContainedIn, evidence(node.Address, "vpc_id", vpc, "subnet is contained in VPC"), nil)
			}
		case "aws_route_table_association":
			values := resourceValues(g, id)
			subnet := findByIDLike(g, asString(values["subnet_id"]), "aws_subnet")
			routeTable := findByIDLike(g, asString(values["route_table_id"]), "aws_route_table")
			if subnet != "" && routeTable != "" {
				g.addEdge(subnet, routeTable, EdgeAttachedTo, evidence(node.Address, "route_table_id", routeTable, "subnet is associated with route table"), nil)
			}
		case "aws_route":
			values := resourceValues(g, id)
			routeTable := findByIDLike(g, asString(values["route_table_id"]), "aws_route_table")
			if routeTable != "" {
				g.addEdge(routeTable, id, EdgeAttachedTo, evidence(node.Address, "route_table_id", routeTable, "route belongs to route table"), nil)
			}
			if cidrIsPublic(values["destination_cidr_block"], values["destination_ipv6_cidr_block"]) {
				if igw := findByIDLike(g, asString(values["gateway_id"]), "aws_internet_gateway"); igw != "" {
					g.ensureSynthetic(InternetNodeID, "internet", "internet")
					g.addEdge(id, igw, EdgeRoutesTo, evidence(node.Address, "gateway_id", igw, "route sends public traffic to internet gateway"), nil)
					g.addEdge(InternetNodeID, id, EdgeRoutesTo, evidence(node.Address, "destination_cidr_block", "public", "internet can traverse public route"), nil)
				}
				if nat := findByIDLike(g, asString(values["nat_gateway_id"]), "aws_nat_gateway"); nat != "" {
					g.addEdge(id, nat, EdgeRoutesTo, evidence(node.Address, "nat_gateway_id", nat, "route sends broad egress through NAT gateway"), nil)
				}
			}
		}
	}
}

func inferAWSLoadBalancing(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		values := resourceValues(g, id)
		switch node.Type {
		case "aws_lb":
			if (asString(values["load_balancer_type"]) == "application" && asString(values["internal"]) == "false") || asString(values["scheme"]) == "internet-facing" {
				g.ensureSynthetic(InternetNodeID, "internet", "internet")
				g.addEdge(InternetNodeID, id, EdgeRoutesTo, evidence(node.Address, "scheme", "internet-facing", "load balancer is internet-facing"), nil)
				g.addEdge(InternetNodeID, id, EdgeHasPublicAccess, evidence(node.Address, "scheme", "internet-facing", "load balancer is internet exposed"), nil)
			}
			for _, sg := range stringList(values["security_groups"]) {
				if target := findByIDLike(g, sg, "aws_security_group"); target != "" {
					g.addEdge(target, id, EdgeAllowsIngress, evidence(node.Address, "security_groups", sg, "security group allows traffic to load balancer"), nil)
				}
			}
		case "aws_lb_listener":
			if lb := findByARNOrAddress(g, asString(values["load_balancer_arn"]), "aws_lb"); lb != "" {
				g.addEdge(lb, id, EdgeRoutesTo, evidence(node.Address, "load_balancer_arn", lb, "load balancer routes to listener"), nil)
			}
			for _, tg := range targetGroupsFromListener(values) {
				if target := findByARNOrAddress(g, tg, "aws_lb_target_group"); target != "" {
					g.addEdge(id, target, EdgeRoutesTo, evidence(node.Address, "default_action.target_group_arn", target, "listener forwards to target group"), nil)
				}
			}
		case "aws_lb_target_group_attachment":
			if tg := findByARNOrAddress(g, asString(values["target_group_arn"]), "aws_lb_target_group"); tg != "" {
				if target := findByIDLike(g, asString(values["target_id"]), ""); target != "" {
					g.addEdge(tg, target, EdgeRoutesTo, evidence(node.Address, "target_id", target, "target group routes to attached target"), nil)
				}
			}
		case "aws_cloudfront_distribution":
			g.ensureSynthetic(InternetNodeID, "internet", "internet")
			g.addEdge(InternetNodeID, id, EdgeRoutesTo, evidence(node.Address, "enabled", true, "CloudFront distribution is publicly reachable"), nil)
			for _, origin := range nestedStrings(values["origin"], "domain_name") {
				if target := findByIDLike(g, origin, ""); target != "" {
					g.addEdge(id, target, EdgeRoutesTo, evidence(node.Address, "origin.domain_name", target, "CloudFront routes to origin"), nil)
				}
			}
		case "aws_api_gateway_rest_api", "aws_apigatewayv2_api":
			g.ensureSynthetic(InternetNodeID, "internet", "internet")
			g.addEdge(InternetNodeID, id, EdgeRoutesTo, evidence(node.Address, "api", "public", "API Gateway endpoint is publicly reachable"), nil)
		}
	}
}

func inferAWSECS(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		values := resourceValues(g, id)
		switch node.Type {
		case "aws_ecs_service":
			for _, tg := range targetGroupsFromECS(values) {
				if target := findByARNOrAddress(g, tg, "aws_lb_target_group"); target != "" {
					g.addEdge(target, id, EdgeRoutesTo, evidence(node.Address, "load_balancer.target_group_arn", target, "target group routes to ECS service"), nil)
				}
			}
			if task := findByARNOrAddress(g, asString(values["task_definition"]), "aws_ecs_task_definition"); task != "" {
				g.addEdge(id, task, EdgeDependsOn, evidence(node.Address, "task_definition", task, "ECS service uses task definition"), nil)
			}
		case "aws_ecs_task_definition":
			for _, roleField := range []string{"task_role_arn", "execution_role_arn"} {
				if role := findByARNOrAddress(g, asString(values[roleField]), "aws_iam_role"); role != "" {
					g.addEdge(id, role, EdgeCanPassRole, evidence(node.Address, roleField, role, "task definition uses IAM role"), nil)
				}
			}
		}
	}
}

func inferAWSLambda(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if node.Type != "aws_lambda_function" {
			continue
		}
		values := resourceValues(g, id)
		if role := findByARNOrAddress(g, asString(values["role"]), "aws_iam_role"); role != "" {
			g.addEdge(id, role, EdgeCanAssume, evidence(node.Address, "role", role, "Lambda function assumes execution role"), nil)
		}
	}
}

func inferAWSRDS(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if node.Type != "aws_db_instance" && node.Type != "aws_rds_cluster" {
			continue
		}
		values := resourceValues(g, id)
		if publicBool(values["publicly_accessible"]) {
			g.ensureSynthetic(InternetNodeID, "internet", "internet")
			g.addEdge(InternetNodeID, id, EdgeRoutesTo, evidence(node.Address, "publicly_accessible", true, "database is publicly accessible"), nil)
			g.addEdge(InternetNodeID, id, EdgeHasPublicAccess, evidence(node.Address, "publicly_accessible", true, "database is internet exposed"), nil)
		}
		for _, sg := range stringList(values["vpc_security_group_ids"]) {
			if target := findByIDLike(g, sg, "aws_security_group"); target != "" {
				g.addEdge(target, id, EdgeAllowsIngress, evidence(node.Address, "vpc_security_group_ids", sg, "security group allows traffic to database"), nil)
			}
		}
	}
}

func inferAWSS3(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		values := resourceValues(g, id)
		switch node.Type {
		case "aws_s3_bucket_public_access_block":
			bucket := findByIDLike(g, asString(values["bucket"]), "aws_s3_bucket")
			if bucket != "" {
				g.addEdge(id, bucket, EdgeAttachedTo, evidence(node.Address, "bucket", bucket, "public access block applies to bucket"), nil)
			}
		case "aws_s3_bucket_policy":
			bucket := findByIDLike(g, asString(values["bucket"]), "aws_s3_bucket")
			if bucket != "" && strings.Contains(asString(values["policy"]), `"Principal":"*"`) {
				g.ensureSynthetic(InternetNodeID, "internet", "internet")
				g.addEdge(InternetNodeID, bucket, EdgeCanReadData, evidence(node.Address, "policy", "public principal", "bucket policy grants public access"), nil)
				g.addEdge(InternetNodeID, bucket, EdgeHasPublicAccess, evidence(node.Address, "policy", "public principal", "bucket is publicly accessible"), nil)
			}
		}
	}
}

func inferAWSDataProtection(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		values := resourceValues(g, id)
		switch node.Type {
		case "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_efs_file_system", "aws_dynamodb_table", "aws_elasticache_cluster", "aws_elasticache_replication_group", "aws_opensearch_domain", "aws_elasticsearch_domain", "aws_secretsmanager_secret":
			for _, keyField := range []string{"kms_key_id", "kms_key_arn", "key_id"} {
				if key := findByARNOrAddress(g, asString(values[keyField]), "aws_kms_key"); key != "" {
					g.addEdge(id, key, EdgeEncryptsWith, evidence(node.Address, keyField, key, "resource is encrypted with KMS key"), nil)
				}
			}
			if replica := findByIDLike(g, asString(values["replica_kms_key_id"]), "aws_kms_key"); replica != "" {
				g.addEdge(id, replica, EdgeReplicatesTo, evidence(node.Address, "replica_kms_key_id", replica, "resource replicates encrypted data"), nil)
			}
		case "aws_s3_bucket_public_access_block":
			if bucket := findByIDLike(g, asString(values["bucket"]), "aws_s3_bucket"); bucket != "" {
				g.addEdge(id, bucket, EdgeProtects, evidence(node.Address, "bucket", bucket, "public access block protects bucket"), nil)
			}
		}
	}
}

func inferAWSIAM(g *Graph) {
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		values := resourceValues(g, id)
		switch node.Type {
		case "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment":
			policy := findByARNOrAddress(g, asString(values["policy_arn"]), "aws_iam_policy")
			principal := iamPrincipalForAttachment(g, node.Type, values)
			if principal != "" && policy != "" {
				g.addEdge(principal, policy, EdgeAttachedTo, evidence(node.Address, "policy_arn", policy, "IAM policy is attached to principal"), nil)
				g.addEdge(policy, principal, EdgeGrantsPermission, evidence(node.Address, "policy_arn", principal, "IAM policy grants permissions to principal"), nil)
				inferPolicyAccess(g, principal, policy)
			}
		case "aws_iam_role_policy", "aws_iam_policy":
			principal := findByIDLike(g, asString(values["role"]), "aws_iam_role")
			if principal != "" {
				inferInlinePolicyAccess(g, principal, node.Address, asString(values["policy"]))
			}
		case "aws_iam_role":
			policy := asString(values["assume_role_policy"])
			for _, principal := range principalsFromAssumePolicy(policy) {
				if source := findByARNOrAddress(g, principal, ""); source != "" {
					g.addEdge(source, id, EdgeCanAssume, evidence(node.Address, "assume_role_policy", principal, "principal can assume role"), nil)
				}
			}
		}
	}
}

func propagateEnvironment(g *Graph) {
	changed := true
	for changed {
		changed = false
		for _, edge := range g.Edges {
			from := g.Nodes[edge.From]
			to := g.Nodes[edge.To]
			if from == nil || to == nil {
				continue
			}
			if from.Environment != "" && to.Environment == "" && propagatesEnvironment(edge.Type) {
				to.Environment = from.Environment
				changed = true
			}
			if to.Environment != "" && from.Environment == "" && propagatesEnvironment(edge.Type) {
				from.Environment = to.Environment
				changed = true
			}
		}
	}
}

func propagatesEnvironment(edgeType EdgeType) bool {
	switch edgeType {
	case EdgeRoutesTo, EdgeAttachedTo, EdgeContainedIn, EdgeDependsOn, EdgeAllowsIngress, EdgeAllowsEgress:
		return true
	default:
		return false
	}
}

func referencesInNode(g *Graph, id ResourceID) map[ResourceID]bool {
	values := resourceValues(g, id)
	refs := make(map[ResourceID]bool)
	blob, err := json.Marshal(values)
	if err != nil {
		return refs
	}
	text := string(blob)
	for candidate := range g.Nodes {
		if candidate == id {
			continue
		}
		if strings.Contains(text, string(candidate)) {
			refs[candidate] = true
		}
	}
	return refs
}

func resourceValues(g *Graph, id ResourceID) map[string]any {
	if g == nil || g.Nodes[id] == nil {
		return nil
	}
	return g.Nodes[id].Values
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := asString(item)
			if text != "" && text != "<nil>" {
				out = append(out, text)
			}
		}
		sort.Strings(out)
		return out
	case []string:
		out := append([]string(nil), typed...)
		sort.Strings(out)
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func isPublicIngress(value any) bool {
	blob := asString(value)
	return strings.Contains(blob, "0.0.0.0/0") || strings.Contains(blob, "::/0")
}

func cidrIsPublic(values ...any) bool {
	for _, value := range values {
		text := asString(value)
		if text == "0.0.0.0/0" || text == "::/0" {
			return true
		}
	}
	return false
}

func publicBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed == "true"
	default:
		return false
	}
}

func securityGroupTarget(g *Graph, values map[string]any) ResourceID {
	for _, key := range []string{"security_group_id", "referenced_security_group_id"} {
		if target := findByIDLike(g, asString(values[key]), "aws_security_group"); target != "" {
			return target
		}
	}
	return ""
}

func targetGroupsFromListener(values map[string]any) []string {
	return nestedStrings(values["default_action"], "target_group_arn")
}

func targetGroupsFromECS(values map[string]any) []string {
	return nestedStrings(values["load_balancer"], "target_group_arn")
}

func nestedStrings(value any, key string) []string {
	out := make([]string, 0)
	for _, item := range asList(value) {
		if obj, ok := item.(map[string]any); ok {
			out = append(out, stringList(obj[key])...)
		}
	}
	sort.Strings(out)
	return out
}

func asList(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case nil:
		return nil
	default:
		return []any{typed}
	}
}

func findByIDLike(g *Graph, value string, resourceType string) ResourceID {
	if value == "" || value == "<nil>" {
		return ""
	}
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if resourceType != "" && node.Type != resourceType {
			continue
		}
		if string(id) == value || node.Name == value || strings.HasSuffix(string(id), "."+value) {
			return id
		}
		values := resourceValues(g, id)
		for _, key := range []string{"id", "arn", "name", "bucket", "identifier"} {
			if asString(values[key]) == value {
				return id
			}
		}
	}
	return ""
}

func findByARNOrAddress(g *Graph, value string, resourceType string) ResourceID {
	return findByIDLike(g, value, resourceType)
}

func iamPrincipalForAttachment(g *Graph, resourceType string, values map[string]any) ResourceID {
	switch resourceType {
	case "aws_iam_role_policy_attachment":
		return findByIDLike(g, asString(values["role"]), "aws_iam_role")
	case "aws_iam_user_policy_attachment":
		return findByIDLike(g, asString(values["user"]), "aws_iam_user")
	case "aws_iam_group_policy_attachment":
		return findByIDLike(g, asString(values["group"]), "aws_iam_group")
	default:
		return ""
	}
}

func inferPolicyAccess(g *Graph, principal ResourceID, policy ResourceID) {
	values := resourceValues(g, policy)
	inferInlinePolicyAccess(g, principal, string(policy), asString(values["policy"]))
}

func inferInlinePolicyAccess(g *Graph, principal ResourceID, resource string, policyJSON string) {
	lower := strings.ToLower(policyJSON)
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if !isSensitiveDataNode(node) {
			continue
		}
		if strings.Contains(lower, "s3:get") || strings.Contains(lower, "rds:describe") || strings.Contains(lower, "secretsmanager:get") || strings.Contains(lower, "*") {
			g.addEdge(principal, id, EdgeCanReadData, evidence(resource, "policy", id, "IAM policy allows reading sensitive data resource"), nil)
			if node.Kind == NodeSecret {
				g.addEdge(principal, id, EdgeReadsSecret, evidence(resource, "policy", id, "IAM policy allows reading secret value"), nil)
			}
		}
		if strings.Contains(lower, "s3:put") || strings.Contains(lower, "rds:modify") || strings.Contains(lower, "secretsmanager:put") || strings.Contains(lower, "*") {
			g.addEdge(principal, id, EdgeCanWriteData, evidence(resource, "policy", id, "IAM policy allows writing sensitive data resource"), nil)
			g.addEdge(principal, id, EdgeWritesTo, evidence(resource, "policy", id, "IAM policy allows writing data resource"), nil)
		}
	}
	for _, id := range sortedNodeIDs(g) {
		node := g.Nodes[id]
		if node.Type != "aws_iam_role" {
			continue
		}
		if strings.Contains(lower, "sts:assumerole") || strings.Contains(lower, "*") {
			g.addEdge(principal, id, EdgeCanAssume, evidence(resource, "policy", id, "IAM policy allows assuming role"), nil)
		}
		if strings.Contains(lower, "iam:passrole") || strings.Contains(lower, "*") {
			g.addEdge(principal, id, EdgeCanPassRole, evidence(resource, "policy", id, "IAM policy allows passing role"), nil)
		}
	}
}

func principalsFromAssumePolicy(policy string) []string {
	if policy == "" {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(policy), &decoded); err != nil {
		return nil
	}
	blob := fmt.Sprint(decoded)
	out := make([]string, 0)
	for _, field := range strings.FieldsFunc(blob, func(r rune) bool {
		return r == ' ' || r == '[' || r == ']' || r == ',' || r == ':' || r == '{' || r == '}'
	}) {
		if strings.Contains(field, "arn:aws:iam") {
			out = append(out, strings.Trim(field, `"`))
		}
	}
	sort.Strings(out)
	return out
}
