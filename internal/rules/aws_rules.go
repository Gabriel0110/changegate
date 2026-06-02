package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

type awsRule struct {
	meta Metadata
	eval func(context.Context, RuleInput, Metadata) ([]model.Finding, error)
}

func (r awsRule) Metadata() Metadata {
	return r.meta
}

func (r awsRule) Evaluate(ctx context.Context, input RuleInput) ([]model.Finding, error) {
	if r.eval == nil {
		return nil, nil
	}
	return r.eval(ctx, input, r.meta)
}

func awsRules() []Rule {
	return []Rule{
		newAWSRule("AWS_PUBLIC_ADMIN_SERVICE", "Internet-facing ALB routes to admin service", "Detects public load balancer paths to resources that appear to expose admin surfaces.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_lb", "aws_lb_listener", "aws_lb_target_group", "aws_ecs_service"}, []Capability{CapabilityGraph}, evalPublicAdminService),
		newAWSRule("AWS_PUBLIC_INTERNAL_SERVICE", "Public load balancer routes to internal service", "Detects public load balancers routing to downstream services tagged internal.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_lb", "aws_ecs_service"}, []Capability{CapabilityGraph}, evalPublicInternalService),
		newAWSRule("AWS_SG_WORLD_OPEN_ADMIN_PORT", "Security group opens admin port to the world", "Detects public ingress to administrative ports.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_security_group", "aws_vpc_security_group_ingress_rule"}, []Capability{CapabilityResourceChanges, CapabilityGraph}, evalWorldOpenAdminPort),
		newAWSRule("AWS_SG_WORLD_OPEN_DB_PORT", "Security group opens database port to the world", "Detects public ingress to database ports.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_security_group", "aws_vpc_security_group_ingress_rule"}, []Capability{CapabilityResourceChanges, CapabilityGraph}, evalWorldOpenDBPort),
		newAWSRule("AWS_EC2_PUBLIC_IP_ADMIN_INGRESS", "EC2 instance has public IP and admin ingress", "Detects EC2 instances with public IPs reachable through public admin ingress.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_instance", "aws_security_group"}, []Capability{CapabilityGraph}, evalEC2PublicAdmin),
		newAWSRule("AWS_PUBLIC_RDS_INSTANCE", "Public RDS instance", "Detects publicly accessible RDS instances.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_db_instance", "aws_rds_cluster"}, []Capability{CapabilityResourceChanges, CapabilityGraph}, evalPublicRDS),
		newAWSRule("AWS_PUBLIC_OPENSEARCH_DOMAIN", "Public OpenSearch domain", "Detects OpenSearch domains with broad public access policies.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_opensearch_domain", "aws_elasticsearch_domain"}, []Capability{CapabilityResourceChanges}, evalPublicOpenSearch),
		newAWSRule("AWS_PUBLIC_EKS_ENDPOINT_PROD", "Production EKS endpoint is public", "Detects production EKS clusters with public endpoints enabled.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_eks_cluster"}, []Capability{CapabilityResourceChanges}, evalPublicEKSProd),
		newAWSRule("AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD", "Production S3 public access block disabled", "Detects production S3 public access block resources that disable one or more protections.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_s3_bucket_public_access_block"}, []Capability{CapabilityResourceChanges}, evalS3PublicAccessBlockDisabledProd),
		newAWSRule("AWS_CLOUDFRONT_S3_PUBLIC_MISMATCH", "CloudFront and S3 public exposure mismatch", "Detects S3 buckets exposed publicly while also fronted by CloudFront.", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_cloudfront_distribution", "aws_s3_bucket"}, []Capability{CapabilityGraph}, evalCloudFrontS3PublicMismatch),
		newAWSRule("AWS_PASSROLE_WITH_COMPUTE_MUTATION", "iam:PassRole with compute mutation", "Detects IAM principals that can pass roles and mutate compute resources.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation", []string{"aws_iam_policy", "aws_lambda_function", "aws_ecs_service", "aws_instance"}, []Capability{CapabilityGraph}, evalPassRoleWithComputeMutation),
		newAWSRule("AWS_IAM_WILDCARD_ADMIN", "Wildcard IAM administration", "Detects IAM policies with broad iam:* or Action:* grants.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation", []string{"aws_iam_policy", "aws_iam_role_policy"}, []Capability{CapabilityResourceChanges}, evalIAMWildcardAdmin),
		newAWSRule("AWS_ROLE_ASSUME_ADMIN_PATH", "Role assumption path to admin role", "Detects graph paths that allow a principal to assume an administrator role.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation", []string{"aws_iam_role", "aws_iam_policy"}, []Capability{CapabilityGraph}, evalRoleAssumeAdminPath),
		newAWSRule("AWS_IAM_ADMIN_POLICY_ATTACHMENT", "IAM administrator policy attachment", "Detects attachment of AdministratorAccess to IAM identities.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation", []string{"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment"}, []Capability{CapabilityResourceChanges}, evalAdminPolicyAttachment),
		newAWSRule("AWS_EXTERNAL_ACCOUNT_TRUST", "Trust policy allows external account assumption", "Detects trust policies granting role assumption to an external account.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation", []string{"aws_iam_role"}, []Capability{CapabilityResourceChanges}, evalExternalAccountTrust),
		newAWSRule("AWS_GITHUB_OIDC_TRUST_BROAD", "GitHub OIDC trust policy is too broad", "Detects GitHub OIDC trust policies without repository or branch constraints.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation", []string{"aws_iam_role"}, []Capability{CapabilityResourceChanges}, evalGithubOIDCBroad),
		newAWSRule("AWS_KMS_DECRYPT_BROAD", "KMS decrypt access granted broadly", "Detects broad KMS decrypt grants.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation", []string{"aws_iam_policy", "aws_iam_role_policy", "aws_kms_key"}, []Capability{CapabilityResourceChanges}, evalKMSDecryptBroad),
		newAWSRule("AWS_SECRETS_READ_BROAD", "Secrets Manager read access granted broadly", "Detects broad Secrets Manager read grants.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation", []string{"aws_iam_policy", "aws_iam_role_policy"}, []Capability{CapabilityResourceChanges}, evalSecretsReadBroad),
		newAWSRule("AWS_RDS_REPLACEMENT_PROD", "Production RDS replacement", "Detects replacement of production RDS instances.", model.RiskCategoryAvailability, model.SeverityHigh, model.ConfidenceHigh, "aws-core", []string{"aws_db_instance", "aws_rds_cluster"}, []Capability{CapabilityResourceChanges}, evalRDSReplacementProd),
		newAWSRule("AWS_STATEFUL_REPLACEMENT", "Stateful resource replacement", "Detects destructive replacement of stateful resources.", model.RiskCategoryAvailability, model.SeverityHigh, model.ConfidenceHigh, "aws-core", []string{"aws_db_instance", "aws_rds_cluster", "aws_efs_file_system", "aws_elasticache_cluster", "aws_dynamodb_table"}, []Capability{CapabilityResourceChanges}, evalStatefulReplacement),
		newAWSRule("AWS_PUBLIC_TO_SENSITIVE_DATASTORE", "Public resource can reach sensitive datastore", "Detects public resources that can reach sensitive data stores through the graph.", model.RiskCategorySensitiveData, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_lb", "aws_ecs_service", "aws_db_instance", "aws_s3_bucket"}, []Capability{CapabilityGraph}, evalPublicToSensitiveDatastore),
		newAWSRule("AWS_SENSITIVE_STORAGE_ENCRYPTION_DISABLED", "Sensitive storage encryption disabled", "Detects sensitive storage resources with encryption disabled.", model.RiskCategorySensitiveData, model.SeverityHigh, model.ConfidenceHigh, "aws-core", []string{"aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_efs_file_system", "aws_dynamodb_table"}, []Capability{CapabilityResourceChanges}, evalSensitiveStorageEncryptionDisabled),
		newAWSRule("AWS_RDS_BACKUP_RETENTION_DISABLED_PROD", "Production RDS backup retention disabled", "Detects production databases with backup retention disabled or reduced to zero.", model.RiskCategoryAvailability, model.SeverityHigh, model.ConfidenceHigh, "aws-core", []string{"aws_db_instance", "aws_rds_cluster"}, []Capability{CapabilityResourceChanges}, evalRDSBackupRetentionDisabledProd),
		newAWSRule("AWS_RDS_DELETION_PROTECTION_DISABLED_PROD", "Production RDS deletion protection disabled", "Detects production databases without deletion protection.", model.RiskCategoryAvailability, model.SeverityHigh, model.ConfidenceHigh, "aws-core", []string{"aws_db_instance", "aws_rds_cluster"}, []Capability{CapabilityResourceChanges}, evalRDSDeletionProtectionDisabledProd),
		newAWSRule("AWS_S3_SENSITIVE_BUCKET_LOGGING_DISABLED", "Sensitive S3 bucket logging disabled", "Detects sensitive buckets without access logging.", model.RiskCategorySensitiveData, model.SeverityHigh, model.ConfidenceHigh, "aws-core", []string{"aws_s3_bucket", "aws_s3_bucket_logging"}, []Capability{CapabilityResourceChanges, CapabilityGraph}, evalS3SensitiveLoggingDisabled),
		newAWSRule("AWS_PRIVATE_SUBNET_ROUTE_TO_IGW", "Private subnet route to internet gateway", "Detects route table changes that route private subnets to an internet gateway.", model.RiskCategoryNetworkBlastRadius, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_route", "aws_route_table", "aws_subnet"}, []Capability{CapabilityResourceChanges, CapabilityGraph}, evalPrivateSubnetRouteToIGW),
		newAWSRule("AWS_PRIVATE_WORKLOAD_EXPOSED_BY_NAT_OR_SG", "Private workload exposed by NAT or security group change", "Detects changes that expose internal or private workloads through public ingress or NAT routing.", model.RiskCategoryNetworkBlastRadius, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_security_group", "aws_vpc_security_group_ingress_rule", "aws_route"}, []Capability{CapabilityResourceChanges, CapabilityGraph}, evalPrivateWorkloadExposedByNATOrSG),
		newAWSRule("AWS_TGW_ROUTE_TO_SENSITIVE_SUBNET", "Transit or peering route expands access to sensitive subnet", "Detects transit gateway or VPC peering routes that target sensitive or private route tables.", model.RiskCategoryNetworkBlastRadius, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_route", "aws_route_table"}, []Capability{CapabilityResourceChanges, CapabilityGraph}, evalTGWRouteToSensitiveSubnet),
		newAWSRule("AWS_EGRESS_OPEN_FROM_SENSITIVE_WORKLOAD", "Sensitive workload egress opened to internet", "Detects broad egress from sensitive workloads.", model.RiskCategoryNetworkBlastRadius, model.SeverityHigh, model.ConfidenceHigh, "aws-public-exposure", []string{"aws_security_group", "aws_vpc_security_group_egress_rule"}, []Capability{CapabilityResourceChanges, CapabilityGraph}, evalSensitiveWorkloadOpenEgress),
	}
}

func newAWSRule(id string, title string, desc string, category model.RiskCategory, severity model.Severity, confidence model.Confidence, pack string, resources []string, capabilities []Capability, eval func(context.Context, RuleInput, Metadata) ([]model.Finding, error)) Rule {
	return awsRule{
		meta: Metadata{
			ID:           id,
			Title:        title,
			Description:  desc,
			Category:     category,
			Severity:     severity,
			Confidence:   confidence,
			Providers:    []string{"aws"},
			Resources:    resources,
			Capabilities: capabilities,
			Status:       StatusStable,
			Version:      "0.1.0",
			PolicyPack:   pack,
			Documentation: Documentation{
				Summary: desc,
				Remediation: []string{
					"Review the planned change before apply.",
					"Constrain the risky permission, exposure, or destructive action to the minimum required scope.",
				},
			},
		},
		eval: eval,
	}
}

func finding(meta Metadata, resource string, provider string, env string, evidence []model.Evidence, remediation string) model.Finding {
	return model.Finding{
		ResourceAddress: resource,
		Provider:        provider,
		Environment:     env,
		Evidence:        evidence,
		Remediation: model.Remediation{
			Summary: remediation,
		},
	}
}

func evalPublicAdminService(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	if input.Graph == nil {
		return nil, nil
	}
	out := make([]model.Finding, 0)
	for id, node := range sortedNodes(input.Graph) {
		if !looksAdmin(node) || !input.Graph.IsInternetExposed(id) {
			continue
		}
		out = append(out, finding(meta, node.Address, node.Provider, node.Environment, exposureEvidence(input.Graph, graph.InternetNodeID, id, node.Address), "Remove public routing to the admin service or require private/authenticated access."))
	}
	return out, nil
}

func evalPublicInternalService(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for id, node := range sortedNodes(input.Graph) {
		if !input.Graph.IsInternetExposed(id) || !isInternal(node) {
			continue
		}
		out = append(out, finding(meta, node.Address, node.Provider, node.Environment, exposureEvidence(input.Graph, graph.InternetNodeID, id, node.Address), "Keep internal services behind private load balancers or remove internal tags if this is intentionally public."))
	}
	return out, nil
}

func evalWorldOpenAdminPort(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	return securityGroupPortFindings(input, meta, adminPorts(), "public ingress reaches an administrative port", "Restrict administrative ingress to VPN, SSM, or trusted CIDRs."), nil
}

func evalWorldOpenDBPort(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	return securityGroupPortFindings(input, meta, dbPorts(), "public ingress reaches a database port", "Remove public database ingress and place data stores in private networks."), nil
}

func evalEC2PublicAdmin(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_instance" || !truthy(change.After["associate_public_ip_address"]) {
			continue
		}
		if input.Graph != nil && input.Graph.CanReach(graph.InternetNodeID, graph.ResourceID(change.Address)) {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{
				ev(change.Address, "associate_public_ip_address", true, "instance receives a public IP"),
				ev(change.Address, "graph", "internet", "internet can reach instance through security group graph"),
			}, "Remove the public IP or restrict admin ingress."))
		}
	}
	return out, nil
}

func evalPublicRDS(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if isRDS(change.Type) && truthy(change.After["publicly_accessible"]) {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "publicly_accessible", true, "database is configured as publicly accessible")}, "Set publicly_accessible to false and use private subnets."))
		}
	}
	return out, nil
}

func evalPublicOpenSearch(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_opensearch_domain" && change.Type != "aws_elasticsearch_domain" {
			continue
		}
		text := normalizePolicyText(asString(change.After["access_policies"]) + asJSON(change.After))
		if strings.Contains(text, `"principal":"*"`) || strings.Contains(text, `"aws":"*"`) {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "access_policies", "(policy)", "domain access policy grants public principal")}, "Restrict OpenSearch access policies to trusted principals and private networking."))
		}
	}
	return out, nil
}

func evalPublicEKSProd(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type == "aws_eks_cluster" && envFromChange(change) == "production" && truthy(change.After["endpoint_public_access"]) {
			out = append(out, finding(meta, change.Address, change.Provider, "production", []model.Evidence{ev(change.Address, "endpoint_public_access", true, "production EKS public endpoint is enabled")}, "Disable public endpoint access or restrict public access CIDRs."))
		}
	}
	return out, nil
}

func evalS3PublicAccessBlockDisabledProd(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	keys := []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_s3_bucket_public_access_block" || envFromChange(change) != "production" {
			continue
		}
		for _, key := range keys {
			if value, ok := change.After[key]; ok && !truthy(value) {
				out = append(out, finding(meta, change.Address, change.Provider, "production", []model.Evidence{ev(change.Address, key, value, "production S3 public access block protection is disabled")}, "Enable all S3 public access block protections for production buckets."))
				break
			}
		}
	}
	return out, nil
}

func evalCloudFrontS3PublicMismatch(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	if input.Graph == nil {
		return nil, nil
	}
	hasCloudFront := hasResourceType(input.Graph, "aws_cloudfront_distribution")
	if !hasCloudFront {
		return nil, nil
	}
	out := make([]model.Finding, 0)
	for id, node := range sortedNodes(input.Graph) {
		if node.Type == "aws_s3_bucket" && input.Graph.IsInternetExposed(id) {
			out = append(out, finding(meta, node.Address, node.Provider, node.Environment, []model.Evidence{ev(node.Address, "graph", "cloudfront+s3", "bucket is public while CloudFront exists in the same change graph")}, "Use CloudFront origin access control and make the bucket private."))
		}
	}
	return out, nil
}

func evalPassRoleWithComputeMutation(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	if input.Graph == nil {
		return nil, nil
	}
	computeMutating := hasAnyChangedType(input.Plan, "aws_lambda_function", "aws_ecs_service", "aws_instance", "aws_launch_template")
	if !computeMutating {
		return nil, nil
	}
	out := make([]model.Finding, 0)
	for id, node := range sortedNodes(input.Graph) {
		if !strings.HasPrefix(node.Type, "aws_iam_") {
			continue
		}
		for _, edge := range input.Graph.OutgoingEdges(id) {
			if edge.Type == graph.EdgeCanPassRole {
				out = append(out, finding(meta, node.Address, node.Provider, node.Environment, append(edge.Evidence, ev(node.Address, "plan", "compute mutation", "same plan mutates compute resources")), "Separate iam:PassRole grants from compute mutation or scope passable roles tightly."))
			}
		}
	}
	return out, nil
}

func evalIAMWildcardAdmin(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_iam_policy" && change.Type != "aws_iam_role_policy" && change.Type != "aws_iam_user_policy" && change.Type != "aws_iam_group_policy" {
			continue
		}
		text := normalizePolicyText(asString(change.After["policy"]) + asJSON(change.After))
		if strings.Contains(text, `"action":"*"`) || strings.Contains(text, `"action":["*"`) || strings.Contains(text, "iam:*") {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "policy", "(policy)", "IAM policy grants wildcard administrative actions")}, "Replace wildcard IAM actions with least-privilege actions and scoped resources."))
		}
	}
	return out, nil
}

func evalRoleAssumeAdminPath(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	if input.Graph == nil {
		return nil, nil
	}
	out := make([]model.Finding, 0)
	adminRoles := adminRoleIDs(input.Graph)
	for id, node := range sortedNodes(input.Graph) {
		if !strings.HasPrefix(node.Type, "aws_iam_") {
			continue
		}
		for _, role := range adminRoles {
			if input.Graph.CanAssumeRole(id, role) {
				out = append(out, finding(meta, node.Address, node.Provider, node.Environment, []model.Evidence{ev(node.Address, "graph", role, "principal can assume admin role")}, "Remove the assume-role path or require a tightly scoped break-glass workflow."))
			}
		}
	}
	return out, nil
}

func evalAdminPolicyAttachment(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if strings.Contains(change.Type, "policy_attachment") && strings.Contains(asString(change.After["policy_arn"]), "AdministratorAccess") {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "policy_arn", change.After["policy_arn"], "AdministratorAccess policy is attached")}, "Use least-privilege policies and require explicit approval for administrator access."))
		}
	}
	return out, nil
}

func evalExternalAccountTrust(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_iam_role" {
			continue
		}
		policy := asString(change.After["assume_role_policy"])
		if strings.Contains(policy, "arn:aws:iam::") && !strings.Contains(policy, ":123456789012:") && strings.Contains(strings.ToLower(policy), "sts:assumerole") {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "assume_role_policy", "external account", "trust policy allows external account assumption")}, "Constrain external trust with external IDs, exact principals, and conditions."))
		}
	}
	return out, nil
}

func evalGithubOIDCBroad(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	return policyTextFindings(input, meta, []string{"aws_iam_role"}, []string{"token.actions.githubusercontent.com", "repo:*"}, "assume_role_policy", "GitHub OIDC trust is too broad", "Constrain GitHub OIDC trust to exact organization, repository, and branch claims."), nil
}

func evalKMSDecryptBroad(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_iam_policy" && change.Type != "aws_iam_role_policy" && change.Type != "aws_kms_key" {
			continue
		}
		text := normalizePolicyText(asString(change.After["policy"]) + asJSON(change.After))
		if strings.Contains(text, "kms:decrypt") && (strings.Contains(text, `"resource":"*"`) || strings.Contains(text, `"principal":"*"`)) {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "policy", "(policy)", "KMS decrypt is granted broadly")}, "Scope kms:Decrypt to exact keys and principals. If this is a key policy, remove public principals."))
		}
	}
	return out, nil
}

func evalSecretsReadBroad(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	return policyTextFindings(input, meta, []string{"aws_iam_policy", "aws_iam_role_policy"}, []string{"secretsmanager:getsecretvalue", `"Resource":"*"`}, "policy", "Secrets Manager read access is granted broadly", "Scope Secrets Manager read access to exact secrets and principals."), nil
}

func evalRDSReplacementProd(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if isRDS(change.Type) && isReplacement(change) && envFromChange(change) == "production" {
			out = append(out, finding(meta, change.Address, change.Provider, "production", []model.Evidence{ev(change.Address, "actions", change.Actions, "production database will be replaced")}, "Review replacement cause and require manual approval before apply."))
		}
	}
	return out, nil
}

func evalStatefulReplacement(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	stateful := map[string]bool{"aws_db_instance": true, "aws_rds_cluster": true, "aws_efs_file_system": true, "aws_elasticache_cluster": true, "aws_dynamodb_table": true}
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if stateful[change.Type] && isReplacement(change) {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "actions", change.Actions, "stateful resource will be replaced")}, "Review stateful replacement, snapshot data, and require approval before apply."))
		}
	}
	return out, nil
}

func evalPublicToSensitiveDatastore(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	if input.Graph == nil {
		return nil, nil
	}
	out := make([]model.Finding, 0)
	for id, node := range sortedNodes(input.Graph) {
		if !input.Graph.IsInternetExposed(id) {
			continue
		}
		for targetID, target := range sortedNodes(input.Graph) {
			if !isSensitiveNode(target) {
				continue
			}
			if id == targetID {
				continue
			}
			path, ok := firstHighConfidencePath(input.Graph, id, targetID)
			if !ok || !pathHasWorkload(input.Graph, path) {
				continue
			}
			out = append(out, finding(meta, node.Address, node.Provider, node.Environment, graphPathEvidence(node.Address, target.Address, path), "Break the public-to-sensitive path with private networking, scoped security groups, or service isolation."))
		}
	}
	return out, nil
}

func evalSensitiveStorageEncryptionDisabled(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if !statefulType(change.Type) {
			continue
		}
		if encryptionDisabled(change.After) {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "encryption", "disabled", "sensitive storage encryption is disabled")}, "Enable encryption at rest with a managed or customer-managed KMS key."))
		}
	}
	return out, nil
}

func evalRDSBackupRetentionDisabledProd(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if isRDS(change.Type) && envFromChange(change) == "production" && intValue(change.After["backup_retention_period"]) == 0 {
			out = append(out, finding(meta, change.Address, change.Provider, "production", []model.Evidence{ev(change.Address, "backup_retention_period", 0, "production database backup retention is disabled")}, "Set backup retention to a non-zero period aligned with recovery requirements."))
		}
	}
	return out, nil
}

func evalRDSDeletionProtectionDisabledProd(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if isRDS(change.Type) && envFromChange(change) == "production" && !truthy(change.After["deletion_protection"]) {
			out = append(out, finding(meta, change.Address, change.Provider, "production", []model.Evidence{ev(change.Address, "deletion_protection", false, "production database deletion protection is disabled")}, "Enable deletion protection for production databases."))
		}
	}
	return out, nil
}

func evalS3SensitiveLoggingDisabled(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	hasLogging := make(map[string]bool)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type == "aws_s3_bucket_logging" {
			hasLogging[asString(change.After["bucket"])] = true
		}
	}
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type == "aws_s3_bucket" && isSensitiveBucket(change) && !hasLogging[asString(change.After["bucket"])] && !hasLogging[change.Name] {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "logging", "missing", "sensitive bucket has no access logging resource in plan")}, "Enable S3 server access logging or equivalent object access audit logging."))
		}
	}
	return out, nil
}

func evalPrivateSubnetRouteToIGW(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if (change.Type == "aws_route" || change.Type == "aws_route_table") && asString(change.After["gateway_id"]) != "" && strings.Contains(asString(change.After["gateway_id"]), "igw") && strings.Contains(strings.ToLower(change.Address), "private") {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "gateway_id", change.After["gateway_id"], "private route points to internet gateway")}, "Do not route private subnet route tables directly to an internet gateway."))
		}
	}
	return out, nil
}

func evalPrivateWorkloadExposedByNATOrSG(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		text := strings.ToLower(change.Address + " " + fmt.Sprint(change.Tags) + " " + asJSON(change.After["tags"]))
		privateContext := strings.Contains(text, "private") || strings.Contains(text, "internal") || strings.Contains(text, "prod")
		if !privateContext {
			continue
		}
		if (change.Type == "aws_security_group" || change.Type == "aws_vpc_security_group_ingress_rule") && publicCIDRInChange(change) {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "ingress", "0.0.0.0/0", "private workload security boundary now allows public ingress")}, "Keep private workloads behind internal load balancers and trusted security group sources."))
		}
		if change.Type == "aws_route" && strings.Contains(asString(change.After["nat_gateway_id"]), "nat-") && strings.Contains(asString(change.After["destination_cidr_block"]), "0.0.0.0/0") {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "nat_gateway_id", change.After["nat_gateway_id"], "private workload route opens broad internet egress through NAT")}, "Restrict private workload egress through explicit destinations or controlled proxy paths."))
		}
	}
	return out, nil
}

func evalTGWRouteToSensitiveSubnet(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if change.Type != "aws_route" && change.Type != "aws_route_table" {
			continue
		}
		text := strings.ToLower(change.Address + " " + fmt.Sprint(change.Tags) + " " + asJSON(change.After["tags"]))
		if !(strings.Contains(text, "sensitive") || strings.Contains(text, "private") || strings.Contains(text, "prod")) {
			continue
		}
		if asString(change.After["transit_gateway_id"]) != "" || asString(change.After["vpc_peering_connection_id"]) != "" {
			out = append(out, finding(meta, change.Address, change.Provider, envFromChange(change), []model.Evidence{ev(change.Address, "route_target", change.After, "route expands access to sensitive/private network through TGW or peering")}, "Review route propagation and restrict transit/peering routes to required CIDRs only."))
		}
	}
	return out, nil
}

func evalSensitiveWorkloadOpenEgress(_ context.Context, input RuleInput, meta Metadata) ([]model.Finding, error) {
	out := make([]model.Finding, 0)
	for _, change := range sortedChanges(input.Plan) {
		if (change.Type == "aws_security_group" || change.Type == "aws_vpc_security_group_egress_rule") && envFromChange(change) == "production" && strings.Contains(asJSON(change.After["egress"]), "0.0.0.0/0") {
			out = append(out, finding(meta, change.Address, change.Provider, "production", []model.Evidence{ev(change.Address, "egress", "0.0.0.0/0", "production security group opens egress to the internet")}, "Restrict egress to required destinations or use controlled NAT/proxy paths."))
		}
	}
	return out, nil
}
