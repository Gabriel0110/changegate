package rules

import (
	"context"

	"github.com/Gabriel0110/changegate/internal/attackpath"
	"github.com/Gabriel0110/changegate/internal/model"
)

func attackPathRules() []Rule {
	return []Rule{
		staticAttackPathRule(attackpath.RulePublicToSensitiveDataPath, "Public path reaches sensitive data", "Detects a graph-backed public entrypoint to sensitive data attack path.", model.RiskCategorySensitiveData, model.SeverityCritical, model.ConfidenceHigh, "aws-public-exposure"),
		staticAttackPathRule(attackpath.RuleIAMPassRoleFunctionEscalation, "IAM pass-role function escalation path", "Detects iam:PassRole combined with Lambda or ECS compute mutation.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation"),
		staticAttackPathRule(attackpath.RuleIAMAssumeAdminPath, "IAM assume admin path", "Detects sts:AssumeRole paths to administrator or sensitive roles.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation"),
		staticAttackPathRule(attackpath.RulePublicAdminServicePath, "Public admin service path", "Detects public entrypoints reaching admin-like workloads without sensitive downstream context.", model.RiskCategoryPublicExposure, model.SeverityMedium, model.ConfidenceMedium, "aws-public-exposure"),
		staticAttackPathRule(attackpath.RulePublicEKSClusterAdminPath, "Public EKS cluster-admin attack path", "Detects public EKS control-plane exposure with graph evidence of cluster-admin or privileged role access.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation"),
		staticAttackPathRule(attackpath.RuleIAMPolicyMutationEscalation, "IAM policy mutation escalation path", "Detects IAM policy mutation permissions that can create or promote privileged access.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation"),
		staticAttackPathRule(attackpath.RuleIAMBroadNotActionEscalation, "IAM NotAction escalation path", "Detects broad NotAction allow semantics that imply privilege-escalation permissions.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceMedium, "aws-iam-escalation"),
		staticAttackPathRule(attackpath.RuleIAMRoleAssumptionChain, "IAM role assumption chain", "Detects multi-hop role assumption paths to administrator or sensitive roles.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation"),
		staticAttackPathRule(attackpath.RuleIAMPathfindingCatalogEscalation, "Pathfinding.cloud IAM escalation path", "Detects IAM privilege-escalation prerequisites from the embedded Datadog pathfinding.cloud catalog.", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, "aws-iam-escalation"),
	}
}

type generatedAttackPathRule struct {
	meta Metadata
}

func (r generatedAttackPathRule) Metadata() Metadata {
	return r.meta
}

func (r generatedAttackPathRule) Evaluate(context.Context, RuleInput) ([]model.Finding, error) {
	return nil, nil
}

func staticAttackPathRule(id string, title string, desc string, category model.RiskCategory, severity model.Severity, confidence model.Confidence, pack string) Rule {
	resources := []string{"aws_lb", "aws_ecs_service", "aws_lambda_function", "aws_iam_role", "aws_iam_policy", "aws_db_instance", "aws_secretsmanager_secret"}
	remediation := []string{
		"Break the attack path by removing public exposure, sensitive reachability, or privilege escalation permissions.",
		"Scope IAM and network access to the minimum required resources.",
	}
	references := []string{"docs/attack-paths.md"}
	switch id {
	case attackpath.RuleIAMPathfindingCatalogEscalation:
		resources = []string{"aws_iam_role", "aws_iam_user", "aws_iam_policy", "aws_codebuild_project", "aws_ecs_service", "aws_lambda_function"}
		remediation = []string{
			"Remove or narrow the IAM actions required by the matched escalation path.",
			"Scope resources to exact non-privileged targets and add restrictive IAM conditions where supported.",
			"Restrict iam:PassRole to approved service roles and use iam:PassedToService conditions when pass-role is involved.",
		}
		references = []string{"docs/attack-paths.md", "https://pathfinding.cloud/paths/", "https://github.com/DataDog/pathfinding.cloud"}
	case attackpath.RuleIAMPolicyMutationEscalation, attackpath.RuleIAMBroadNotActionEscalation, attackpath.RuleIAMRoleAssumptionChain, attackpath.RuleIAMAssumeAdminPath, attackpath.RuleIAMPassRoleFunctionEscalation:
		resources = []string{"aws_iam_role", "aws_iam_user", "aws_iam_policy", "aws_lambda_function", "aws_ecs_service"}
	case attackpath.RulePublicEKSClusterAdminPath:
		resources = []string{"aws_eks_cluster", "aws_iam_role", "aws_iam_policy"}
	case attackpath.RulePublicAdminServicePath, attackpath.RulePublicToSensitiveDataPath:
		resources = []string{"aws_lb", "aws_api_gatewayv2_route", "aws_lambda_function_url", "aws_ecs_service", "aws_lambda_function", "aws_db_instance", "aws_secretsmanager_secret"}
	}
	return generatedAttackPathRule{meta: Metadata{
		ID:           id,
		Title:        title,
		Description:  desc,
		Category:     category,
		Severity:     severity,
		Confidence:   confidence,
		Providers:    []string{"aws"},
		Resources:    resources,
		Capabilities: []Capability{CapabilityGraph},
		Status:       StatusStable,
		Version:      "0.1.0",
		PolicyPack:   pack,
		Documentation: Documentation{
			Summary:     desc,
			Remediation: remediation,
			References:  references,
		},
	}}
}
