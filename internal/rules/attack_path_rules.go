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
	return generatedAttackPathRule{meta: Metadata{
		ID:           id,
		Title:        title,
		Description:  desc,
		Category:     category,
		Severity:     severity,
		Confidence:   confidence,
		Providers:    []string{"aws"},
		Resources:    []string{"aws_lb", "aws_ecs_service", "aws_lambda_function", "aws_iam_role", "aws_iam_policy", "aws_db_instance", "aws_secretsmanager_secret"},
		Capabilities: []Capability{CapabilityGraph},
		Status:       StatusStable,
		Version:      "0.1.0",
		PolicyPack:   pack,
		Documentation: Documentation{
			Summary: desc,
			Remediation: []string{
				"Break the attack path by removing public exposure, sensitive reachability, or privilege escalation permissions.",
				"Scope IAM and network access to the minimum required resources.",
			},
			References: []string{"docs/attack-paths.md"},
		},
	}}
}
