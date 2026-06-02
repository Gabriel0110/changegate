package attackpath

import (
	"fmt"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
)

const (
	// RulePublicToSensitiveDataPath identifies public-to-sensitive-data attack path findings.
	RulePublicToSensitiveDataPath = "AWS_PUBLIC_TO_SENSITIVE_DATA_PATH"
	// RuleIAMPassRoleFunctionEscalation identifies pass-role plus compute mutation attack paths.
	RuleIAMPassRoleFunctionEscalation = "AWS_IAM_PASSROLE_FUNCTION_ESCALATION"
	// RuleIAMAssumeAdminPath identifies assume-role paths to admin or sensitive roles.
	RuleIAMAssumeAdminPath = "AWS_IAM_ASSUME_ADMIN_PATH"
	// RulePublicAdminServicePath identifies public admin workload paths without sensitive downstream context.
	RulePublicAdminServicePath = "AWS_PUBLIC_ADMIN_SERVICE_PATH"
)

// Findings converts attack paths into normal findings for policy, baseline, waiver, and review flows.
func Findings(paths []AttackPath, policy model.AttackPathPolicy) []model.Finding {
	if !policy.Enabled {
		return nil
	}
	paths = Normalize(paths)
	out := make([]model.Finding, 0, len(paths))
	for _, path := range paths {
		if !attackPathAllowed(path, policy) {
			continue
		}
		out = append(out, model.NormalizeFinding(findingFromPath(path)))
	}
	return out
}

func attackPathAllowed(path AttackPath, policy model.AttackPathPolicy) bool {
	for _, threshold := range policy.Block {
		if threshold.Type == string(path.Type) && confidenceMeets(path.Confidence, threshold.MinConfidence) {
			return true
		}
	}
	for _, threshold := range policy.Warn {
		if threshold.Type == string(path.Type) && confidenceMeets(path.Confidence, threshold.MinConfidence) {
			return true
		}
	}
	return false
}

func findingFromPath(path AttackPath) model.Finding {
	ruleID, title, category := ruleForPath(path)
	resource := path.Target
	if resource == "" {
		resource = path.Entrypoint
	}
	if resource == "" {
		resource = path.Principal
	}
	evidence := append([]model.Evidence{
		{
			Type:     "attack_path",
			Resource: resource,
			Path:     "attack_path.id",
			Value:    path.ID,
			Message:  fmt.Sprintf("attack path %s produced %s decision", path.ID, path.Decision),
		},
		{
			Type:     "attack_path",
			Resource: resource,
			Path:     "attack_path.type",
			Value:    string(path.Type),
			Message:  "attack path type is " + string(path.Type),
		},
		{
			Type:     "attack_path",
			Resource: resource,
			Path:     "attack_path.kind",
			Value:    string(path.Kind),
			Message:  "attack path kind is " + string(path.Kind),
		},
		{
			Type:     "attack_path",
			Resource: resource,
			Path:     "attack_path.confidence_reason",
			Value:    path.ConfidenceReason,
			Message:  path.ConfidenceReason,
		},
	}, path.Evidence...)
	if path.Source != "" {
		evidence = append(evidence, model.Evidence{
			Type:     "attack_path",
			Resource: resource,
			Path:     "attack_path.source",
			Value:    string(path.Source),
			Message:  "attack path source is " + string(path.Source),
		})
	}
	if len(path.AffectedResources) > 0 {
		evidence = append(evidence, model.Evidence{
			Type:     "attack_path",
			Resource: resource,
			Path:     "attack_path.affected_resources",
			Value:    affectedResourceValues(path.AffectedResources),
			Message:  "attack path affected resources are linked to this finding",
		})
	}
	for _, step := range path.Steps {
		evidence = append(evidence, model.Evidence{
			Type:     "attack_path.step",
			Resource: resource,
			Path:     step.Action,
			Value:    []string{step.From, step.To},
			Message:  step.Explanation,
		})
	}
	reason := fmt.Sprintf("attack path %s meets %s/%s threshold", path.ID, path.Severity, path.Confidence)
	return model.Finding{
		RuleID:            ruleID,
		RuleName:          title,
		PolicyPack:        policyPackForCategory(category),
		PolicyPackVersion: "0.1.0",
		Title:             path.Title,
		Description:       "ChangeGate detected a high-signal infrastructure attack path.",
		ResourceAddress:   resource,
		Category:          category,
		Severity:          path.Severity,
		Confidence:        path.Confidence,
		Evidence:          evidence,
		Remediation: model.Remediation{
			Summary:      firstNonEmpty(path.Mitigations, "Break the attack path or reduce the permissions/exposure that create it."),
			Steps:        append([]string(nil), path.Mitigations...),
			References:   append([]string(nil), path.References...),
			WhyThisWorks: "Removing any required step breaks the attack path before deployment.",
		},
		DecisionReasons: []model.DecisionReason{{
			Resource: resource,
			Policy:   policyPackForCategory(category),
			Reason:   reason,
		}},
	}
}

func affectedResourceValues(resources []AffectedResource) []string {
	out := make([]string, 0, len(resources))
	for _, resource := range resources {
		if resource.Resource == "" {
			continue
		}
		value := resource.Resource
		if resource.Role != "" {
			value += ":" + resource.Role
		}
		out = append(out, value)
	}
	return out
}

func ruleForPath(path AttackPath) (string, string, model.RiskCategory) {
	switch path.Type {
	case TypePublicToSensitiveData:
		if path.Decision == model.DecisionWarn && !strings.Contains(strings.ToLower(path.Target), "db") && !strings.Contains(strings.ToLower(path.Target), "secret") {
			return RulePublicAdminServicePath, "Public admin service attack path", model.RiskCategoryPublicExposure
		}
		return RulePublicToSensitiveDataPath, "Public to sensitive data attack path", model.RiskCategorySensitiveData
	case TypeIAMPrivilegeEscalation:
		if pathHasAction(path, "sts:AssumeRole") {
			return RuleIAMAssumeAdminPath, "IAM assume admin attack path", model.RiskCategoryPrivilegeEscalation
		}
		return RuleIAMPassRoleFunctionEscalation, "IAM pass-role function escalation path", model.RiskCategoryPrivilegeEscalation
	default:
		return "AWS_ATTACK_PATH", "AWS attack path", model.RiskCategoryUnknown
	}
}

func pathHasAction(path AttackPath, action string) bool {
	for _, step := range path.Steps {
		if strings.EqualFold(step.Action, action) {
			return true
		}
	}
	return false
}

func policyPackForCategory(category model.RiskCategory) string {
	switch category {
	case model.RiskCategoryPrivilegeEscalation:
		return "aws-iam-escalation"
	default:
		return "aws-public-exposure"
	}
}

func confidenceMeets(current model.Confidence, minimum model.Confidence) bool {
	return confidenceRank(current) >= confidenceRank(minimum)
}

func firstNonEmpty(values []string, fallback string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return fallback
}
