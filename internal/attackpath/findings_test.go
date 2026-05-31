package attackpath

import (
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestFindingsApplyPolicyThresholds(t *testing.T) {
	t.Parallel()

	paths := []AttackPath{
		{
			Type:       TypePublicToSensitiveData,
			Title:      "public path",
			Severity:   model.SeverityCritical,
			Confidence: model.ConfidenceHigh,
			Decision:   model.DecisionBlock,
			Entrypoint: "aws_lb.admin",
			Target:     "aws_db_instance.customer",
		},
		{
			Type:       TypeIAMPrivilegeEscalation,
			Title:      "medium IAM path",
			Severity:   model.SeverityHigh,
			Confidence: model.ConfidenceMedium,
			Decision:   model.DecisionWarn,
			Principal:  "aws_iam_role.deploy",
			Target:     "aws_iam_role.admin",
			Steps:      []Step{{Action: "sts:AssumeRole", From: "aws_iam_role.deploy", To: "aws_iam_role.admin"}},
		},
	}
	policy := model.AttackPathPolicy{
		Enabled: true,
		Block: []model.AttackPathThreshold{
			{Type: string(TypePublicToSensitiveData), MinConfidence: model.ConfidenceHigh},
		},
		Warn: []model.AttackPathThreshold{
			{Type: string(TypeIAMPrivilegeEscalation), MinConfidence: model.ConfidenceMedium},
		},
	}

	findings := Findings(paths, policy)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].Fingerprint == "" || findings[1].Fingerprint == "" {
		t.Fatalf("findings were not normalized: %#v", findings)
	}
	if !hasRule(findings, RulePublicToSensitiveDataPath) {
		t.Fatalf("missing %s in %#v", RulePublicToSensitiveDataPath, findings)
	}
	if !hasRule(findings, RuleIAMAssumeAdminPath) {
		t.Fatalf("missing %s in %#v", RuleIAMAssumeAdminPath, findings)
	}
}

func TestFindingsRespectDisabledPolicy(t *testing.T) {
	t.Parallel()

	findings := Findings([]AttackPath{{
		Type:       TypePublicToSensitiveData,
		Title:      "public path",
		Severity:   model.SeverityCritical,
		Confidence: model.ConfidenceHigh,
		Decision:   model.DecisionBlock,
		Entrypoint: "aws_lb.admin",
		Target:     "aws_db_instance.customer",
	}}, model.AttackPathPolicy{Enabled: false})
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

func hasRule(findings []model.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
