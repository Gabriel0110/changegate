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

func TestPublicToSensitiveFindingCarriesStableBaselineContext(t *testing.T) {
	t.Parallel()

	left := AttackPath{
		Type:             TypePublicToSensitiveData,
		Kind:             PathKindNetwork,
		Title:            "public path",
		Severity:         model.SeverityCritical,
		Confidence:       model.ConfidenceHigh,
		ConfidenceReason: "path confidence is based on plan graph evidence",
		Decision:         model.DecisionBlock,
		Entrypoint:       "aws_lb.admin",
		Target:           "aws_db_instance.customer",
		Evidence: []model.Evidence{{
			Type:     "attack_path.graph_path",
			Resource: "aws_db_instance.customer",
			Path:     "graph.path",
			Value:    []string{"internet", "aws_lb.admin", "aws_ecs_service.admin", "aws_db_instance.customer"},
			Message:  "public entrypoint reaches sensitive asset",
		}},
		Steps: []Step{{
			From:        "aws_lb.admin",
			To:          "aws_ecs_service.admin",
			Action:      "routes to",
			Explanation: "load balancer routes to workload",
		}},
	}
	right := left
	right.ConfidenceReason = "path confidence is based on mixed graph evidence"
	right.Evidence[0].Message = "cloud context confirmed path to sensitive asset"

	findings := Findings([]AttackPath{left, right}, model.DefaultAttackPathPolicy())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Fingerprint == "" {
		t.Fatalf("finding fingerprint was empty: %#v", findings[0])
	}
	if !model.RiskContextFromFinding(findings[0]).GraphSensitiveData {
		t.Fatalf("public-to-sensitive attack path finding did not expose graph-sensitive movement context: %#v", findings[0].Evidence)
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
