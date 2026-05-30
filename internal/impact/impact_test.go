package impact

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
)

func TestBuildStatementGolden(t *testing.T) {
	t.Parallel()

	statement, err := Build(sampleReport(), Options{GeneratedAt: fixedTime()})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	assertNoSensitiveLeaks(t, body)
	assertGolden(t, "statement.json", string(body)+"\n")
}

func TestBuildStatementRedactsSensitiveEvidence(t *testing.T) {
	t.Parallel()

	report := sampleReport()
	secretFinding := impactFinding("AWS_SECRETS_READ_BROAD", "aws_iam_policy.reader", model.RiskCategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh, []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold})
	secretFinding.Evidence = []model.Evidence{
		{
			Type:     "secret_arn",
			Resource: secretFinding.ResourceAddress,
			Path:     "policy.Statement[0].Resource",
			Value:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-password-AbCd",
			Message:  "Policy references a secret ARN.",
		},
		{
			Type:     "policy_document",
			Resource: secretFinding.ResourceAddress,
			Path:     "policy",
			Value:    `{"Statement":[{"Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:123456789012:secret:db-password-AbCd"}]}`,
			Message:  "Policy document grants secret access.",
		},
	}
	report.Findings = append(report.Findings, secretFinding)
	statement, err := Build(report, Options{GeneratedAt: fixedTime()})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	assertNoSensitiveLeaks(t, body)
	if !bytes.Contains(body, []byte(`"(sensitive)"`)) {
		t.Fatalf("redacted marker missing:\n%s", string(body))
	}
}

func TestSortFindingsUsesSeverityConfidenceDecisionImpactResourceAndRule(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		impactFinding("AWS_Z", "aws_security_group.z", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceMedium, nil),
		impactFinding("AWS_A", "aws_security_group.a", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, []model.DecisionReasonCode{model.ReasonBelowBlockThreshold}),
		impactFinding("AWS_B", "aws_security_group.b", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}),
		impactFinding("AWS_CRITICAL", "aws_security_group.c", model.RiskCategoryPublicExposure, model.SeverityCritical, model.ConfidenceLow, nil),
	}
	SortFindings(findings)

	got := []string{findings[0].RuleID, findings[1].RuleID, findings[2].RuleID, findings[3].RuleID}
	want := []string{"AWS_CRITICAL", "AWS_B", "AWS_A", "AWS_Z"}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("sorted[%d] = %s, want %s; full order=%v", index, got[index], want[index], got)
		}
	}
}

func sampleReport() output.Report {
	publicFinding := model.NormalizeFinding(model.Finding{
		RuleID:          "AWS_PUBLIC_ADMIN_SERVICE",
		RuleName:        "Public admin service",
		PolicyPack:      "aws-public-exposure",
		Title:           "Public admin service reaches customer data",
		Description:     "The admin load balancer can reach a sensitive datastore.",
		ResourceAddress: "aws_lb.admin",
		Provider:        "aws",
		Environment:     "prod",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
		Evidence: []model.Evidence{
			{
				Type:     "graph_path",
				Resource: "aws_lb.admin",
				Path:     "graph.path",
				Value:    []string{"internet", "aws_lb.admin", "aws_ecs_service.admin", "aws_db_instance.customer"},
				Message:  "Public entrypoint routes to an admin workload and customer database.",
			},
			{
				Type:      "attribute",
				Resource:  "aws_lb.admin",
				Path:      "tags.secret",
				Value:     "super-secret-token",
				Message:   "Sensitive tag value was redacted.",
				Sensitive: true,
			},
		},
		Remediation: model.Remediation{OwnerHints: []string{"platform-security"}},
	})
	publicFinding.Remediation.OwnerHints = []string{"platform-security"}
	publicFinding.DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}
	publicFinding.DecisionReasons = []model.DecisionReason{{
		FindingID: publicFinding.ID,
		Resource:  publicFinding.ResourceAddress,
		Code:      model.ReasonMeetsBlockThreshold,
		Reason:    "high severity and high confidence meets block threshold",
	}}

	iamFinding := model.NormalizeFinding(model.Finding{
		RuleID:          "AWS_PASSROLE_WITH_COMPUTE_MUTATION",
		Title:           "Deploy role can pass privileged role and mutate compute",
		ResourceAddress: "aws_iam_role.deploy",
		Provider:        "aws",
		Category:        model.RiskCategoryPrivilegeEscalation,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
		Evidence: []model.Evidence{
			{Type: "iam", Resource: "aws_iam_role.deploy", Path: "policy.Statement[0].Action", Value: []any{"iam:PassRole", "lambda:UpdateFunctionCode"}, Message: "Policy allows PassRole and function code mutation."},
		},
	})
	iamFinding.DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}

	existingFinding := impactFinding("AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD", "aws_s3_bucket.logs", model.RiskCategorySensitiveData, model.SeverityMedium, model.ConfidenceHigh, []model.DecisionReasonCode{model.ReasonExistingRisk})
	existingFinding.Suppressions = []model.Suppression{{Kind: "existing_risk", Reason: "finding fingerprint exists in baseline", Active: true}}

	waivedFinding := impactFinding("AWS_PUBLIC_RDS_INSTANCE", "aws_db_instance.legacy", model.RiskCategorySensitiveData, model.SeverityHigh, model.ConfidenceHigh, []model.DecisionReasonCode{model.ReasonSuppressed})
	waivedFinding.Suppressions = []model.Suppression{{Kind: "waiver", Reason: "approved migration exception", Active: true}}

	findings := []model.Finding{existingFinding, publicFinding, waivedFinding, iamFinding}
	return output.Report{
		SchemaVersion: output.ReportSchemaVersion,
		Decision:      model.DecisionBlock,
		Plan: output.PlanSummary{
			Path:          "tfplan.json",
			Tool:          model.ToolTerraform,
			FormatVersion: "1.0",
			Resources:     9,
			Changes:       4,
		},
		Graph:       output.GraphSummary{Nodes: 9, Edges: 12},
		RiskSummary: model.BuildRiskSummary(findings, model.DefaultPolicyConfig()),
		ReasonCodes: []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold},
		Reasons: []model.DecisionReason{{
			FindingID: publicFinding.ID,
			Resource:  publicFinding.ResourceAddress,
			Code:      model.ReasonMeetsBlockThreshold,
			Reason:    "finding meets block threshold",
		}},
		Findings: findings,
		Diagnostics: []model.Diagnostic{{
			Severity: model.DiagnosticWarning,
			Code:     "TEST_DIAGNOSTIC",
			Message:  "test warning",
		}},
	}
}

func impactFinding(ruleID string, resource string, category model.RiskCategory, severity model.Severity, confidence model.Confidence, reasons []model.DecisionReasonCode) model.Finding {
	finding := model.NormalizeFinding(model.Finding{
		RuleID:          ruleID,
		Title:           ruleID,
		ResourceAddress: resource,
		Provider:        "aws",
		Category:        category,
		Severity:        severity,
		Confidence:      confidence,
		Evidence: []model.Evidence{{
			Type:     "attribute",
			Resource: resource,
			Path:     "example",
			Value:    "safe",
			Message:  "example evidence",
		}},
	})
	finding.DecisionReasonCodes = append([]model.DecisionReasonCode(nil), reasons...)
	return finding
}

func fixedTime() time.Time {
	return time.Date(2026, 5, 30, 16, 0, 0, 0, time.UTC)
}

func assertGolden(t *testing.T, name string, got string) {
	t.Helper()

	path := filepath.Join("testdata", "golden", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if string(want) != got {
		t.Fatalf("golden mismatch for %s\nwant:\n%s\ngot:\n%s", name, string(want), got)
	}
}

func assertNoSensitiveLeaks(t *testing.T, body []byte) {
	t.Helper()

	for _, needle := range [][]byte{
		[]byte("super-secret-token"),
		[]byte("plain-secret-value"),
		[]byte("db-password"),
		[]byte("PRIVATE KEY"),
	} {
		if bytes.Contains(body, needle) {
			t.Fatalf("impact statement leaked sensitive value %q:\n%s", string(needle), string(body))
		}
	}
}
