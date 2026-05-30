package compliance

import (
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestBuildReportMapsOnlyActualFindings(t *testing.T) {
	t.Parallel()

	finding := model.NormalizeFinding(model.Finding{
		RuleID:          "AWS_PUBLIC_RDS_INSTANCE",
		Title:           "Public RDS instance",
		ResourceAddress: "aws_db_instance.main",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
	})

	report := BuildReport([]model.Finding{finding})
	if len(report.Mappings) == 0 {
		t.Fatalf("expected default rule mappings")
	}
	if len(report.Findings) != 1 {
		t.Fatalf("mapped findings = %d, want 1", len(report.Findings))
	}
	mapped := report.Findings[0]
	if !mapped.ActualRisk {
		t.Fatalf("mapped finding should mark actual risk")
	}
	if mapped.Frameworks["nist_800_53"][0] != "AC-4" {
		t.Fatalf("unexpected NIST mapping: %+v", mapped.Frameworks["nist_800_53"])
	}
	if report.Summary["cis_aws"] != 1 {
		t.Fatalf("cis_aws summary = %d, want 1", report.Summary["cis_aws"])
	}
}
