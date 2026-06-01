package compliance

import (
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
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
	if report.Summary["soc2"] != 1 || report.Summary["iso_27001"] != 1 {
		t.Fatalf("expected SOC 2 and ISO summaries: %+v", report.Summary)
	}
}

func TestDefaultMappingsCoverStableAWSRules(t *testing.T) {
	t.Parallel()

	registry, err := rules.DefaultRegistry()
	if err != nil {
		t.Fatalf("default registry: %v", err)
	}
	mappings := defaultMappings()
	for _, rule := range registry.Rules() {
		meta := rule.Metadata()
		if meta.PolicyPack != "aws-core" && meta.PolicyPack != "aws-public-exposure" && meta.PolicyPack != "aws-iam-escalation" {
			continue
		}
		if _, ok := mappings[meta.ID]; !ok {
			t.Fatalf("missing compliance mapping for %s", meta.ID)
		}
	}
}

func TestBuildReportWithCustomMappings(t *testing.T) {
	t.Parallel()

	finding := model.NormalizeFinding(model.Finding{
		RuleID:          "ORG_QUEUE_REVIEW",
		Title:           "Queue review",
		ResourceAddress: "aws_sqs_queue.jobs",
		Category:        model.RiskCategoryCompliance,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
	})
	report := BuildReportWithMappings([]model.Finding{finding}, map[string]map[string][]string{
		"ORG_QUEUE_REVIEW": {
			"soc2": {"CC8.1"},
		},
	})
	if len(report.Findings) != 1 {
		t.Fatalf("mapped findings = %d, want 1", len(report.Findings))
	}
	if got := report.Findings[0].Frameworks["soc2"]; len(got) != 1 || got[0] != "CC8.1" {
		t.Fatalf("custom mapping not applied: %#v", report.Findings[0].Frameworks)
	}
}
