package output

import (
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestRenderMarkdownExternalScannerIntelligence(t *testing.T) {
	t.Parallel()

	report := Report{
		SchemaVersion: ReportSchemaVersion,
		Decision:      model.DecisionBlock,
		Plan:          PlanSummary{Path: "tfplan.json", Tool: model.ToolTerraform, FormatVersion: "1.2", Resources: 1, Changes: 1},
		Graph:         GraphSummary{Nodes: 1, Edges: 0},
		RiskSummary:   model.RiskSummary{Total: 1, Blocking: 1},
		Imports: &ImportSummary{
			Imported:           3,
			Retained:           1,
			Deduplicated:       2,
			SupersededByNative: 1,
			Correlated:         1,
			Downgraded:         1,
			BySource:           map[string]int{"checkov": 2, "sarif": 1},
			Insights: []ImportInsight{
				{
					Action:       "superseded_by_native",
					Source:       "checkov",
					RuleID:       "EXT_CHECKOV_CKV_AWS_20",
					Resource:     "aws_s3_bucket.logs",
					NativeRuleID: "AWS_S3_BUCKET_PUBLIC_POLICY",
					Reason:       "native ChangeGate finding covers the same resource and risk category with plan graph evidence",
				},
				{
					Action:   "downgraded",
					Source:   "sarif",
					RuleID:   "EXT_SARIF_X",
					Resource: "main.tf",
					Reason:   "imported finding did not correlate to a changed graph resource",
				},
			},
		},
		Findings: []model.Finding{
			model.NormalizeFinding(model.Finding{
				RuleID:          "AWS_S3_BUCKET_PUBLIC_POLICY",
				Title:           "S3 bucket has public policy",
				ResourceAddress: "aws_s3_bucket.logs",
				Provider:        "aws",
				Category:        model.RiskCategoryPublicExposure,
				Severity:        model.SeverityHigh,
				Confidence:      model.ConfidenceHigh,
			}),
		},
	}

	got := RenderMarkdown(report)
	for _, want := range []string{
		"## External scanner intelligence",
		"retained 1 after deduplication",
		"| `checkov` | 2 |",
		"`checkov` `superseded_by_native` `aws_s3_bucket.logs`",
		"(`AWS_S3_BUCKET_PUBLIC_POLICY`)",
		"`sarif` `downgraded` `main.tf`",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("markdown missing %q:\n%s", want, got)
		}
	}
}
