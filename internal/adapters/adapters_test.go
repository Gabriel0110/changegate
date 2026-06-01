package adapters

import (
	"os"
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

func TestImportAdaptersNormalizeFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source Source
		body   string
		want   string
	}{
		{
			name:   "sarif",
			source: SourceSARIF,
			body:   `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"checkov","rules":[{"id":"CKV_AWS_1","name":"public bucket","properties":{"category":"public"}}]}},"results":[{"ruleId":"CKV_AWS_1","level":"error","message":{"text":"public bucket"},"properties":{"resource":"aws_s3_bucket.logs","severity":"HIGH"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.tf"},"region":{"startLine":7}}}]}]}]}`,
			want:   "EXT_SARIF_CKV_AWS_1",
		},
		{
			name:   "generic",
			source: SourceGeneric,
			body:   `{"findings":[{"rule_id":"CUSTOM_PUBLIC","title":"public thing","resource_address":"aws_lb.admin","category":"public","severity":"high","confidence":"high"}]}`,
			want:   "EXT_GENERIC_JSON_CUSTOM_PUBLIC",
		},
		{
			name:   "checkov",
			source: SourceCheckov,
			body:   `{"results":{"failed_checks":[{"check_id":"CKV_AWS_20","check_name":"S3 public access","resource":"aws_s3_bucket.logs","file_path":"main.tf","file_line_range":[3,5],"severity":"HIGH"}]}}`,
			want:   "EXT_CHECKOV_CKV_AWS_20",
		},
		{
			name:   "trivy",
			source: SourceTrivy,
			body:   `{"Results":[{"Target":"main.tf","Misconfigurations":[{"ID":"AVD-AWS-0086","Title":"bucket is public","Severity":"HIGH","CauseMetadata":{"Resource":"aws_s3_bucket.logs","StartLine":4}}]}]}`,
			want:   "EXT_TRIVY_AVD_AWS_0086",
		},
		{
			name:   "kics",
			source: SourceKICS,
			body:   `{"queries":[{"query_id":"abc","query_name":"security group allows public ingress","severity":"HIGH","category":"network","files":[{"file_name":"main.tf","resource_id":"aws_security_group.web","line":9}]}]}`,
			want:   "EXT_KICS_ABC",
		},
		{
			name:   "grype",
			source: SourceGrype,
			body:   `{"matches":[{"vulnerability":{"id":"CVE-2026-0001","severity":"High","description":"test"},"artifact":{"name":"openssl","type":"deb","version":"1.0","locations":[{"path":"/image"}]}}]}`,
			want:   "EXT_GRYPE_CVE_2026_0001",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := Import(tt.source, strings.NewReader(tt.body))
			if len(result.Diagnostics) > 0 {
				t.Fatalf("diagnostics = %#v", result.Diagnostics)
			}
			if len(result.Findings) != 1 {
				t.Fatalf("findings = %d, want 1", len(result.Findings))
			}
			got := result.Findings[0]
			if got.RuleID != tt.want {
				t.Fatalf("rule id = %q, want %q", got.RuleID, tt.want)
			}
			if got.PolicyPack != "external:"+string(tt.source) {
				t.Fatalf("policy pack = %q", got.PolicyPack)
			}
			if len(got.Evidence) == 0 || got.Evidence[0].Type != "external_scanner" {
				t.Fatalf("missing external scanner evidence: %#v", got.Evidence)
			}
		})
	}
}

func TestImportAdaptersParseRealScannerOutputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		source    Source
		path      string
		wantCount int
		wantRule  string
	}{
		{name: "checkov", source: SourceCheckov, path: "testdata/real/checkov-real.json", wantCount: 10, wantRule: "EXT_CHECKOV_CKV_AWS_18"},
		{name: "trivy", source: SourceTrivy, path: "testdata/real/trivy-real.json", wantCount: 11, wantRule: "EXT_TRIVY_AWS_0086"},
		{name: "kics", source: SourceKICS, path: "testdata/real/kics-real.json", wantCount: 11, wantRule: "EXT_KICS_381C3F2A_EF6F_4EFF_99F7_B169CDA3422C"},
		{name: "grype-empty", source: SourceGrype, path: "testdata/real/grype-real.json", wantCount: 0},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("read real scanner output: %v", err)
			}
			result := Import(tt.source, strings.NewReader(string(body)))
			if len(result.Diagnostics) > 0 {
				t.Fatalf("diagnostics = %#v", result.Diagnostics)
			}
			if len(result.Findings) != tt.wantCount {
				t.Fatalf("findings = %d, want %d", len(result.Findings), tt.wantCount)
			}
			if result.Summary.Imported != tt.wantCount || result.Summary.BySource[tt.source] != tt.wantCount {
				t.Fatalf("summary = %#v, want imported/by-source count %d", result.Summary, tt.wantCount)
			}
			if tt.wantRule != "" && !hasRuleID(result.Findings, tt.wantRule) {
				t.Fatalf("missing normalized rule %s in findings", tt.wantRule)
			}
			for _, finding := range result.Findings {
				if finding.ResourceAddress == "" || finding.Fingerprint == "" {
					t.Fatalf("finding missing normalized identity: %#v", finding)
				}
				if finding.PolicyPack != "external:"+string(tt.source) {
					t.Fatalf("policy pack = %q, want external:%s", finding.PolicyPack, tt.source)
				}
				if len(finding.Evidence) == 0 || finding.Evidence[0].Type != "external_scanner" {
					t.Fatalf("missing external scanner evidence: %#v", finding)
				}
			}
		})
	}
}

func TestMergeDeduplicatesAndCorrelatesImportedFindings(t *testing.T) {
	t.Parallel()

	native := model.NormalizeFinding(model.Finding{
		RuleID:          "AWS_PUBLIC_BUCKET",
		Title:           "public bucket",
		ResourceAddress: "aws_s3_bucket.logs",
		Provider:        "aws",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
	})
	importedDuplicate := model.NormalizeFinding(model.Finding{
		RuleID:          "EXT_CHECKOV_CKV_AWS_20",
		Title:           "public bucket",
		ResourceAddress: "aws_s3_bucket.logs",
		Provider:        "external",
		PolicyPack:      "external:checkov",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceMedium,
	})
	importedCorrelated := model.NormalizeFinding(model.Finding{
		RuleID:          "EXT_TRIVY_AVD_AWS_1",
		Title:           "encryption issue",
		ResourceAddress: "aws_lb.admin",
		Provider:        "external",
		PolicyPack:      "external:trivy",
		Category:        model.RiskCategorySensitiveData,
		Severity:        model.SeverityMedium,
		Confidence:      model.ConfidenceMedium,
	})
	importedUnknown := model.NormalizeFinding(model.Finding{
		RuleID:          "EXT_KICS_ABC",
		Title:           "uncorrelated",
		ResourceAddress: "aws_security_group.missing",
		Provider:        "external",
		PolicyPack:      "external:kics",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
	})
	resourceGraph := &graph.Graph{
		Nodes: map[graph.ResourceID]*graph.Node{
			graph.InternetNodeID: {ID: graph.InternetNodeID, Address: string(graph.InternetNodeID), Type: "internet", Synthetic: true},
			"aws_lb.admin":       {ID: "aws_lb.admin", Address: "aws_lb.admin", Type: "aws_lb"},
		},
		Edges: []graph.Edge{{From: graph.InternetNodeID, To: "aws_lb.admin", Type: graph.EdgeHasPublicAccess}},
	}

	merged, summary := Merge([]model.Finding{native}, []model.Finding{importedDuplicate, importedCorrelated, importedUnknown}, resourceGraph)
	if len(merged) != 3 {
		t.Fatalf("merged findings = %d, want 3", len(merged))
	}
	if summary.Imported != 3 || summary.Deduplicated != 1 || summary.Correlated != 1 || summary.Downgraded != 1 || summary.Upgraded != 1 {
		t.Fatalf("summary = %#v", summary)
	}
	if summary.BySource[SourceCheckov] != 1 || summary.BySource[SourceTrivy] != 1 || summary.BySource[SourceKICS] != 1 {
		t.Fatalf("by source = %#v", summary.BySource)
	}
}

func TestMergeDeduplicatesRepeatedImportedFindings(t *testing.T) {
	t.Parallel()

	imported := model.NormalizeFinding(model.Finding{
		RuleID:          "EXT_CHECKOV_CKV_AWS_20",
		Title:           "public bucket",
		ResourceAddress: "aws_s3_bucket.logs",
		Provider:        "external",
		PolicyPack:      "external:checkov",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceMedium,
	})

	merged, summary := Merge(nil, []model.Finding{imported, imported}, nil)
	if len(merged) != 1 {
		t.Fatalf("merged findings = %d, want 1", len(merged))
	}
	if summary.Imported != 2 || summary.Deduplicated != 1 || summary.BySource[SourceCheckov] != 2 {
		t.Fatalf("summary = %#v", summary)
	}
}

func hasRuleID(findings []model.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
