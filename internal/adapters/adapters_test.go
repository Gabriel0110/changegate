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

func TestCheckovImportRejectsUnrelatedJSON(t *testing.T) {
	t.Parallel()

	result := Import(SourceCheckov, strings.NewReader(`{"totally":"not checkov"}`))
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one parse diagnostic", result.Diagnostics)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %d, want none", len(result.Findings))
	}
}

func TestImportRejectsOversizedArtifacts(t *testing.T) {
	t.Parallel()

	result := Import(SourceGeneric, strings.NewReader(strings.Repeat(" ", int(maxImportBytes)+1)))
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "ADAPTER_IMPORT_TOO_LARGE" {
		t.Fatalf("diagnostics = %#v, want size diagnostic", result.Diagnostics)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %d, want none", len(result.Findings))
	}
}

func TestSARIFAndGenericCannotSelfAssertHighConfidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source Source
		body   string
	}{
		{
			name:   "sarif",
			source: SourceSARIF,
			body:   `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner","rules":[{"id":"RULE_1","name":"rule","properties":{"severity":"HIGH","confidence":"HIGH"}}]}},"results":[{"ruleId":"RULE_1","message":{"text":"finding"},"properties":{"resource":"aws_s3_bucket.logs","severity":"HIGH","confidence":"HIGH"}}]}]}`,
		},
		{
			name:   "generic",
			source: SourceGeneric,
			body:   `{"findings":[{"rule_id":"CUSTOM_PUBLIC","title":"public thing","resource_address":"aws_lb.admin","category":"public","severity":"high","confidence":"high"}]}`,
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
				t.Fatalf("findings = %d, want one", len(result.Findings))
			}
			if result.Findings[0].Severity != model.SeverityHigh {
				t.Fatalf("severity = %q, want high", result.Findings[0].Severity)
			}
			if result.Findings[0].Confidence != model.ConfidenceMedium {
				t.Fatalf("confidence = %q, want capped medium", result.Findings[0].Confidence)
			}
		})
	}
}

func TestImportAdaptersRejectUnrelatedJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source Source
		body   string
	}{
		{name: "sarif", source: SourceSARIF, body: `{"totally":"not sarif"}`},
		{name: "generic", source: SourceGeneric, body: `{"totally":"not generic findings"}`},
		{name: "trivy", source: SourceTrivy, body: `{"totally":"not trivy"}`},
		{name: "kics", source: SourceKICS, body: `{"totally":"not kics"}`},
		{name: "grype", source: SourceGrype, body: `{"totally":"not grype"}`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := Import(tt.source, strings.NewReader(tt.body))
			if len(result.Diagnostics) != 1 {
				t.Fatalf("diagnostics = %#v, want one parse diagnostic", result.Diagnostics)
			}
			if len(result.Findings) != 0 {
				t.Fatalf("findings = %d, want none", len(result.Findings))
			}
		})
	}
}

func TestImportAdaptersAcceptValidEmptyOutputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source Source
		body   string
	}{
		{name: "sarif", source: SourceSARIF, body: `{"version":"2.1.0","runs":[]}`},
		{name: "generic-array", source: SourceGeneric, body: `[]`},
		{name: "generic-envelope", source: SourceGeneric, body: `{"findings":[]}`},
		{name: "checkov", source: SourceCheckov, body: `{"results":{"failed_checks":[]}}`},
		{name: "trivy", source: SourceTrivy, body: `{"Results":[]}`},
		{name: "kics", source: SourceKICS, body: `{"queries":[]}`},
		{name: "grype", source: SourceGrype, body: `{"matches":[]}`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := Import(tt.source, strings.NewReader(tt.body))
			if len(result.Diagnostics) != 0 {
				t.Fatalf("diagnostics = %#v, want none", result.Diagnostics)
			}
			if len(result.Findings) != 0 {
				t.Fatalf("findings = %d, want none", len(result.Findings))
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
	if summary.Imported != 3 || summary.Retained != 2 || summary.Deduplicated != 1 || summary.SupersededByNative != 1 || summary.Correlated != 1 || summary.Downgraded != 1 || summary.Upgraded != 1 {
		t.Fatalf("summary = %#v", summary)
	}
	if summary.BySource[SourceCheckov] != 1 || summary.BySource[SourceTrivy] != 1 || summary.BySource[SourceKICS] != 1 {
		t.Fatalf("by source = %#v", summary.BySource)
	}
	if !hasInsight(summary.Insights, "superseded_by_native", "aws_s3_bucket.logs") {
		t.Fatalf("missing superseded insight: %#v", summary.Insights)
	}
	if !hasInsight(summary.Insights, "upgraded", "aws_lb.admin") {
		t.Fatalf("missing upgraded insight: %#v", summary.Insights)
	}
	if !hasInsight(summary.Insights, "downgraded", "aws_security_group.missing") {
		t.Fatalf("missing downgraded insight: %#v", summary.Insights)
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
	if summary.Imported != 2 || summary.Retained != 1 || summary.Deduplicated != 1 || summary.BySource[SourceCheckov] != 2 {
		t.Fatalf("summary = %#v", summary)
	}
	if !hasInsight(summary.Insights, "repeated_duplicate", "aws_s3_bucket.logs") {
		t.Fatalf("missing repeated duplicate insight: %#v", summary.Insights)
	}
}

func TestMergeCorrelatesImportedFindingsByGraphAlias(t *testing.T) {
	t.Parallel()

	imported := model.NormalizeFinding(model.Finding{
		RuleID:          "EXT_SARIF_PUBLIC_BUCKET",
		Title:           "public bucket",
		ResourceAddress: "arn:aws:s3:::customer-logs",
		Provider:        "external",
		PolicyPack:      "external:sarif",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityMedium,
		Confidence:      model.ConfidenceMedium,
	})
	resourceGraph := &graph.Graph{
		Nodes: map[graph.ResourceID]*graph.Node{
			"aws_s3_bucket.logs": {
				ID:      "aws_s3_bucket.logs",
				Address: "aws_s3_bucket.logs",
				Type:    "aws_s3_bucket",
				Values: map[string]any{
					"arn":    "arn:aws:s3:::customer-logs",
					"bucket": "customer-logs",
				},
			},
		},
	}

	merged, summary := Merge(nil, []model.Finding{imported}, resourceGraph)
	if len(merged) != 1 {
		t.Fatalf("merged findings = %d, want 1", len(merged))
	}
	if got := merged[0].ResourceAddress; got != "aws_s3_bucket.logs" {
		t.Fatalf("canonical resource = %q, want aws_s3_bucket.logs", got)
	}
	if summary.Retained != 1 || summary.Correlated != 1 || summary.Downgraded != 0 {
		t.Fatalf("summary = %#v", summary)
	}
	if !hasInsight(summary.Insights, "correlated", "aws_s3_bucket.logs") {
		t.Fatalf("missing correlated insight: %#v", summary.Insights)
	}
}

func TestMergeSupersedesImportedFindingsByGraphAlias(t *testing.T) {
	t.Parallel()

	native := model.NormalizeFinding(model.Finding{
		RuleID:          "AWS_S3_BUCKET_PUBLIC_POLICY",
		Title:           "public bucket policy",
		ResourceAddress: "aws_s3_bucket.logs",
		Provider:        "aws",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
	})
	imported := model.NormalizeFinding(model.Finding{
		RuleID:          "EXT_SARIF_PUBLIC_BUCKET",
		Title:           "public bucket",
		ResourceAddress: "arn:aws:s3:::customer-logs",
		Provider:        "external",
		PolicyPack:      "external:sarif",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceMedium,
	})
	resourceGraph := &graph.Graph{
		Nodes: map[graph.ResourceID]*graph.Node{
			"aws_s3_bucket.logs": {
				ID:      "aws_s3_bucket.logs",
				Address: "aws_s3_bucket.logs",
				Type:    "aws_s3_bucket",
				Values: map[string]any{
					"arn":    "arn:aws:s3:::customer-logs",
					"bucket": "customer-logs",
				},
			},
		},
	}

	merged, summary := Merge([]model.Finding{native}, []model.Finding{imported}, resourceGraph)
	if len(merged) != 1 {
		t.Fatalf("merged findings = %d, want 1", len(merged))
	}
	if summary.Imported != 1 || summary.Retained != 0 || summary.Deduplicated != 1 || summary.SupersededByNative != 1 {
		t.Fatalf("summary = %#v", summary)
	}
	if !hasInsight(summary.Insights, "superseded_by_native", "aws_s3_bucket.logs") {
		t.Fatalf("missing alias superseded insight: %#v", summary.Insights)
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

func hasInsight(insights []Insight, action string, resource string) bool {
	for _, insight := range insights {
		if insight.Action == action && insight.Resource == resource {
			return true
		}
	}
	return false
}
