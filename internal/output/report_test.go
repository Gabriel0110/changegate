package output

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestRenderGoldenOutputs(t *testing.T) {
	t.Parallel()

	report := sampleReport()
	tests := []struct {
		name     string
		format   string
		golden   string
		validate func(t *testing.T, body []byte)
	}{
		{name: "console", format: "table", golden: "console.txt"},
		{name: "json", format: "json", golden: "report.json", validate: assertJSON},
		{name: "sarif", format: "sarif", golden: "report.sarif", validate: assertSARIF},
		{name: "junit", format: "junit", golden: "report.junit.xml", validate: assertXML},
		{name: "markdown", format: "markdown", golden: "report.md"},
		{name: "github summary", format: "github-step-summary", golden: "github-step-summary.md"},
		{name: "github annotations", format: "github-annotations", golden: "github-annotations.txt"},
		{name: "gitlab code quality", format: "gitlab-code-quality", golden: "gitlab-code-quality.json", validate: assertJSON},
		{name: "pr comment", format: "pr-comment", golden: "pr-comment.md"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body, _, err := Render(report, tt.format)
			if err != nil {
				t.Fatalf("render %s: %v", tt.format, err)
			}
			assertNoSensitiveLeaks(t, body)
			if tt.validate != nil {
				tt.validate(t, body)
			}
			assertGolden(t, tt.golden, string(body))
		})
	}
}

func TestAuditBundle(t *testing.T) {
	t.Parallel()

	body, _, err := Render(sampleReport(), "audit-bundle")
	if err != nil {
		t.Fatalf("render audit bundle: %v", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open audit bundle: %v", err)
	}
	names := make([]string, 0, len(reader.File))
	for _, file := range reader.File {
		names = append(names, file.Name)
		handle, err := file.Open()
		if err != nil {
			t.Fatalf("open audit bundle member %s: %v", file.Name, err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(handle); err != nil {
			t.Fatalf("read audit bundle member %s: %v", file.Name, err)
		}
		if err := handle.Close(); err != nil {
			t.Fatalf("close audit bundle member %s: %v", file.Name, err)
		}
		assertNoSensitiveLeaks(t, buf.Bytes())
	}
	sort.Strings(names)
	assertGolden(t, "audit-bundle.txt", strings.Join(names, "\n")+"\n")
}

func sampleReport() Report {
	finding := model.NormalizeFinding(model.Finding{
		RuleID:          "AWS_SG_WORLD_OPEN_ADMIN_PORT",
		RuleName:        "Security group opens admin port to the world",
		PolicyPack:      "aws-public-exposure",
		Title:           "Security group opens SSH to the world",
		Description:     "The planned security group permits public administrative ingress.",
		ResourceAddress: "aws_security_group.admin",
		Provider:        "aws",
		Environment:     "prod",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
		Evidence: []model.Evidence{
			{
				Type:      "attribute",
				Resource:  "aws_security_group.admin",
				Path:      "ingress[0].cidr_blocks",
				Value:     []string{"0.0.0.0/0"},
				Message:   "Ingress allows SSH from the public internet.",
				Sensitive: false,
			},
			{
				Type:      "attribute",
				Resource:  "aws_security_group.admin",
				Path:      "tags.secret",
				Value:     "super-secret",
				Message:   "Sensitive tag value was redacted.",
				Sensitive: true,
			},
		},
		Remediation: model.Remediation{
			Summary: "Restrict administrative ingress to trusted CIDR ranges.",
			Steps: []string{
				"Replace 0.0.0.0/0 with a trusted bastion, VPN, or private subnet range.",
				"Prefer SSM Session Manager for administrative access.",
			},
			References: []string{"https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"},
		},
	})
	finding.DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}
	finding.DecisionReasons = []model.DecisionReason{{
		FindingID: finding.ID,
		Resource:  finding.ResourceAddress,
		Code:      model.ReasonMeetsBlockThreshold,
		Reason:    "high severity and high confidence meets block threshold",
	}}

	return Report{
		SchemaVersion: ReportSchemaVersion,
		Decision:      model.DecisionBlock,
		Plan: PlanSummary{
			Path:          "tfplan.json",
			Tool:          model.ToolTerraform,
			FormatVersion: "1.0",
			Resources:     12,
			Changes:       3,
		},
		Graph: GraphSummary{Nodes: 12, Edges: 7},
		RiskSummary: model.RiskSummary{
			Total:      1,
			Blocking:   1,
			BySeverity: map[model.Severity]int{model.SeverityHigh: 1},
			ByCategory: map[model.RiskCategory]int{model.RiskCategoryPublicExposure: 1},
		},
		ReasonCodes: []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold},
		Reasons: []model.DecisionReason{{
			FindingID: finding.ID,
			Resource:  finding.ResourceAddress,
			Code:      model.ReasonMeetsBlockThreshold,
			Reason:    "high severity and high confidence meets block threshold",
		}},
		Findings: []model.Finding{finding},
		Rules: map[string]RuleSummary{
			"AWS_SG_WORLD_OPEN_ADMIN_PORT": {
				ID:          "AWS_SG_WORLD_OPEN_ADMIN_PORT",
				Name:        "Security group opens admin port to the world",
				Description: "Detects administrative ingress exposed to the public internet.",
				Category:    model.RiskCategoryPublicExposure,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceHigh,
				Help:        "Public administrative ingress is a high-confidence exposure risk.",
				Remediation: []string{"Restrict ingress to trusted CIDR ranges."},
				References:  []string{"https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"},
			},
		},
		Message: "plan parsed, graph built, and policy evaluated",
	}
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

	if bytes.Contains(body, []byte("super-secret")) {
		t.Fatalf("output leaked sensitive value:\n%s", string(body))
	}
}

func assertJSON(t *testing.T, body []byte) {
	t.Helper()

	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, string(body))
	}
}

func assertXML(t *testing.T, body []byte) {
	t.Helper()

	var value any
	if err := xml.Unmarshal(body, &value); err != nil {
		t.Fatalf("invalid XML: %v\n%s", err, string(body))
	}
}

func assertSARIF(t *testing.T, body []byte) {
	t.Helper()

	var value struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID   string `json:"id"`
						Help struct {
							Markdown string `json:"markdown"`
						} `json:"help"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Locations           []any             `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, string(body))
	}
	if value.Version != "2.1.0" {
		t.Fatalf("SARIF version = %q, want 2.1.0", value.Version)
	}
	if len(value.Runs) != 1 || len(value.Runs[0].Tool.Driver.Rules) != 1 || len(value.Runs[0].Results) != 1 {
		t.Fatalf("SARIF missing rule/result: %+v", value)
	}
	if value.Runs[0].Tool.Driver.Rules[0].ID == "" || value.Runs[0].Tool.Driver.Rules[0].Help.Markdown == "" {
		t.Fatalf("SARIF missing stable rule ID or help: %+v", value.Runs[0].Tool.Driver.Rules[0])
	}
	result := value.Runs[0].Results[0]
	if result.PartialFingerprints["changegateFingerprint/v1"] == "" || len(result.Locations) == 0 {
		t.Fatalf("SARIF missing fingerprint/location: %+v", result)
	}
}
