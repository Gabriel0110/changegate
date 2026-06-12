package risktest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/baseline"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
)

func TestAssertPassesSupportedExpectations(t *testing.T) {
	t.Parallel()

	waiverExpiry := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	report := output.Report{
		Decision: model.DecisionBlock,
		RiskSummary: model.RiskSummary{
			BySeverity: map[model.Severity]int{model.SeverityCritical: 1, model.SeverityHigh: 1},
		},
		RiskMovement: &baseline.RiskMovement{NewHigh: 1, ExistingWorsened: 1, WaivedActive: 1},
		Findings: []model.Finding{
			{
				RuleID:          "AWS_PUBLIC_TO_SENSITIVE_DATA_PATH",
				ResourceAddress: "aws_db_instance.customer",
				Severity:        model.SeverityCritical,
				Evidence: []model.Evidence{
					{Type: "attack_path", Path: "attack_path.type", Value: "public_to_sensitive_data"},
					{Type: "attack_path.graph_path", Path: "graph.path", Value: []string{"internet", "aws_lb.admin", "aws_db_instance.customer"}},
				},
				Suppressions: []model.Suppression{{Kind: "waiver", Active: true, ExpiresAt: &waiverExpiry}},
			},
			{RuleID: "AWS_RDS_BACKUP_RETENTION_DISABLED_PROD", Severity: model.SeverityHigh},
		},
	}

	expect := Expectations{
		Decision: model.DecisionBlock,
		Findings: FindingExpectations{
			Include: []string{"AWS_PUBLIC_TO_SENSITIVE_DATA_PATH"},
			Exclude: []string{"AWS_PUBLIC_RDS_INSTANCE"},
			Counts:  map[string]int{"AWS_PUBLIC_TO_SENSITIVE_DATA_PATH": 1},
			Resources: map[string][]string{
				"AWS_PUBLIC_TO_SENSITIVE_DATA_PATH": {"aws_db_instance.customer"},
			},
		},
		SeverityCount: map[model.Severity]int{model.SeverityCritical: 1, model.SeverityHigh: 1},
		AttackPaths:   PathExpectations{Include: []string{"public_to_sensitive_data"}, Exclude: []string{"iam_privilege_escalation"}},
		GraphPaths:    PathExpectations{Include: []string{"aws_lb.admin -> aws_db_instance.customer"}},
		RiskMovement: RiskMovementExpect{
			NewHigh:          intPtr(1),
			ExistingWorsened: intPtr(1),
			WaivedActive:     intPtr(1),
		},
		Waivers: WaiverExpectations{
			Applied:    []string{"AWS_PUBLIC_TO_SENSITIVE_DATA_PATH"},
			NotApplied: []string{"AWS_RDS_BACKUP_RETENTION_DISABLED_PROD"},
		},
	}
	if failures := Assert("public_admin", report, expect, "", false); len(failures) != 0 {
		t.Fatalf("failures = %#v, want none", failures)
	}
}

func TestAssertReportsPreciseFailures(t *testing.T) {
	t.Parallel()

	report := output.Report{
		Decision: model.DecisionAllow,
		RiskSummary: model.RiskSummary{
			BySeverity: map[model.Severity]int{model.SeverityHigh: 1},
		},
		Findings: []model.Finding{{RuleID: "AWS_PUBLIC_RDS_INSTANCE", Severity: model.SeverityHigh}},
	}
	expect := Expectations{
		Decision:      model.DecisionBlock,
		Findings:      FindingExpectations{Include: []string{"AWS_PUBLIC_ADMIN_SERVICE"}, Exclude: []string{"AWS_PUBLIC_RDS_INSTANCE"}},
		SeverityCount: map[model.Severity]int{model.SeverityCritical: 1},
		AttackPaths:   PathExpectations{Include: []string{"public_to_sensitive_data"}},
		RiskMovement:  RiskMovementExpect{NewHigh: intPtr(1)},
		Waivers:       WaiverExpectations{Applied: []string{"AWS_PUBLIC_RDS_INSTANCE"}},
	}

	failures := Assert("bad_case", report, expect, "", false)
	if len(failures) < 6 {
		t.Fatalf("failures = %d, want at least 6: %#v", len(failures), failures)
	}
	body := RenderText(Result{
		Passed: false,
		Manifests: []ManifestRun{{
			Path: "changegate-test.yaml",
			Tests: []CaseRun{{
				Name:     "bad_case",
				Failures: failures,
			}},
		}},
		Summary: Summary{Manifests: 1, Tests: 1, Failed: 1},
	})
	want, err := os.ReadFile(filepath.Join("testdata", "golden", "failure.txt"))
	if err != nil {
		t.Fatalf("read golden failure output: %v", err)
	}
	wantText := normalizeTestNewlines(string(want))
	bodyText := normalizeTestNewlines(body)
	if bodyText != wantText {
		t.Fatalf("failure output mismatch\nwant:\n%s\ngot:\n%s", wantText, bodyText)
	}
}

func TestAssertFindingCountsAndResourcesReportPreciseFailures(t *testing.T) {
	t.Parallel()

	report := output.Report{
		Decision: model.DecisionBlock,
		Findings: []model.Finding{
			{RuleID: "AWS_PUBLIC_ADMIN_SERVICE", ResourceAddress: "aws_lb.admin"},
			{RuleID: "AWS_PUBLIC_ADMIN_SERVICE", ResourceAddress: "aws_ecs_service.admin"},
		},
	}
	expect := Expectations{
		Findings: FindingExpectations{
			Counts: map[string]int{"AWS_PUBLIC_ADMIN_SERVICE": 1},
			Resources: map[string][]string{
				"AWS_PUBLIC_ADMIN_SERVICE": {"aws_lb.admin"},
			},
		},
	}

	failures := Assert("noisy_admin", report, expect, "", false)
	if len(failures) != 2 {
		t.Fatalf("failures = %#v, want count and resource failures", failures)
	}
	if failures[0].Assertion != "findings.counts.AWS_PUBLIC_ADMIN_SERVICE" {
		t.Fatalf("first failure = %#v", failures[0])
	}
	if failures[1].Assertion != "findings.resources.AWS_PUBLIC_ADMIN_SERVICE" {
		t.Fatalf("second failure = %#v", failures[1])
	}
}

func TestAssertSnapshotMatchAndUpdate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	report := output.Report{Decision: model.DecisionAllow}
	expect := Expectations{Snapshot: "snapshots/report.json"}

	failures := Assert("snapshot", report, expect, tempDir, true)
	if len(failures) != 0 {
		t.Fatalf("update snapshot failures = %#v", failures)
	}
	path := filepath.Join(tempDir, "snapshots", "report.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot was not written: %v", err)
	}
	if failures := Assert("snapshot", report, expect, tempDir, false); len(failures) != 0 {
		t.Fatalf("snapshot match failures = %#v", failures)
	}

	changed := output.Report{Decision: model.DecisionBlock}
	failures = Assert("snapshot", changed, expect, tempDir, false)
	if len(failures) != 1 || failures[0].Assertion != "snapshot" {
		t.Fatalf("snapshot mismatch failures = %#v", failures)
	}
}

func intPtr(value int) *int {
	return &value
}

func normalizeTestNewlines(value string) string {
	return strings.ReplaceAll(value, "\r\n", "\n")
}
