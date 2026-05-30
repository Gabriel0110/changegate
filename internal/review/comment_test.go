package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/impact"
	"github.com/Gabriel0110/changegate/internal/model"
)

func TestRenderCommentGoldens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		statement impact.Statement
		golden    string
	}{
		{name: "allow", statement: reviewStatement(model.DecisionAllow), golden: "allow.md"},
		{name: "warn", statement: reviewStatement(model.DecisionWarn), golden: "warn.md"},
		{name: "block", statement: reviewStatement(model.DecisionBlock), golden: "block.md"},
		{name: "manual", statement: reviewStatement(model.Decision("manual_review")), golden: "manual-review.md"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := RenderComment(tt.statement, CommentOptions{
				ArtifactLinks: []ArtifactLink{{Label: "Audit bundle", URL: "https://example.test/audit.zip"}},
			})
			assertGolden(t, tt.golden, got)
		})
	}
}

func TestRenderCommentCompactsWhenSizeLimitExceeded(t *testing.T) {
	t.Parallel()

	statement := reviewStatement(model.DecisionBlock)
	for i := 0; i < 30; i++ {
		statement.TopFindings = append(statement.TopFindings, reviewFinding("AWS_EXTRA_"+string(rune('A'+i%26)), "aws_security_group.extra", model.SeverityHigh, model.ConfidenceHigh))
	}
	got := RenderComment(statement, CommentOptions{MaxBytes: 900})
	if len(got) > 900 {
		t.Fatalf("comment length = %d, want <= 900\n%s", len(got), got)
	}
	if !strings.Contains(got, "Comment compacted") && !strings.Contains(got, "Comment truncated") {
		t.Fatalf("compact/truncation notice missing:\n%s", got)
	}
	if !strings.Contains(got, DefaultStickyCommentMarker) {
		t.Fatalf("sticky marker missing:\n%s", got)
	}
}

func TestRenderCommentDoesNotLeakSensitiveEvidenceValues(t *testing.T) {
	t.Parallel()

	statement := reviewStatement(model.DecisionBlock)
	statement.TopFindings[0].Title = "Public admin <!-- injected --> <script>alert(1)</script>"
	statement.TopFindings[0].Evidence = append(statement.TopFindings[0].Evidence, model.Evidence{
		Type:      "attribute",
		Resource:  "aws_lb.admin",
		Path:      "tags.secret",
		Value:     "super-secret-token",
		Message:   "Sensitive value was redacted.",
		Sensitive: true,
	})
	got := RenderComment(statement, CommentOptions{})
	if strings.Contains(got, "super-secret-token") {
		t.Fatalf("comment leaked sensitive evidence value:\n%s", got)
	}
	for _, forbidden := range []string{"<!-- injected -->", "<script>", "</script>"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("comment did not sanitize %q:\n%s", forbidden, got)
		}
	}
}

func reviewStatement(decision model.Decision) impact.Statement {
	findings := []model.Finding{}
	if decision != model.DecisionAllow {
		findings = append(findings,
			reviewFinding("AWS_PUBLIC_ADMIN_SERVICE", "aws_lb.admin", model.SeverityHigh, model.ConfidenceHigh),
			reviewFinding("AWS_STATEFUL_REPLACEMENT", "aws_db_instance.customer", model.SeverityHigh, model.ConfidenceHigh),
		)
	}
	if decision == model.DecisionWarn {
		for index := range findings {
			findings[index].DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonBelowBlockThreshold}
		}
	}
	if decision == model.DecisionBlock || decision == model.Decision("manual_review") {
		for index := range findings {
			findings[index].DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}
		}
	}
	statement := impact.Statement{
		Version:        impact.StatementVersion,
		Decision:       decision,
		ReviewRequired: decision != model.DecisionAllow,
		GeneratedAt:    time.Date(2026, 5, 30, 16, 0, 0, 0, time.UTC),
		TopFindings:    findings,
		TopGraphPaths:  graphPaths(decision),
		AttackPaths:    attackPaths(decision),
		Waivers:        impact.WaiverSummary{Active: 1, Expired: 0, Total: 1},
		Baseline:       impact.BaselineSummary{ExistingFindings: 3, NewFindings: len(findings)},
		Ownership:      []impact.OwnershipHint{{Owner: "platform-security", Resource: "aws_lb.admin", Source: "tags.owner"}},
		Summary: impact.Summary{
			PlansScanned:           1,
			ResourcesChanged:       4,
			PublicEntrypointsAdded: len(findings),
			SensitiveAssetsTouched: len(findings),
			IAMPermissionChanges:   1,
			NetworkPathChanges:     len(findings),
			DataPathChanges:        len(findings),
		},
		RiskMovement: impact.RiskMovement{
			NewHigh:           len(findings),
			ExistingUnchanged: 3,
			ExistingWorsened:  1,
			ResolvedHigh:      1,
			WaivedActive:      1,
		},
		Diagnostics: []model.Diagnostic{{Severity: model.DiagnosticWarning, Code: "TEST_WARNING", Message: "fixture diagnostic"}},
	}
	if decision != model.DecisionAllow {
		statement.RequiredReviewers = []impact.ReviewerRequirement{
			{Reviewer: "security", Reason: "deployment decision requires review", Source: "decision"},
		}
	}
	if decision == model.DecisionAllow {
		statement.Waivers = impact.WaiverSummary{}
		statement.Diagnostics = nil
	}
	return statement
}

func reviewFinding(ruleID string, resource string, severity model.Severity, confidence model.Confidence) model.Finding {
	finding := model.NormalizeFinding(model.Finding{
		RuleID:          ruleID,
		Title:           strings.ReplaceAll(ruleID, "_", " "),
		Description:     "A high-confidence infrastructure risk was introduced.",
		ResourceAddress: resource,
		Provider:        "aws",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        severity,
		Confidence:      confidence,
		Evidence: []model.Evidence{{
			Type:     "graph_path",
			Resource: resource,
			Path:     "graph.path",
			Value:    []string{"internet", "aws_lb.admin", "aws_ecs_service.admin", "aws_db_instance.customer"},
			Message:  "Public entrypoint reaches a sensitive downstream asset.",
		}},
		Remediation: model.Remediation{
			Summary:    "Restrict public ingress or move the service behind an internal entrypoint.",
			Steps:      []string{"Make the load balancer internal or restrict ingress to approved CIDRs."},
			OwnerHints: []string{"platform-security"},
		},
	})
	finding.DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}
	return finding
}

func graphPaths(decision model.Decision) []impact.GraphPathSummary {
	if decision == model.DecisionAllow {
		return nil
	}
	return []impact.GraphPathSummary{{
		ID:          "graph-path-1",
		RuleID:      "AWS_PUBLIC_ADMIN_SERVICE",
		Resource:    "aws_lb.admin",
		Title:       "Public admin route reaches customer database",
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceHigh,
		Path:        []string{"internet", "aws_lb.admin", "aws_ecs_service.admin", "aws_db_instance.customer"},
		Description: "A public entrypoint reaches a sensitive downstream asset.",
	}}
}

func attackPaths(decision model.Decision) []impact.AttackPathSummary {
	if decision != model.DecisionBlock {
		return nil
	}
	return []impact.AttackPathSummary{{
		ID:         "attack-path-1",
		RuleID:     "AWS_PASSROLE_WITH_COMPUTE_MUTATION",
		Resource:   "aws_iam_role.deploy",
		Type:       "iam_escalation",
		Title:      "Deploy role can pass privileged role and mutate compute",
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceHigh,
		Steps:      []string{"DeveloperRole", "lambda:UpdateFunctionCode", "iam:PassRole", "AdminExecutionRole"},
		Decision:   model.DecisionBlock,
	}}
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
		t.Fatalf("read golden %s: %v\ngot:\n%s", path, err, got)
	}
	if string(want) != got {
		t.Fatalf("golden mismatch for %s (want len %d, got len %d)\nwant suffix: %q\ngot suffix: %q\nwant:\n%s\ngot:\n%s", name, len(want), len(got), suffix(string(want), 24), suffix(got, 24), string(want), got)
	}
}

func suffix(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[len(value)-limit:]
}
