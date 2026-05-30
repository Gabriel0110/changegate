package baseline

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
)

func TestBuildWriteLoadAndDiff(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	expires := now.Add(30 * 24 * time.Hour)
	oldFinding := finding("AWS_PUBLIC_RDS_INSTANCE", "aws_db_instance.legacy")
	file := Build([]model.Finding{oldFinding}, rules.DefaultPolicyPacks(), now, &expires)

	var buf bytes.Buffer
	if err := Write(&buf, file); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	if strings.Contains(buf.String(), "secret") || !strings.Contains(buf.String(), `"version": 1`) {
		t.Fatalf("baseline JSON invalid or leaked sensitive content:\n%s", buf.String())
	}

	loaded, err := Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	diff := Diff(loaded, []model.Finding{
		oldFinding,
		finding("AWS_S3_SENSITIVE_BUCKET_LOGGING_DISABLED", "aws_s3_bucket.new"),
	}, now, 10, true)
	if diff.Summary.Unchanged != 1 || diff.Summary.New != 1 || diff.Summary.Stale != 0 {
		body, _ := json.MarshalIndent(diff, "", "  ")
		t.Fatalf("unexpected diff:\n%s", string(body))
	}
}

func TestDiffDetectsStaleAndRenamedFindings(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	oldFinding := finding("AWS_PUBLIC_RDS_INSTANCE", "aws_db_instance.legacy")
	renamedFinding := finding("AWS_PUBLIC_RDS_INSTANCE", "aws_db_instance.renamed")
	file := Build([]model.Finding{
		oldFinding,
		finding("AWS_STATEFUL_REPLACEMENT", "aws_db_instance.deleted"),
	}, nil, now.Add(-40*24*time.Hour), nil)

	diff := Diff(file, []model.Finding{renamedFinding}, now, 30, true)
	if diff.Summary.Changed != 1 || diff.Summary.Stale != 1 {
		body, _ := json.MarshalIndent(diff, "", "  ")
		t.Fatalf("unexpected diff:\n%s", string(body))
	}
	if diff.Changed[0].ResourceMovedFrom != "aws_db_instance.legacy" {
		t.Fatalf("resource rename not captured: %+v", diff.Changed[0])
	}
	if len(diff.Warnings) != 2 {
		t.Fatalf("warnings = %v, want missing expiration and stale age", diff.Warnings)
	}
}

func TestDiffClassifiesRiskMovementCategories(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	unchanged := findingWith("AWS_UNCHANGED", "aws_security_group.unchanged", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, nil)
	worsenedSeverityOld := findingWith("AWS_WORSENED_SEVERITY", "aws_security_group.severity", model.RiskCategoryPublicExposure, model.SeverityMedium, model.ConfidenceMedium, nil)
	worsenedSeverityNew := findingWith("AWS_WORSENED_SEVERITY", "aws_security_group.severity", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, nil)
	improvedOld := findingWith("AWS_IMPROVED", "aws_security_group.improved", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, nil)
	improvedNew := findingWith("AWS_IMPROVED", "aws_security_group.improved", model.RiskCategoryPublicExposure, model.SeverityMedium, model.ConfidenceMedium, nil)
	resolved := findingWith("AWS_RESOLVED", "aws_security_group.resolved", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, nil)
	waivedOld := findingWith("AWS_WAIVER_GONE", "aws_db_instance.waiver", model.RiskCategorySensitiveData, model.SeverityHigh, model.ConfidenceHigh, []model.Suppression{{Kind: "waiver", Reason: "temporary", Active: true}})
	waivedNew := findingWith("AWS_WAIVER_GONE", "aws_db_instance.waiver", model.RiskCategorySensitiveData, model.SeverityHigh, model.ConfidenceHigh, nil)
	newFinding := findingWith("AWS_NEW", "aws_security_group.new", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, nil)

	file := Build([]model.Finding{unchanged, worsenedSeverityOld, improvedOld, resolved, waivedOld}, nil, now, nil)
	diff := Diff(file, []model.Finding{unchanged, worsenedSeverityNew, improvedNew, waivedNew, newFinding}, now, 0, false)

	if diff.Summary.NewRisk != 1 || diff.Summary.ExistingUnchanged != 1 || diff.Summary.ExistingWorsened != 2 || diff.Summary.ExistingImproved != 1 || diff.Summary.Resolved != 1 {
		body, _ := json.MarshalIndent(diff, "", "  ")
		t.Fatalf("unexpected movement summary:\n%s", string(body))
	}
	if diff.RiskMovement.NewHigh != 1 || diff.RiskMovement.ExistingUnchanged != 1 || diff.RiskMovement.ExistingWorsened != 2 || diff.RiskMovement.ExistingImproved != 1 || diff.RiskMovement.ResolvedHigh != 1 {
		body, _ := json.MarshalIndent(diff.RiskMovement, "", "  ")
		t.Fatalf("unexpected risk movement:\n%s", string(body))
	}
}

func TestDiffTreatsNewSensitiveGraphPathAsWorsened(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	oldFinding := graphFinding("AWS_PUBLIC_ADMIN_SERVICE", "aws_lb.admin", []string{"internet", "aws_lb.admin", "aws_ecs_service.admin"})
	newFinding := graphFinding("AWS_PUBLIC_ADMIN_SERVICE", "aws_lb.admin", []string{"internet", "aws_lb.admin", "aws_ecs_service.admin", "aws_db_instance.customer"})
	if oldFinding.Fingerprint != newFinding.Fingerprint {
		t.Fatalf("test setup expected same fingerprint, got %s and %s", oldFinding.Fingerprint, newFinding.Fingerprint)
	}

	file := Build([]model.Finding{oldFinding}, nil, now, nil)
	diff := Diff(file, []model.Finding{newFinding}, now, 0, false)
	if diff.Summary.ExistingWorsened != 1 || diff.RiskMovement.ExistingWorsened != 1 {
		body, _ := json.MarshalIndent(diff, "", "  ")
		t.Fatalf("sensitive graph path was not worsened:\n%s", string(body))
	}
}

func finding(ruleID string, resource string) model.Finding {
	return findingWith(ruleID, resource, model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh, nil)
}

func findingWith(ruleID string, resource string, category model.RiskCategory, severity model.Severity, confidence model.Confidence, suppressions []model.Suppression) model.Finding {
	finding := model.NormalizeFinding(model.Finding{
		RuleID:          ruleID,
		Title:           ruleID,
		ResourceAddress: resource,
		Provider:        "aws",
		Category:        category,
		Severity:        severity,
		Confidence:      confidence,
		Evidence: []model.Evidence{{
			Type:      "attribute",
			Resource:  resource,
			Path:      "secret",
			Value:     "secret-value",
			Sensitive: true,
			Message:   "redacted test evidence",
		}},
		Remediation: model.Remediation{Summary: "Fix it."},
	})
	finding.DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}
	finding.Suppressions = suppressions
	return finding
}

func graphFinding(ruleID string, resource string, path []string) model.Finding {
	finding := model.NormalizeFinding(model.Finding{
		RuleID:          ruleID,
		Title:           ruleID,
		ResourceAddress: resource,
		Provider:        "aws",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
		Evidence: []model.Evidence{{
			Type:     "graph_path",
			Resource: resource,
			Path:     "graph.path",
			Value:    path,
			Message:  "graph path changed",
		}},
		Remediation: model.Remediation{Summary: "Fix it."},
	})
	finding.DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}
	return finding
}
