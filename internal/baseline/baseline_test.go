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

func finding(ruleID string, resource string) model.Finding {
	return model.NormalizeFinding(model.Finding{
		RuleID:          ruleID,
		Title:           ruleID,
		ResourceAddress: resource,
		Provider:        "aws",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
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
}
