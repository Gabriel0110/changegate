package waiver

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestValidateApplyAndPrune(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	finding := testFinding("AWS_PUBLIC_RDS_INSTANCE", "aws_db_instance.analytics", "staging")
	file := File{
		Version: Version,
		Waivers: []Record{
			{
				ID:          "WVR-001",
				RuleID:      finding.RuleID,
				Resource:    finding.ResourceAddress,
				Fingerprint: finding.Fingerprint,
				Owner:       "platform@example.com",
				Reason:      "Temporary migration exposure.",
				CreatedAt:   "2026-05-01",
				ExpiresAt:   "2026-06-30",
				Conditions: Conditions{
					Environment:         "staging",
					EvidenceFingerprint: finding.Fingerprint,
				},
			},
			{
				ID:        "WVR-002",
				RuleID:    "AWS_OLD",
				Owner:     "platform@example.com",
				Reason:    "Expired.",
				CreatedAt: "2026-01-01",
				ExpiresAt: "2026-01-31",
			},
		},
	}

	validation := Validate(file, ValidationOptions{RequireExpiration: true, MaxDurationDays: 90, Now: now})
	if !validation.Valid || validation.Summary.Active != 1 || validation.Summary.Expired != 1 {
		t.Fatalf("unexpected validation: %+v", validation)
	}

	applied, report := Apply(file, []model.Finding{finding}, now, true)
	if report.Summary.Applied != 1 || len(applied[0].Suppressions) != 1 {
		t.Fatalf("waiver not applied: report=%+v finding=%+v", report, applied[0])
	}

	next, pruned := PruneExpired(file, now)
	if len(pruned) != 1 || len(next.Waivers) != 1 || pruned[0].ID != "WVR-002" {
		t.Fatalf("unexpected prune result: next=%+v pruned=%+v", next, pruned)
	}
}

func TestEvidenceFingerprintInvalidatesWaiver(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	finding := testFinding("AWS_PUBLIC_RDS_INSTANCE", "aws_db_instance.analytics", "staging")
	file := File{Version: Version, Waivers: []Record{{
		ID:        "WVR-001",
		RuleID:    finding.RuleID,
		Resource:  finding.ResourceAddress,
		Owner:     "platform@example.com",
		Reason:    "Temporary.",
		CreatedAt: "2026-05-01",
		ExpiresAt: "2026-06-30",
		Conditions: Conditions{
			EvidenceFingerprint: "different",
		},
	}}}

	_, report := Apply(file, []model.Finding{finding}, now, false)
	if report.Summary.Applied != 0 || report.Summary.Invalid != 1 {
		t.Fatalf("expected invalid waiver report: %+v", report)
	}
	if !strings.Contains(report.Applications[0].Reason, "evidence fingerprint changed") {
		t.Fatalf("missing invalidation reason: %+v", report.Applications[0])
	}
}

func TestWriteLoadDoesNotStoreEvidence(t *testing.T) {
	t.Parallel()

	file := File{Version: Version, Waivers: []Record{{
		ID:        "WVR-001",
		RuleID:    "AWS_RULE",
		Resource:  "aws_resource.example",
		Owner:     "platform@example.com",
		Reason:    "Temporary.",
		CreatedAt: "2026-05-01",
		ExpiresAt: "2026-06-30",
	}}}
	var buf bytes.Buffer
	if err := Write(&buf, file); err != nil {
		t.Fatalf("write: %v", err)
	}
	if strings.Contains(buf.String(), "secret") {
		t.Fatalf("waiver file leaked evidence: %s", buf.String())
	}
	loaded, err := Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Waivers[0].ID != "WVR-001" {
		t.Fatalf("unexpected loaded file: %+v", loaded)
	}
}

func testFinding(ruleID string, resource string, env string) model.Finding {
	return model.NormalizeFinding(model.Finding{
		RuleID:          ruleID,
		Title:           "Public RDS",
		ResourceAddress: resource,
		Provider:        "aws",
		Environment:     env,
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
		Evidence: []model.Evidence{{
			Type:      "attribute",
			Resource:  resource,
			Path:      "password",
			Value:     "secret",
			Sensitive: true,
			Message:   "redacted evidence",
		}},
		Remediation: model.Remediation{Summary: "Fix it."},
	})
}
