package cloudcontext

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestEnrichFindingsDowngradesAndUpgrades(t *testing.T) {
	t.Parallel()

	public := finding("AWS_PUBLIC_ADMIN_SERVICE", "aws_lb.edge", model.RiskCategoryPublicExposure)
	sensitive := finding("AWS_PUBLIC_TO_SENSITIVE_DATASTORE", "aws_lb.public", model.RiskCategorySensitiveData)
	truth := true
	falseValue := false
	snapshot := Snapshot{
		Version:     Version,
		Provider:    ProviderAWS,
		GeneratedAt: "2026-05-29T00:00:00Z",
		Account:     Account{ID: "123456789012"},
		Resources: map[string]Resource{
			"aws_lb.edge": {
				Address:              "aws_lb.edge",
				Region:               "us-east-1",
				Public:               &truth,
				CompensatingControls: []string{"expected_public_tls_edge"},
				Tags:                 map[string]string{"token": "secret-value"},
			},
			"aws_lb.public": {
				Address:              "aws_lb.public",
				Region:               "us-east-1",
				EncryptionEnabled:    &falseValue,
				RelatedSensitiveData: []string{"aws_db_instance.customer"},
				Drift:                map[string]string{"publicly_accessible": "actual true, plan false"},
			},
		},
	}

	enriched, diagnostics := EnrichFindings([]model.Finding{public, sensitive}, snapshot)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	if enriched[0].Severity != model.SeverityMedium || !hasReason(enriched[0], model.ReasonDowngraded) {
		t.Fatalf("public finding was not downgraded: %+v", enriched[0])
	}
	if enriched[1].Severity != model.SeverityCritical || !hasReason(enriched[1], model.ReasonUpgraded) {
		t.Fatalf("sensitive finding was not upgraded: %+v", enriched[1])
	}

	var buf bytes.Buffer
	if err := Write(&buf, snapshot); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	loaded, err := Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if loaded.Resources["aws_lb.edge"].Tags["token"] != "(sensitive)" {
		t.Fatalf("sensitive tag was not redacted: %+v", loaded.Resources["aws_lb.edge"].Tags)
	}
}

func TestIdentitySnapshotAndPermissionValidation(t *testing.T) {
	t.Parallel()

	identity := DetectAWSIdentity(map[string]string{
		"AWS_ACCOUNT_ID":     "123456789012",
		"AWS_DEFAULT_REGION": "us-west-2",
		"AWS_PROFILE":        "prod",
	})
	if !identity.Detected || identity.Region != "us-west-2" || identity.Profile != "prod" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	snapshot := NewAWSSnapshot(identity, time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC))
	if snapshot.Provider != ProviderAWS || snapshot.Account.ID != "123456789012" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	diagnostics := ValidatePermissions(snapshot)
	if len(diagnostics) == 0 {
		t.Fatalf("expected missing permission diagnostics")
	}
	if !strings.Contains(ReadOnlyPolicyTemplate(), "ec2:DescribeSecurityGroups") {
		t.Fatalf("permissions template missing security group action")
	}
}

func finding(ruleID string, resource string, category model.RiskCategory) model.Finding {
	return model.NormalizeFinding(model.Finding{
		RuleID:          ruleID,
		Title:           ruleID,
		ResourceAddress: resource,
		Provider:        "aws",
		Category:        category,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
		Evidence:        []model.Evidence{{Type: "rule", Resource: resource, Path: "path", Message: "rule evidence"}},
		Remediation:     model.Remediation{Summary: "Fix it."},
	})
}

func hasReason(f model.Finding, code model.DecisionReasonCode) bool {
	for _, current := range f.DecisionReasonCodes {
		if current == code {
			return true
		}
	}
	return false
}
