package cloudcontext

import (
	"bytes"
	"encoding/json"
	"os"
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
		Edge: ResourceSet{
			Resources: map[string]Resource{
				"aws_lb.edge": {
					TerraformAddress:     "aws_lb.edge",
					Region:               "us-east-1",
					Public:               &truth,
					CompensatingControls: []string{"expected_public_tls_edge"},
					Tags:                 map[string]string{"token": "secret-value"},
				},
				"aws_lb.public": {
					TerraformAddress:     "aws_lb.public",
					Region:               "us-east-1",
					EncryptionEnabled:    &falseValue,
					RelatedSensitiveData: []string{"aws_db_instance.customer"},
					Drift:                map[string]string{"publicly_accessible": "actual true, plan false"},
				},
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
	if loaded.Edge.Resources["aws_lb.edge"].Tags["token"] != "(sensitive)" {
		t.Fatalf("sensitive tag was not redacted: %+v", loaded.Edge.Resources["aws_lb.edge"].Tags)
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

func TestReadOnlyPolicyTemplateMatchesExample(t *testing.T) {
	t.Parallel()

	example, err := os.ReadFile("../../examples/aws-context-readonly-policy.json")
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	got := strings.TrimSpace(ReadOnlyPolicyTemplate())
	want := strings.TrimSpace(string(example))
	if got != want {
		t.Fatalf("read-only policy template drifted from example\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestLoadRejectsLegacyCloudContextVersion(t *testing.T) {
	t.Parallel()

	_, err := Load(strings.NewReader(`{"version":1,"provider":"aws","generated_at":"2026-05-29T00:00:00Z","account":{"id":"123456789012"}}`))
	if err == nil || !strings.Contains(err.Error(), "context version must be 2") {
		t.Fatalf("Load legacy snapshot error = %v, want version rejection", err)
	}
}

func TestV2SnapshotSchemaGolden(t *testing.T) {
	t.Parallel()

	public := true
	snapshot := Snapshot{
		Version:     Version,
		Provider:    ProviderAWS,
		GeneratedAt: "2026-05-29T00:00:00Z",
		Account:     Account{ID: "123456789012"},
		Network: ResourceSet{Resources: map[string]Resource{
			"aws_security_group.admin": {
				TerraformAddress: "aws_security_group.admin",
				ARN:              "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
				ID:               "sg-123",
				AccountID:        "123456789012",
				Type:             "aws_security_group",
				Region:           "us-east-1",
				Tags:             map[string]string{"Name": "admin-sg", "token": "secret-token"},
				Public:           &public,
			},
		}},
		Data: ResourceSet{Resources: map[string]Resource{
			"aws_db_instance.customer": {
				TerraformAddress: "aws_db_instance.customer",
				ARN:              "arn:aws:rds:us-east-1:123456789012:db:customer",
				Type:             "aws_db_instance",
				Region:           "us-east-1",
				Sensitivity:      Sensitivity{Data: true, Reason: "customer records"},
			},
		}},
		Relationships: []Relationship{
			{From: "aws_security_group.admin", To: "aws_db_instance.customer", Type: "network_reaches", Source: "ec2", Confidence: "high"},
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, snapshot); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	golden, err := os.ReadFile("testdata/v2-snapshot.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want := strings.ReplaceAll(string(golden), "\r\n", "\n")
	got := strings.ReplaceAll(buf.String(), "\r\n", "\n")
	if got != want {
		t.Fatalf("snapshot JSON mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode written snapshot: %v", err)
	}
	if decoded["version"].(float64) != 2 {
		t.Fatalf("version = %v, want 2", decoded["version"])
	}
	for _, section := range []string{"network", "data"} {
		current, ok := decoded[section].(map[string]any)
		if !ok || current["resources"] == nil {
			t.Fatalf("snapshot missing %s.resources:\n%s", section, buf.String())
		}
	}
	network := decoded["network"].(map[string]any)["resources"].(map[string]any)
	sg := network["aws_security_group.admin"].(map[string]any)
	tags := sg["tags"].(map[string]any)
	if tags["token"] != "(sensitive)" {
		t.Fatalf("sensitive tag was not redacted:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"relationships"`) {
		t.Fatalf("snapshot missing relationships:\n%s", buf.String())
	}
}

func TestEnrichFindingsIndexesV2ResourceIdentifiers(t *testing.T) {
	t.Parallel()

	falseValue := false
	snapshot := Snapshot{
		Version:     Version,
		Provider:    ProviderAWS,
		GeneratedAt: "2026-05-29T00:00:00Z",
		Account:     Account{ID: "123456789012"},
		Data: ResourceSet{Resources: map[string]Resource{
			"aws_s3_bucket.logs": {
				TerraformAddress:     "aws_s3_bucket.logs",
				ARN:                  "arn:aws:s3:::company-logs",
				ID:                   "company-logs",
				Type:                 "aws_s3_bucket",
				Region:               "us-east-1",
				Tags:                 map[string]string{"Name": "company-logs-prod", "terraform_address": "module.logs.aws_s3_bucket.this"},
				Attributes:           map[string]string{"name": "company-logs", "resource_id": "bucket-123"},
				PublicAccessBlocked:  &falseValue,
				RelatedSensitiveData: []string{"aws_db_instance.customer"},
			},
		}},
	}
	for _, resourceAddress := range []string{
		"arn:aws:s3:::company-logs",
		"company-logs",
		"company-logs-prod",
		"module.logs.aws_s3_bucket.this",
		"bucket-123",
	} {
		enriched, _ := EnrichFindings([]model.Finding{
			finding("AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED", resourceAddress, model.RiskCategoryPublicExposure),
		}, snapshot)
		if len(enriched[0].DecisionReasonCodes) == 0 || !hasReason(enriched[0], model.ReasonUpgraded) {
			t.Fatalf("resource %q was not enriched by v2 identifier index: %+v", resourceAddress, enriched[0])
		}
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
