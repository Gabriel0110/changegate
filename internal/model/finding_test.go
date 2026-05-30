package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeFindingStableFingerprint(t *testing.T) {
	t.Parallel()

	first := NormalizeFinding(sampleFinding())
	secondInput := sampleFinding()
	secondInput.Description = "human wording can change"
	secondInput.Evidence = []Evidence{
		secondInput.Evidence[1],
		secondInput.Evidence[2],
		secondInput.Evidence[0],
	}
	second := NormalizeFinding(secondInput)

	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprints differ:\nfirst:  %s\nsecond: %s", first.Fingerprint, second.Fingerprint)
	}
	if first.ID != second.ID {
		t.Fatalf("stable IDs differ: %s vs %s", first.ID, second.ID)
	}
	assertGolden(t, "finding-fingerprint.txt", first.Fingerprint+"\n"+first.ID+"\n")
}

func TestFindingJSONIsStableAndRedacted(t *testing.T) {
	t.Parallel()

	finding := NormalizeFinding(sampleFinding())
	encoded, err := json.MarshalIndent(finding, "", "  ")
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	got := string(encoded) + "\n"

	if strings.Contains(got, "super-secret-token") || strings.Contains(got, "plain-secret-value") {
		t.Fatalf("finding JSON leaked sensitive data:\n%s", got)
	}
	assertGolden(t, "finding-redacted.json", got)
}

func TestEvaluatePolicyBlockWarnAllowAndValidate(t *testing.T) {
	t.Parallel()

	blocking := sampleFinding()
	outcome := EvaluatePolicy([]Finding{blocking}, DefaultPolicyConfig())
	if outcome.Decision != DecisionBlock {
		t.Fatalf("Decision = %q, want block", outcome.Decision)
	}
	if outcome.Summary.Blocking != 1 {
		t.Fatalf("Blocking = %d, want 1", outcome.Summary.Blocking)
	}
	if err := ValidateOutcome(outcome); err != nil {
		t.Fatalf("ValidateOutcome returned error: %v", err)
	}

	warnOnly := sampleFinding()
	warnOnly.RuleID = "AWS_LOW_CONFIDENCE"
	warnOnly.Severity = SeverityMedium
	warnOnly.Confidence = ConfidenceMedium
	warnOutcome := EvaluatePolicy([]Finding{warnOnly}, DefaultPolicyConfig())
	if warnOutcome.Decision != DecisionWarn {
		t.Fatalf("Decision = %q, want warn", warnOutcome.Decision)
	}

	allowOutcome := EvaluatePolicy(nil, DefaultPolicyConfig())
	if allowOutcome.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want allow", allowOutcome.Decision)
	}
}

func TestPolicyModes(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		mode PolicyMode
		want Decision
	}{
		{name: "block", mode: PolicyModeBlock, want: DecisionBlock},
		{name: "warn", mode: PolicyModeWarn, want: DecisionWarn},
		{name: "audit", mode: PolicyModeAudit, want: DecisionWarn},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := DefaultPolicyConfig()
			config.Mode = tt.mode
			outcome := EvaluatePolicy([]Finding{sampleFinding()}, config)
			if outcome.Decision != tt.want {
				t.Fatalf("Decision = %q, want %q", outcome.Decision, tt.want)
			}
		})
	}
}

func TestDeduplicateAndSortFindings(t *testing.T) {
	t.Parallel()

	high := NormalizeFinding(sampleFinding())
	medium := sampleFinding()
	medium.RuleID = "AWS_MEDIUM"
	medium.ResourceAddress = "aws_s3_bucket.logs"
	medium.Severity = SeverityMedium
	medium.Confidence = ConfidenceMedium
	medium = NormalizeFinding(medium)

	duplicate := sampleFinding()
	duplicate.Title = "duplicate wording"
	duplicate = NormalizeFinding(duplicate)

	findings := DeduplicateFindings([]Finding{medium, duplicate, high})
	if len(findings) != 2 {
		t.Fatalf("deduplicated length = %d, want 2", len(findings))
	}
	if findings[0].RuleID != high.RuleID {
		t.Fatalf("first finding = %q, want high severity %q", findings[0].RuleID, high.RuleID)
	}
}

func TestOverrideAndSuppression(t *testing.T) {
	t.Parallel()

	finding := NormalizeFinding(sampleFinding())
	low := SeverityLow
	overridden := ApplyOverride(finding, Override{
		Severity: &low,
		Reason:   "accepted for test environment",
	})
	if overridden.Severity != SeverityLow {
		t.Fatalf("Severity = %q, want low", overridden.Severity)
	}

	suppressed := sampleFinding()
	suppressed.Suppressions = []Suppression{{
		Kind:   "waiver",
		Reason: "temporary exception",
		Active: true,
	}}
	outcome := EvaluatePolicy([]Finding{suppressed}, DefaultPolicyConfig())
	if outcome.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want allow for suppressed finding", outcome.Decision)
	}
	if outcome.Summary.Suppressed != 1 {
		t.Fatalf("Suppressed = %d, want 1", outcome.Summary.Suppressed)
	}
}

func TestRenderEvidenceDeterministic(t *testing.T) {
	t.Parallel()

	lines := RenderEvidence(sampleFinding().Evidence)
	got := strings.Join(lines, "\n") + "\n"
	assertGolden(t, "evidence-rendering.txt", got)
}

func sampleFinding() Finding {
	return Finding{
		RuleID:            "AWS_PUBLIC_ADMIN_SERVICE",
		RuleName:          "Public admin service",
		PolicyPack:        "aws-public-exposure",
		PolicyPackVersion: "0.1.0",
		Title:             "Internet-facing admin service",
		Description:       "An internet-facing load balancer routes to a production admin service.",
		ResourceAddress:   "aws_lb.admin",
		Provider:          "registry.terraform.io/hashicorp/aws",
		Environment:       "production",
		Category:          RiskCategoryPublicExposure,
		Severity:          SeverityHigh,
		Confidence:        ConfidenceHigh,
		Evidence: []Evidence{
			{
				Type:     "attribute",
				Resource: "aws_lb.admin",
				Path:     "scheme",
				Value:    "internet-facing",
				Message:  "load balancer is internet-facing",
			},
			{
				Type:      "secret",
				Resource:  "aws_ecs_service.admin",
				Path:      "task_definition.container_definitions.0.environment.ADMIN_TOKEN",
				Value:     "super-secret-token",
				Sensitive: true,
				Message:   "admin token is present in service configuration",
			},
			{
				Type:     "tag",
				Resource: "aws_ecs_service.admin",
				Path:     "tags.env",
				Value: map[string]any{
					"env":    "prod",
					"secret": "plain-secret-value",
				},
				Message: "service is tagged as production",
			},
		},
		Remediation: Remediation{
			Summary: "Restrict ingress to a trusted network or authenticated proxy.",
			Steps: []string{
				"Change the load balancer scheme to internal.",
				"Require authenticated access before admin routes.",
			},
		},
	}
}

func assertGolden(t *testing.T, name string, got string) {
	t.Helper()

	path := filepath.Join("testdata", "golden", name)
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if got != string(wantBytes) {
		t.Fatalf("golden mismatch for %s\nwant:\n%s\ngot:\n%s", name, string(wantBytes), got)
	}
}
