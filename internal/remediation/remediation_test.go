package remediation

import (
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestEnrichFindingAddsConcreteGuidance(t *testing.T) {
	t.Parallel()

	finding := model.NormalizeFinding(model.Finding{
		RuleID:          "AWS_PUBLIC_ADMIN_SERVICE",
		Title:           "Public admin service",
		ResourceAddress: "aws_lb.admin",
		Category:        model.RiskCategoryPublicExposure,
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
		Remediation:     model.Remediation{Summary: ""},
	})
	enriched := EnrichFinding(finding, map[string]string{"owner": "platform", "service": "admin"}, Options{
		DocsLinks: map[string]string{
			"AWS_PUBLIC_ADMIN_SERVICE": "https://docs.example.com/admin",
			"public_exposure":          "https://docs.example.com/public",
		},
	})
	if enriched.Remediation.Summary == "" || enriched.Remediation.WhyThisWorks == "" {
		t.Fatalf("remediation missing concrete guidance: %#v", enriched.Remediation)
	}
	if enriched.Remediation.FixConfidence != model.ConfidenceHigh {
		t.Fatalf("fix confidence = %q", enriched.Remediation.FixConfidence)
	}
	if enriched.Remediation.Effort == "" || enriched.Remediation.DowntimeRisk == "" {
		t.Fatalf("operational metadata missing: %#v", enriched.Remediation)
	}
	if len(enriched.Remediation.FixOptions) == 0 || !enriched.Remediation.FixOptions[0].Preferred {
		t.Fatalf("fix options missing preferred route: %#v", enriched.Remediation.FixOptions)
	}
	if len(enriched.Remediation.TerraformHints) == 0 {
		t.Fatalf("terraform hints missing: %#v", enriched.Remediation.TerraformHints)
	}
	if enriched.Remediation.AutoFixAvailable {
		t.Fatalf("autofix should not be enabled")
	}
	if len(enriched.Remediation.Patches) == 0 || enriched.Remediation.Patches[0].SafeToApply {
		t.Fatalf("patch suggestion missing or unsafe flag wrong: %#v", enriched.Remediation.Patches)
	}
	if len(enriched.Remediation.OwnerHints) != 2 {
		t.Fatalf("owner hints = %#v", enriched.Remediation.OwnerHints)
	}
	if len(enriched.Remediation.Docs) != 2 {
		t.Fatalf("docs = %#v", enriched.Remediation.Docs)
	}
}

func TestExplainRuleUsesTemplate(t *testing.T) {
	t.Parallel()

	explanation := ExplainRule("AWS_STATEFUL_REPLACEMENT", "Stateful replacement", "Detects replacement.", model.RiskCategoryAvailability, model.SeverityHigh, model.ConfidenceHigh, nil, Options{})
	if explanation.WhatHappened == "" || explanation.WhyItMatters == "" {
		t.Fatalf("explanation incomplete: %#v", explanation)
	}
	if explanation.Recommended.AutoFixAvailable {
		t.Fatalf("stateful replacement should not have automatic patch")
	}
	if !explanation.Recommended.Destructive || explanation.Recommended.DowntimeRisk != "high" {
		t.Fatalf("stateful replacement missing destructive metadata: %#v", explanation.Recommended)
	}
	if len(explanation.Recommended.Patches) == 0 || explanation.Recommended.Patches[0].Format != "advisory" {
		t.Fatalf("expected advisory patch: %#v", explanation.Recommended.Patches)
	}
}

func TestAttackPathRemediationIsAdvisoryAndNonAutofix(t *testing.T) {
	t.Parallel()

	for _, ruleID := range []string{
		"AWS_PUBLIC_TO_SENSITIVE_DATA_PATH",
		"AWS_PUBLIC_TO_SENSITIVE_DATASTORE",
		"AWS_PUBLIC_ADMIN_SERVICE_PATH",
		"AWS_IAM_PASSROLE_FUNCTION_ESCALATION",
		"AWS_IAM_ASSUME_ADMIN_PATH",
	} {
		ruleID := ruleID
		t.Run(ruleID, func(t *testing.T) {
			t.Parallel()

			finding := model.NormalizeFinding(model.Finding{
				RuleID:          ruleID,
				Title:           ruleID,
				ResourceAddress: "aws_resource.example",
				Category:        model.RiskCategorySensitiveData,
				Severity:        model.SeverityHigh,
				Confidence:      model.ConfidenceHigh,
			})
			if strings.Contains(ruleID, "IAM") {
				finding.Category = model.RiskCategoryPrivilegeEscalation
			}
			enriched := EnrichFinding(finding, nil, Options{})
			if enriched.Remediation.Summary == "" || enriched.Remediation.WhyThisWorks == "" {
				t.Fatalf("%s missing summary or rationale: %#v", ruleID, enriched.Remediation)
			}
			if enriched.Remediation.AutoFixAvailable {
				t.Fatalf("%s unexpectedly enabled autofix", ruleID)
			}
			if len(enriched.Remediation.FixOptions) == 0 || len(enriched.Remediation.TerraformHints) == 0 {
				t.Fatalf("%s missing tradeoffs or Terraform hints: %#v", ruleID, enriched.Remediation)
			}
			for _, patch := range enriched.Remediation.Patches {
				if patch.SafeToApply || !patch.ReviewNeeded {
					t.Fatalf("%s has unsafe patch metadata: %#v", ruleID, patch)
				}
				if strings.Contains(patch.Snippet, "aws_s3_bucket") || strings.Contains(patch.Title, "S3") {
					t.Fatalf("%s unexpectedly used S3-specific patch guidance: %#v", ruleID, patch)
				}
			}
		})
	}
}
