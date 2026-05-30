package remediation

import (
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
	if len(explanation.Recommended.Patches) == 0 || explanation.Recommended.Patches[0].Format != "advisory" {
		t.Fatalf("expected advisory patch: %#v", explanation.Recommended.Patches)
	}
}
