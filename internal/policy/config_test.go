package policy

import (
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
)

func TestLoadValidateAndConvertPolicy(t *testing.T) {
	t.Parallel()

	body := `
version: 1
mode: warn
policy_packs:
  - aws-public-exposure
rules:
  enabled:
    - AWS_IAM_ADMIN_POLICY_ATTACHMENT
  disabled:
    - AWS_PUBLIC_RDS_INSTANCE
decision:
  block_on:
    severity: high
    confidence: high
environments:
  production:
    decision:
      block_on:
        severity: medium
        confidence: medium
overrides:
  AWS_SG_WORLD_OPEN_ADMIN_PORT:
    severity: medium
    confidence: medium
    reason: noisy in migration
compliance:
  mappings:
    ORG_QUEUE_REVIEW:
      frameworks:
        soc2:
          - CC8.1
`
	config, err := Load(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	registry, err := rules.DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	result := Validate(config, registry, rules.DefaultPolicyPacks())
	if !result.Valid {
		t.Fatalf("policy invalid: %#v", result.Diagnostics)
	}

	modelConfig := ModelConfig(config, "production")
	if modelConfig.Mode != model.PolicyModeWarn {
		t.Fatalf("Mode = %q, want warn", modelConfig.Mode)
	}
	if modelConfig.BlockOn.MinSeverity != model.SeverityMedium {
		t.Fatalf("production block severity = %q, want medium", modelConfig.BlockOn.MinSeverity)
	}
	if modelConfig.Overrides["AWS_SG_WORLD_OPEN_ADMIN_PORT"].Severity == nil {
		t.Fatalf("override severity missing")
	}
	if got := modelConfig.ComplianceMappings["ORG_QUEUE_REVIEW"]["soc2"]; len(got) != 1 || got[0] != "CC8.1" {
		t.Fatalf("compliance mapping missing: %#v", modelConfig.ComplianceMappings)
	}

	selection := RuleSelection(config, rules.DefaultPolicyPacks())
	if !selection.EnabledRules["AWS_PUBLIC_ADMIN_SERVICE"] {
		t.Fatalf("pack rule was not enabled")
	}
	if !selection.EnabledRules["AWS_IAM_ADMIN_POLICY_ATTACHMENT"] {
		t.Fatalf("explicit rule was not enabled")
	}
	if !selection.DisabledRules["AWS_PUBLIC_RDS_INSTANCE"] {
		t.Fatalf("disabled rule missing")
	}
	if selection.Overrides["AWS_SG_WORLD_OPEN_ADMIN_PORT"].Confidence == nil {
		t.Fatalf("selection override confidence missing")
	}
}

func TestValidatePolicyRejectsUnknowns(t *testing.T) {
	t.Parallel()

	config := Config{
		Version:     2,
		Mode:        "invalid",
		PolicyPacks: []string{"missing-pack"},
		Rules: RulesConfig{
			Enabled: []string{"MISSING_RULE"},
		},
		Overrides: map[string]OverrideConfig{
			"MISSING_OVERRIDE": {},
		},
	}
	registry, err := rules.DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	result := Validate(config, registry, rules.DefaultPolicyPacks())
	if result.Valid {
		t.Fatalf("policy unexpectedly valid")
	}
	if len(result.Diagnostics) != 5 {
		t.Fatalf("diagnostics = %d, want 5: %#v", len(result.Diagnostics), result.Diagnostics)
	}
}

func TestValidatePolicyRejectsInvalidComplianceMappings(t *testing.T) {
	t.Parallel()

	registry, err := rules.DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	result := Validate(Config{
		Compliance: ComplianceConfig{Mappings: map[string]ComplianceMappingConfig{
			"AWS_PUBLIC_RDS_INSTANCE": {Frameworks: map[string][]string{"soc2": {}}},
		}},
	}, registry, rules.DefaultPolicyPacks())
	if result.Valid {
		t.Fatalf("policy unexpectedly valid")
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "COMPLIANCE_CONTROLS_EMPTY" {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}
}

func TestValidatePolicyPackVersionPinsAndSigningGuard(t *testing.T) {
	t.Parallel()

	registry, err := rules.DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	valid := Validate(Config{PolicyPackVersions: map[string]string{"aws-core": "0.1.0"}}, registry, rules.DefaultPolicyPacks())
	if !valid.Valid {
		t.Fatalf("valid version pin failed: %#v", valid.Diagnostics)
	}
	invalid := Validate(Config{
		PolicyPackVersions: map[string]string{"aws-core": "9.9.9"},
		PolicyPackSigning:  PolicyPackSigningConfig{RequireSigned: true},
	}, registry, rules.DefaultPolicyPacks())
	if invalid.Valid {
		t.Fatalf("invalid version/signing config unexpectedly valid")
	}
	if len(invalid.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %d, want 2: %#v", len(invalid.Diagnostics), invalid.Diagnostics)
	}
}

func TestReviewIntelligenceConfigDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	registry, err := rules.DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	result := Validate(Config{}, registry, rules.DefaultPolicyPacks())
	if !result.Valid {
		t.Fatalf("empty policy invalid: %#v", result.Diagnostics)
	}
	if result.Policy.Review.Enabled == nil || !*result.Policy.Review.Enabled {
		t.Fatalf("review.enabled default was not true")
	}
	if result.Policy.Review.MaxCommentFindings == nil || *result.Policy.Review.MaxCommentFindings != 10 {
		t.Fatalf("review.max_comment_findings = %v, want 10", result.Policy.Review.MaxCommentFindings)
	}
	if result.Policy.Review.MaxGraphPaths == nil || *result.Policy.Review.MaxGraphPaths != 5 {
		t.Fatalf("review.max_graph_paths = %v, want 5", result.Policy.Review.MaxGraphPaths)
	}
	if result.Policy.Review.StickyCommentMarker != "<!-- changegate-review -->" {
		t.Fatalf("review.sticky_comment_marker = %q", result.Policy.Review.StickyCommentMarker)
	}
	if result.Policy.Impact.IncludeExistingRisks == nil || !*result.Policy.Impact.IncludeExistingRisks {
		t.Fatalf("impact.include_existing_risks default was not true")
	}
	if result.Policy.Impact.IncludeResolvedRisks == nil || !*result.Policy.Impact.IncludeResolvedRisks {
		t.Fatalf("impact.include_resolved_risks default was not true")
	}
	if result.Policy.Impact.IncludeWaivers == nil || !*result.Policy.Impact.IncludeWaivers {
		t.Fatalf("impact.include_waivers default was not true")
	}
	if result.Policy.AttackPaths.Enabled == nil || !*result.Policy.AttackPaths.Enabled {
		t.Fatalf("attack_paths.enabled default was not true")
	}
	if len(result.Policy.AttackPaths.Block) != 2 {
		t.Fatalf("attack_paths.block = %#v, want two defaults", result.Policy.AttackPaths.Block)
	}
	if len(result.Policy.AttackPaths.Warn) != 2 {
		t.Fatalf("attack_paths.warn = %#v, want two defaults", result.Policy.AttackPaths.Warn)
	}

	body := `
version: 1
review:
  enabled: false
  max_comment_findings: 0
  max_graph_paths: 0
  sticky_comment_marker: "<!-- custom-changegate-review -->"
impact:
  include_existing_risks: false
  include_resolved_risks: false
  include_waivers: false
attack_paths:
  enabled: false
  block:
    - type: public_to_sensitive_data
      min_confidence: high
  warn:
    - type: public_to_sensitive_data
      min_confidence: medium
`
	config, err := Load(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	result = Validate(config, registry, rules.DefaultPolicyPacks())
	if !result.Valid {
		t.Fatalf("policy invalid: %#v", result.Diagnostics)
	}
	if result.Policy.Review.Enabled == nil || *result.Policy.Review.Enabled {
		t.Fatalf("review.enabled override was not false")
	}
	if result.Policy.Review.MaxCommentFindings == nil || *result.Policy.Review.MaxCommentFindings != 0 {
		t.Fatalf("review.max_comment_findings = %v, want 0", result.Policy.Review.MaxCommentFindings)
	}
	if result.Policy.Review.MaxGraphPaths == nil || *result.Policy.Review.MaxGraphPaths != 0 {
		t.Fatalf("review.max_graph_paths = %v, want 0", result.Policy.Review.MaxGraphPaths)
	}
	if result.Policy.Impact.IncludeExistingRisks == nil || *result.Policy.Impact.IncludeExistingRisks {
		t.Fatalf("impact.include_existing_risks override was not false")
	}
	if result.Policy.Impact.IncludeResolvedRisks == nil || *result.Policy.Impact.IncludeResolvedRisks {
		t.Fatalf("impact.include_resolved_risks override was not false")
	}
	if result.Policy.Impact.IncludeWaivers == nil || *result.Policy.Impact.IncludeWaivers {
		t.Fatalf("impact.include_waivers override was not false")
	}
	if result.Policy.AttackPaths.Enabled == nil || *result.Policy.AttackPaths.Enabled {
		t.Fatalf("attack_paths.enabled override was not false")
	}
	if len(result.Policy.AttackPaths.Block) != 1 || result.Policy.AttackPaths.Block[0].Type != "public_to_sensitive_data" {
		t.Fatalf("attack_paths.block override = %#v", result.Policy.AttackPaths.Block)
	}
}

func TestValidateReviewIntelligenceRejectsInvalidLimits(t *testing.T) {
	t.Parallel()

	registry, err := rules.DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	result := Validate(Config{
		Review: ReviewConfig{
			MaxCommentFindings: intPtr(-1),
			MaxGraphPaths:      intPtr(-1),
		},
	}, registry, rules.DefaultPolicyPacks())
	if result.Valid {
		t.Fatalf("policy unexpectedly valid")
	}
	if len(result.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %d, want 2: %#v", len(result.Diagnostics), result.Diagnostics)
	}
}
