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
