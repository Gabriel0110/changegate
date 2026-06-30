package rules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestDefaultRegistryMetadata(t *testing.T) {
	t.Parallel()

	registry, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	registered := registry.Rules()
	if len(registered) < 6 {
		t.Fatalf("registered rules = %d, want at least 6", len(registered))
	}
	for _, rule := range registered {
		meta := rule.Metadata()
		if err := ValidateMetadata(meta); err != nil {
			t.Fatalf("metadata invalid for %s: %v", meta.ID, err)
		}
		if len(meta.Resources) == 0 {
			t.Fatalf("rule %s has no declared resources", meta.ID)
		}
		if meta.Documentation.Summary == "" {
			t.Fatalf("rule %s has no documentation summary", meta.ID)
		}
	}
}

func TestDocumentationMarkdown(t *testing.T) {
	t.Parallel()

	registry, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry returned error: %v", err)
	}
	rule, ok := registry.Get("AWS_SG_WORLD_OPEN_ADMIN_PORT")
	if !ok {
		t.Fatalf("rule not found")
	}
	doc := DocumentationMarkdown(rule.Metadata())
	for _, want := range []string{
		"# Security group opens admin port to the world",
		"* ID: AWS_SG_WORLD_OPEN_ADMIN_PORT",
		"* Status: stable",
		"Remove `0.0.0.0/0` and `::/0` from admin-port ingress rules.",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("doc missing %q:\n%s", want, doc)
		}
	}
}

func TestRunnerDeterministicAndFaultTolerant(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	for _, rule := range []Rule{
		testRule{id: "ZZZ_RULE", resource: "aws_s3_bucket.z"},
		panicRule{id: "PANIC_RULE"},
		errorRule{id: "ERROR_RULE"},
		testRule{id: "AAA_RULE", resource: "aws_s3_bucket.a"},
	} {
		if err := registry.Register(rule); err != nil {
			t.Fatalf("register: %v", err)
		}
	}

	result := NewRunner(registry).Evaluate(context.Background(), RuleInput{}, Selection{})
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(result.Findings))
	}
	if result.Findings[0].RuleID != "AAA_RULE" || result.Findings[1].RuleID != "ZZZ_RULE" {
		t.Fatalf("findings not deterministic: %#v", result.Findings)
	}
	if len(result.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %d, want 2", len(result.Diagnostics))
	}

	parallel := NewRunner(registry, WithParallelism(4)).Evaluate(context.Background(), RuleInput{}, Selection{})
	if len(parallel.Findings) != len(result.Findings) || parallel.Findings[0].ID != result.Findings[0].ID || parallel.Findings[1].ID != result.Findings[1].ID {
		t.Fatalf("parallel findings differ from sequential\nsequential: %#v\nparallel: %#v", result.Findings, parallel.Findings)
	}
	if len(parallel.Diagnostics) != len(result.Diagnostics) {
		t.Fatalf("parallel diagnostics = %d, want %d", len(parallel.Diagnostics), len(result.Diagnostics))
	}
}

func TestRunnerFailClosedRuleProducesFinding(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if err := registry.Register(failClosedRule{id: "CUSTOM_FAIL_CLOSED"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	result := NewRunner(registry).Evaluate(context.Background(), RuleInput{}, Selection{})
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want fail-closed finding", len(result.Findings))
	}
	if result.Findings[0].Severity != model.SeverityHigh || result.Findings[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("finding did not enforce high/high: %#v", result.Findings[0])
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Severity != model.DiagnosticError {
		t.Fatalf("diagnostics = %#v, want one error diagnostic", result.Diagnostics)
	}
}

func TestRunnerSelectionOverridesAndExperimentalSuppression(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	exp := testRule{id: "EXP_RULE", resource: "aws_s3_bucket.exp"}
	exp.status = StatusExperimental
	stable := testRule{id: "STABLE_RULE", resource: "aws_s3_bucket.stable"}
	if err := registry.Register(exp); err != nil {
		t.Fatalf("register exp: %v", err)
	}
	if err := registry.Register(stable); err != nil {
		t.Fatalf("register stable: %v", err)
	}

	low := model.SeverityLow
	result := NewRunner(registry).Evaluate(context.Background(), RuleInput{}, Selection{
		EnabledRules: map[string]bool{
			"EXP_RULE":    true,
			"STABLE_RULE": true,
		},
		Overrides: map[string]model.Override{
			"STABLE_RULE": {
				Severity: &low,
				Reason:   "lower in dev",
			},
		},
	})
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(result.Findings))
	}

	var experimental model.Finding
	var overridden model.Finding
	for _, finding := range result.Findings {
		switch finding.RuleID {
		case "EXP_RULE":
			experimental = finding
		case "STABLE_RULE":
			overridden = finding
		}
	}
	if len(experimental.Suppressions) != 1 {
		t.Fatalf("experimental suppressions = %#v", experimental.Suppressions)
	}
	if overridden.Severity != model.SeverityLow {
		t.Fatalf("override severity = %q, want low", overridden.Severity)
	}
}

func TestDeprecatedRulesDisabledByDefault(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	deprecated := testRule{id: "DEPRECATED_RULE", resource: "aws_iam_role.old"}
	deprecated.status = StatusDeprecated
	if err := registry.Register(deprecated); err != nil {
		t.Fatalf("register deprecated: %v", err)
	}

	result := NewRunner(registry).Evaluate(context.Background(), RuleInput{}, Selection{})
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Findings))
	}

	result = NewRunner(registry).Evaluate(context.Background(), RuleInput{}, Selection{
		EnabledRules: map[string]bool{"DEPRECATED_RULE": true},
	})
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 when explicitly enabled", len(result.Findings))
	}
}

type testRule struct {
	id       string
	resource string
	status   Status
}

func (r testRule) Metadata() Metadata {
	status := r.status
	if status == "" {
		status = StatusStable
	}
	return Metadata{
		ID:           r.id,
		Title:        r.id + " title",
		Description:  r.id + " description",
		Category:     model.RiskCategoryPublicExposure,
		Severity:     model.SeverityHigh,
		Confidence:   model.ConfidenceHigh,
		Providers:    []string{"aws"},
		Resources:    []string{"aws_s3_bucket"},
		Capabilities: []Capability{CapabilityResourceChanges},
		Status:       status,
		Version:      "0.1.0",
		PolicyPack:   "test-pack",
		Documentation: Documentation{
			Summary: "test summary",
		},
	}
}

func (r testRule) Evaluate(context.Context, RuleInput) ([]model.Finding, error) {
	return []model.Finding{{
		ResourceAddress: r.resource,
		Provider:        "registry.terraform.io/hashicorp/aws",
		Environment:     "test",
		Evidence: []model.Evidence{{
			Type:     "test",
			Resource: r.resource,
			Path:     "test",
			Message:  "test evidence",
		}},
		Remediation: model.Remediation{Summary: "fix it"},
	}}, nil
}

type panicRule struct {
	id string
}

func (r panicRule) Metadata() Metadata {
	return testRule{id: r.id, resource: "panic"}.Metadata()
}

func (panicRule) Evaluate(context.Context, RuleInput) ([]model.Finding, error) {
	panic("boom")
}

type errorRule struct {
	id string
}

func (r errorRule) Metadata() Metadata {
	return testRule{id: r.id, resource: "error"}.Metadata()
}

func (errorRule) Evaluate(context.Context, RuleInput) ([]model.Finding, error) {
	return nil, errors.New("failed")
}

type failClosedRule struct {
	id string
}

func (r failClosedRule) Metadata() Metadata {
	return testRule{id: r.id, resource: "custom-rego"}.Metadata()
}

func (failClosedRule) Evaluate(context.Context, RuleInput) ([]model.Finding, error) {
	return nil, errors.New("policy failed")
}

func (failClosedRule) FailureFinding(err error) (model.Finding, bool) {
	return model.Finding{
		ResourceAddress: "custom-rego",
		Severity:        model.SeverityHigh,
		Confidence:      model.ConfidenceHigh,
		Evidence: []model.Evidence{{
			Type:     "test",
			Resource: "custom-rego",
			Path:     "evaluate",
			Value:    err.Error(),
			Message:  "test policy failed",
		}},
	}, true
}
