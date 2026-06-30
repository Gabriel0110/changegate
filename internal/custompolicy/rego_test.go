package custompolicy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
)

func TestRegoRuleEvaluatesFindings(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	regoPath := filepath.Join(tempDir, "policy.rego")
	body := `package changegate

findings contains f if {
	change := input.changes[_]
	change.type == "aws_sqs_queue"
	f := {
		"rule_id": "ORG_QUEUE_REVIEW",
		"title": "SQS queue requires review",
		"resource_address": change.address,
		"category": "compliance",
		"severity": "high",
		"confidence": "high",
		"remediation": "Review queue access policy."
	}
}
`
	if err := os.WriteFile(regoPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	rule, diagnostics := LoadRegoRule(RegoOptions{
		PolicyPath:    filepath.Join(tempDir, ".changegate.yaml"),
		Files:         []string{"policy.rego"},
		Query:         "data.changegate.findings",
		Timeout:       time.Second,
		MaxInputBytes: 1024 * 1024,
	})
	if len(diagnostics) > 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if rule == nil {
		t.Fatalf("rego rule was nil")
	}
	plan := &model.Plan{Changes: []model.Change{{Address: "aws_sqs_queue.jobs", Type: "aws_sqs_queue"}}}
	findings, err := rule.Evaluate(context.Background(), rules.RuleInput{Plan: plan})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "ORG_QUEUE_REVIEW" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestRegoRuleRejectsUnsafeBuiltins(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	regoPath := filepath.Join(tempDir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte(`package changegate
allow if { http.send({"method": "get", "url": "https://example.com"}) }`), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	rule, diagnostics := LoadRegoRule(RegoOptions{PolicyPath: filepath.Join(tempDir, ".changegate.yaml"), Files: []string{"policy.rego"}})
	if rule != nil {
		t.Fatalf("rule = %#v, want nil", rule)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "REGO_UNSAFE_BUILTIN" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestRegoRuleRejectsInvalidModulesAtLoadTime(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	regoPath := filepath.Join(tempDir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte(`package changegate
findings contains f if {
	f := {
}`), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	rule, diagnostics := LoadRegoRule(RegoOptions{
		PolicyPath: filepath.Join(tempDir, ".changegate.yaml"),
		Files:      []string{"policy.rego"},
		Query:      "data.changegate.findings",
		Timeout:    time.Second,
	})
	if rule != nil {
		t.Fatalf("rule = %#v, want nil", rule)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "REGO_COMPILE_FAILED" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestRegoRuleRejectsOversizedModuleBeforeRead(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	regoPath := filepath.Join(tempDir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte("package changegate\n"+strings.Repeat("#", int(defaultRegoMaxModuleSize)+1)), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	rule, diagnostics := LoadRegoRule(RegoOptions{PolicyPath: filepath.Join(tempDir, ".changegate.yaml"), Files: []string{"policy.rego"}})
	if rule != nil {
		t.Fatalf("rule = %#v, want nil", rule)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "REGO_FILE_READ_FAILED" || !strings.Contains(diagnostics[0].Message, "exceeds") {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestRegoRuleFailureFindingEnforcesPolicyFailure(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	regoPath := filepath.Join(tempDir, "policy.rego")
	body := `package changegate

findings contains f if {
	f := {"rule_id": "ORG_REVIEW", "resource": "aws_s3_bucket.logs"}
}`
	if err := os.WriteFile(regoPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	rule, diagnostics := LoadRegoRule(RegoOptions{
		PolicyPath:    filepath.Join(tempDir, ".changegate.yaml"),
		Files:         []string{"policy.rego"},
		Query:         "data.changegate.findings",
		Timeout:       time.Second,
		MaxInputBytes: 1,
	})
	if len(diagnostics) > 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	findings, err := rule.Evaluate(context.Background(), rules.RuleInput{Plan: &model.Plan{Changes: []model.Change{{Address: "aws_s3_bucket.logs"}}}})
	if err == nil {
		t.Fatalf("Evaluate returned nil error and findings %#v, want max input error", findings)
	}
	failureRule, ok := rule.(rules.FailureFindingRule)
	if !ok {
		t.Fatalf("rego rule does not implement fail-closed contract")
	}
	finding, enforce := failureRule.FailureFinding(err)
	if !enforce || finding.Severity != model.SeverityHigh || finding.Confidence != model.ConfidenceHigh {
		t.Fatalf("failure finding = %#v enforce=%v, want high/high enforcing", finding, enforce)
	}
}
