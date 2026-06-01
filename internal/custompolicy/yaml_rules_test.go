package custompolicy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
)

func TestYAMLRuleEvaluatesSelectorConditionsAndGraphPredicates(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	rulePath := filepath.Join(tempDir, "rules.yaml")
	body := `id: ORG_PUBLIC_ADMIN
title: Public admin services are not allowed in production
category: public_exposure
severity: critical
confidence: high
select:
  type: aws_lb
where:
  all:
    - field: scheme
      equals: internet-facing
    - graph.routes_to.tag:
        key: service_type
        value: admin
    - graph.internet_exposed: true
remediation: Place admin service behind VPN.
`
	if err := os.WriteFile(rulePath, []byte(body), 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	loaded, diagnostics := LoadYAMLRules(filepath.Join(tempDir, ".changegate.yaml"), []string{"rules.yaml"}, 0, false)
	if len(diagnostics) > 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if len(loaded) != 1 {
		t.Fatalf("rules = %d, want 1", len(loaded))
	}

	plan := &model.Plan{Changes: []model.Change{{
		Address:  "aws_lb.admin",
		Type:     "aws_lb",
		Provider: "registry.terraform.io/hashicorp/aws",
		Actions:  []model.Action{model.ActionCreate},
		After:    map[string]any{"scheme": "internet-facing"},
	}}}
	resourceGraph := &graph.Graph{
		Nodes: map[graph.ResourceID]*graph.Node{
			graph.InternetNodeID: {ID: graph.InternetNodeID, Address: "internet", Type: "internet"},
			"aws_lb.admin":       {ID: "aws_lb.admin", Address: "aws_lb.admin", Type: "aws_lb"},
			"aws_ecs_service.admin": {
				ID:      "aws_ecs_service.admin",
				Address: "aws_ecs_service.admin",
				Type:    "aws_ecs_service",
				Tags:    map[string]string{"service_type": "admin"},
			},
		},
		Edges: []graph.Edge{
			{From: graph.InternetNodeID, To: "aws_lb.admin", Type: graph.EdgeRoutesTo},
			{From: "aws_lb.admin", To: "aws_ecs_service.admin", Type: graph.EdgeRoutesTo},
		},
	}

	findings, err := loaded[0].Evaluate(context.Background(), rules.RuleInput{Plan: plan, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].ResourceAddress != "aws_lb.admin" {
		t.Fatalf("resource = %q", findings[0].ResourceAddress)
	}
}

func TestYAMLRuleOptionalEmptyPatternDoesNotFail(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	loaded, diagnostics := LoadYAMLRules(filepath.Join(tempDir, ".changegate.yaml"), []string{"rules/*.yaml"}, 0, false)
	if len(loaded) != 0 || len(diagnostics) != 0 {
		t.Fatalf("optional empty pattern loaded=%d diagnostics=%#v, want none", len(loaded), diagnostics)
	}
	_, diagnostics = LoadYAMLRules(filepath.Join(tempDir, ".changegate.yaml"), []string{"rules/*.yaml"}, 0, true)
	if len(diagnostics) != 1 || diagnostics[0].Code != "CUSTOM_RULE_PATTERN_EMPTY" {
		t.Fatalf("required empty pattern diagnostics = %#v", diagnostics)
	}
}
