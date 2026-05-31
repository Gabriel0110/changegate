package risktest

import (
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestLoadManifestStrictlyValidatesUnknownFields(t *testing.T) {
	t.Parallel()

	_, err := Load(strings.NewReader(`
version: 1
tests:
  - name: bad
    plan: fixture.json
    unexpected: true
    expect:
      decision: block
`))
	if err == nil {
		t.Fatal("Load returned nil error for unknown field")
	}
	if !strings.Contains(err.Error(), "field unexpected not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadManifestParsesExpectations(t *testing.T) {
	t.Parallel()

	manifest, err := Load(strings.NewReader(`
version: 1
tests:
  - name: public_admin_service_should_block
    plan: fixtures/public-admin-service.json
    config: fixtures/changegate.yaml
    expect:
      decision: block
      findings:
        include:
          - AWS_PUBLIC_ADMIN_SERVICE
        exclude:
          - AWS_PUBLIC_RDS_INSTANCE
      severity_count:
        critical: 1
      attack_paths:
        include:
          - public_to_sensitive_data
      graph_paths:
        include:
          - aws_lb.admin -> aws_db_instance.customer
      risk_movement:
        new_high: 2
      waivers:
        not_applied:
          - AWS_PUBLIC_ADMIN_SERVICE
      snapshot: snapshots/public-admin.json
`))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if manifest.Version != ManifestVersion || len(manifest.Tests) != 1 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	test := manifest.Tests[0]
	if test.Name != "public_admin_service_should_block" || test.Expect.Decision != model.DecisionBlock {
		t.Fatalf("unexpected test: %#v", test)
	}
	if test.Expect.RiskMovement.NewHigh == nil || *test.Expect.RiskMovement.NewHigh != 2 {
		t.Fatalf("risk movement not parsed: %#v", test.Expect.RiskMovement)
	}
}

func TestValidateRejectsInvalidManifest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		manifest Manifest
		want     string
	}{
		{name: "version", manifest: Manifest{Version: 2, Tests: []TestCase{{Name: "x", Plan: "plan.json"}}}, want: "version must be 1"},
		{name: "empty", manifest: Manifest{Version: 1}, want: "tests must contain"},
		{name: "missing name", manifest: Manifest{Version: 1, Tests: []TestCase{{Plan: "plan.json"}}}, want: "name is required"},
		{name: "duplicate", manifest: Manifest{Version: 1, Tests: []TestCase{{Name: "x", Plan: "one.json"}, {Name: "x", Plan: "two.json"}}}, want: "duplicated"},
		{name: "missing plan", manifest: Manifest{Version: 1, Tests: []TestCase{{Name: "x"}}}, want: "plan is required"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tt.manifest)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
