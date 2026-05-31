package terraform

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestLoadTerraformPlan(t *testing.T) {
	t.Parallel()

	file, err := os.Open("../testdata/terraform-plan.json")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer closeFile(file)

	plan, err := Load(file)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if plan.Tool != model.ToolTerraform {
		t.Fatalf("Tool = %q, want %q", plan.Tool, model.ToolTerraform)
	}
	if plan.FormatVersion != "1.0" {
		t.Fatalf("FormatVersion = %q, want 1.0", plan.FormatVersion)
	}
	if plan.Statistics.ResourceCount != 2 {
		t.Fatalf("ResourceCount = %d, want 2", plan.Statistics.ResourceCount)
	}
	if plan.Statistics.ChangeCount != 4 {
		t.Fatalf("ChangeCount = %d, want 4", plan.Statistics.ChangeCount)
	}
	if plan.Provider != "registry.terraform.io/hashicorp/aws" {
		t.Fatalf("Provider = %q", plan.Provider)
	}

	replacement := findChange(t, plan, "module.database.aws_db_instance.customer")
	if len(replacement.ModulePath) != 1 || replacement.ModulePath[0] != "database" {
		t.Fatalf("ModulePath = %#v, want [database]", replacement.ModulePath)
	}
	if len(replacement.Actions) != 1 || replacement.Actions[0] != model.ActionReplace {
		t.Fatalf("Actions = %#v, want replace", replacement.Actions)
	}
	if replacement.Before["password"] != "(sensitive)" {
		t.Fatalf("Before password was not redacted: %#v", replacement.Before["password"])
	}
	if replacement.After["password"] != "(sensitive)" {
		t.Fatalf("After password was not redacted: %#v", replacement.After["password"])
	}
	if !replacement.AfterSensitive["password"] {
		t.Fatalf("AfterSensitive missing password marker")
	}
	if len(replacement.ReplacePaths) != 1 || replacement.ReplacePaths[0] != "engine_version" {
		t.Fatalf("ReplacePaths = %#v", replacement.ReplacePaths)
	}

	create := findChange(t, plan, "aws_s3_bucket.logs")
	if create.AfterUnknown["arn"] != true {
		t.Fatalf("AfterUnknown did not preserve arn unknown marker")
	}
	if create.Tags["env"] != "prod" {
		t.Fatalf("Tags = %#v, want env=prod", create.Tags)
	}

	db := findResource(t, plan, "module.database.aws_db_instance.customer")
	if db.Values["password"] != "(sensitive)" {
		t.Fatalf("resource password was not redacted: %#v", db.Values["password"])
	}
	if db.Tags["env"] != "prod" {
		t.Fatalf("resource tags = %#v, want env=prod", db.Tags)
	}

	if plan.Configuration == nil {
		t.Fatalf("Configuration is nil")
	}
	if len(plan.Configuration.ProviderConfigs) != 1 {
		t.Fatalf("ProviderConfigs length = %d, want 1", len(plan.Configuration.ProviderConfigs))
	}
	if len(plan.Configuration.Resources) != 2 {
		t.Fatalf("Configuration.Resources length = %d, want 2", len(plan.Configuration.Resources))
	}
	if len(plan.AWSResources) != 2 {
		t.Fatalf("AWSResources length = %d, want 2", len(plan.AWSResources))
	}
}

func TestLoadOpenTofuPlan(t *testing.T) {
	t.Parallel()

	file, err := os.Open("../testdata/opentofu-plan.json")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer closeFile(file)

	plan, err := Load(file)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if plan.Tool != model.ToolOpenTofu {
		t.Fatalf("Tool = %q, want %q", plan.Tool, model.ToolOpenTofu)
	}
	if plan.Provider != "registry.opentofu.org/hashicorp/aws" {
		t.Fatalf("Provider = %q", plan.Provider)
	}
}

func TestLoadOpenTofuBooleanSensitiveMarkers(t *testing.T) {
	t.Parallel()

	plan, err := Load(strings.NewReader(`{
		"format_version": "1.0",
		"terraform_version": "1.12.1",
		"opentofu_version": "1.12.1",
		"resource_changes": [
			{
				"address": "aws_s3_bucket.example",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "example",
				"provider_name": "registry.opentofu.org/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {"bucket": "public-name", "tags_all": {"env": "test"}},
					"before_sensitive": false,
					"after_sensitive": {"tags_all": {}}
				}
			},
			{
				"address": "aws_secretsmanager_secret_version.example",
				"mode": "managed",
				"type": "aws_secretsmanager_secret_version",
				"name": "example",
				"provider_name": "registry.opentofu.org/hashicorp/aws",
				"change": {
					"actions": ["update"],
					"before": {"secret_string": "old-secret"},
					"after": {"secret_string": "new-secret"},
					"before_sensitive": true,
					"after_sensitive": true
				}
			}
		]
	}`))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if plan.Tool != model.ToolOpenTofu {
		t.Fatalf("Tool = %q, want %q", plan.Tool, model.ToolOpenTofu)
	}
	bucket := findChange(t, plan, "aws_s3_bucket.example")
	if bucket.After["bucket"] != "public-name" {
		t.Fatalf("non-sensitive bucket value was redacted: %#v", bucket.After["bucket"])
	}
	secret := findChange(t, plan, "aws_secretsmanager_secret_version.example")
	if secret.Before["secret_string"] != "(sensitive)" || secret.After["secret_string"] != "(sensitive)" {
		t.Fatalf("boolean sensitive marker did not redact whole change: before=%#v after=%#v", secret.Before, secret.After)
	}
	if !secret.BeforeSensitive[allSensitiveMarker] || !secret.AfterSensitive[allSensitiveMarker] {
		t.Fatalf("whole-object sensitive marker was not preserved")
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		kind string
	}{
		{
			name: "invalid json",
			body: "{",
			kind: "invalid_json",
		},
		{
			name: "missing format version",
			body: `{"resource_changes":[]}`,
			kind: "missing_format_version",
		},
		{
			name: "unsupported major version",
			body: `{"format_version":"2.0","resource_changes":[]}`,
			kind: "unsupported_format_version",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(strings.NewReader(tt.body))
			if err == nil {
				t.Fatalf("Load returned nil error")
			}
			var parseErr *ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
			if parseErr.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", parseErr.Kind, tt.kind)
			}
		})
	}
}

func TestMinorFormatVersionWarning(t *testing.T) {
	t.Parallel()

	plan, err := Load(strings.NewReader(`{"format_version":"1.1","resource_changes":[]}`))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(plan.Diagnostics) != 1 {
		t.Fatalf("Diagnostics length = %d, want 1", len(plan.Diagnostics))
	}
	if plan.Diagnostics[0].Code != "PLAN_FORMAT_MINOR_VERSION" {
		t.Fatalf("Diagnostic code = %q", plan.Diagnostics[0].Code)
	}
}

func TestSensitiveValuesDoNotLeakWhenMarshaled(t *testing.T) {
	t.Parallel()

	file, err := os.Open("../testdata/terraform-plan.json")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer closeFile(file)

	plan, err := Load(file)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	if bytes.Contains(encoded, []byte("super-secret")) || bytes.Contains(encoded, []byte("old-secret")) || bytes.Contains(encoded, []byte("new-secret")) {
		t.Fatalf("encoded model leaked sensitive values: %s", encoded)
	}
}

func TestLargePlan(t *testing.T) {
	t.Parallel()

	const changes = 10000
	var builder strings.Builder
	builder.WriteString(`{"format_version":"1.0","terraform_version":"1.6.6","resource_changes":[`)
	for index := 0; index < changes; index++ {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(fmt.Sprintf(`{"address":"aws_s3_bucket.bucket_%d","mode":"managed","type":"aws_s3_bucket","name":"bucket_%d","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"bucket-%d"},"after_unknown":{"arn":true}}}`, index, index, index))
	}
	builder.WriteString(`]}`)

	plan, err := Load(strings.NewReader(builder.String()))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if plan.Statistics.ChangeCount != changes {
		t.Fatalf("ChangeCount = %d, want %d", plan.Statistics.ChangeCount, changes)
	}
}

func findChange(t *testing.T, plan *model.Plan, address string) model.Change {
	t.Helper()
	for _, change := range plan.Changes {
		if change.Address == address {
			return change
		}
	}
	t.Fatalf("change %s not found", address)
	return model.Change{}
}

func findResource(t *testing.T, plan *model.Plan, address string) model.Resource {
	t.Helper()
	for _, resource := range plan.Resources {
		if resource.Address == address {
			return resource
		}
	}
	t.Fatalf("resource %s not found", address)
	return model.Resource{}
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}
