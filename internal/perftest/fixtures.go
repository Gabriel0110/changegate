// Package perftest provides deterministic synthetic fixtures for benchmarks.
package perftest

import (
	"encoding/json"
	"fmt"

	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/model"
)

// SyntheticPlan returns a deterministic normalized plan with the requested number of resources.
func SyntheticPlan(resources int) *model.Plan {
	if resources < 1 {
		resources = 1
	}
	plan := &model.Plan{
		Tool:          model.ToolTerraform,
		FormatVersion: "1.0",
		Provider:      "registry.terraform.io/hashicorp/aws",
		Resources:     make([]model.Resource, 0, resources),
		Changes:       make([]model.Change, 0, resources),
	}
	for i := 0; i < resources; i++ {
		address := fmt.Sprintf("aws_s3_bucket.logs_%04d", i)
		name := fmt.Sprintf("logs_%04d", i)
		values := map[string]any{
			"bucket": name,
			"tags": map[string]any{
				"env":         "prod",
				"sensitivity": "high",
			},
		}
		plan.Resources = append(plan.Resources, model.Resource{
			Address:  address,
			Mode:     "managed",
			Type:     "aws_s3_bucket",
			Name:     name,
			Provider: "registry.terraform.io/hashicorp/aws",
			Values:   values,
			Tags:     map[string]string{"env": "prod", "sensitivity": "high"},
		})
		plan.Changes = append(plan.Changes, model.Change{
			Address:  address,
			Mode:     "managed",
			Type:     "aws_s3_bucket",
			Name:     name,
			Provider: "registry.terraform.io/hashicorp/aws",
			Actions:  []model.Action{model.ActionUpdate},
			Before:   values,
			After:    values,
			Tags:     map[string]string{"env": "prod", "sensitivity": "high"},
		})
	}
	plan.Statistics = model.Statistics{ResourceCount: len(plan.Resources), ChangeCount: len(plan.Changes)}
	return plan
}

// TerraformPlanJSON returns deterministic Terraform show -json shaped plan bytes.
func TerraformPlanJSON(resources int) []byte {
	plan := SyntheticPlan(resources)
	rawResources := make([]map[string]any, 0, len(plan.Resources))
	rawChanges := make([]map[string]any, 0, len(plan.Changes))
	for _, resource := range plan.Resources {
		rawResources = append(rawResources, map[string]any{
			"address":       resource.Address,
			"mode":          resource.Mode,
			"type":          resource.Type,
			"name":          resource.Name,
			"provider_name": resource.Provider,
			"values":        resource.Values,
		})
	}
	for _, change := range plan.Changes {
		rawChanges = append(rawChanges, map[string]any{
			"address":       change.Address,
			"mode":          change.Mode,
			"type":          change.Type,
			"name":          change.Name,
			"provider_name": change.Provider,
			"change": map[string]any{
				"actions": []string{"update"},
				"before":  change.Before,
				"after":   change.After,
			},
		})
	}
	body, err := json.Marshal(map[string]any{
		"format_version":    "1.0",
		"terraform_version": "1.8.0",
		"planned_values": map[string]any{
			"root_module": map[string]any{
				"resources": rawResources,
			},
		},
		"resource_changes": rawChanges,
	})
	if err != nil {
		panic(err)
	}
	return body
}

// CloudSnapshot returns a redacted cloud-context snapshot matching the synthetic plan.
func CloudSnapshot(plan *model.Plan) cloudcontext.Snapshot {
	resources := make(map[string]cloudcontext.Resource, len(plan.Resources))
	for _, resource := range plan.Resources {
		falseValue := false
		resources[resource.Address] = cloudcontext.Resource{
			TerraformAddress:    resource.Address,
			Type:                resource.Type,
			Region:              "us-east-1",
			EncryptionEnabled:   &falseValue,
			PublicAccessBlocked: &falseValue,
			Tags:                map[string]string{"env": "prod"},
		}
	}
	return cloudcontext.Snapshot{
		Version:     cloudcontext.Version,
		Provider:    cloudcontext.ProviderAWS,
		GeneratedAt: "2026-05-30T00:00:00Z",
		Account:     cloudcontext.Account{ID: "123456789012"},
		Data:        cloudcontext.ResourceSet{Resources: resources},
	}
}
