package adapters

import (
	"encoding/json"
	"fmt"

	"github.com/Gabriel0110/changegate/internal/model"
)

type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		DataSource  string `json:"dataSource"`
	} `json:"vulnerability"`
	Artifact struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Version   string `json:"version"`
		Language  string `json:"language"`
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
	} `json:"artifact"`
}

func parseGrype(body []byte) ([]model.Finding, error) {
	var output grypeOutput
	if err := json.Unmarshal(body, &output); err != nil {
		return nil, fmt.Errorf("parse Grype JSON: %w", err)
	}
	findings := make([]model.Finding, 0, len(output.Matches))
	for _, match := range output.Matches {
		resource := match.Artifact.Name
		path := ""
		if len(match.Artifact.Locations) > 0 {
			path = match.Artifact.Locations[0].Path
		}
		findings = append(findings, model.Finding{
			RuleID:          match.Vulnerability.ID,
			Title:           match.Vulnerability.ID + " in " + match.Artifact.Name,
			Description:     match.Vulnerability.Description,
			ResourceAddress: resource,
			Provider:        "external",
			Category:        model.RiskCategoryCompliance,
			Severity:        severity(match.Vulnerability.Severity),
			Confidence:      model.ConfidenceMedium,
			Evidence: []model.Evidence{{
				Type:     "external_vulnerability",
				Resource: resource,
				Path:     path,
				Value: map[string]string{
					"type":     match.Artifact.Type,
					"version":  match.Artifact.Version,
					"language": match.Artifact.Language,
				},
				Message: "Grype vulnerability match",
			}},
			Remediation: model.Remediation{References: stringSlice(match.Vulnerability.DataSource)},
		})
	}
	return findings, nil
}
