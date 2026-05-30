package adapters

import (
	"encoding/json"
	"fmt"

	"github.com/Gabriel0110/changegate/internal/model"
)

type genericEnvelope struct {
	Findings []genericFinding `json:"findings"`
	Results  []genericFinding `json:"results"`
}

type genericFinding struct {
	RuleID          string           `json:"rule_id"`
	ID              string           `json:"id"`
	Title           string           `json:"title"`
	Name            string           `json:"name"`
	Description     string           `json:"description"`
	ResourceAddress string           `json:"resource_address"`
	Resource        string           `json:"resource"`
	Provider        string           `json:"provider"`
	Category        string           `json:"category"`
	Severity        string           `json:"severity"`
	Confidence      string           `json:"confidence"`
	Remediation     string           `json:"remediation"`
	Evidence        []model.Evidence `json:"evidence"`
}

func parseGeneric(body []byte) ([]model.Finding, error) {
	var items []genericFinding
	if err := json.Unmarshal(body, &items); err != nil {
		var envelope genericEnvelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, fmt.Errorf("parse generic JSON findings: %w", err)
		}
		items = envelope.Findings
		if len(items) == 0 {
			items = envelope.Results
		}
	}

	findings := make([]model.Finding, 0, len(items))
	for _, item := range items {
		ruleID := firstNonEmpty(item.RuleID, item.ID)
		title := firstNonEmpty(item.Title, item.Name, ruleID)
		resource := firstNonEmpty(item.ResourceAddress, item.Resource)
		findings = append(findings, model.Finding{
			RuleID:          ruleID,
			Title:           title,
			Description:     item.Description,
			ResourceAddress: resource,
			Provider:        firstNonEmpty(item.Provider, "external"),
			Category:        category(item.Category),
			Severity:        severity(item.Severity),
			Confidence:      confidence(item.Confidence),
			Evidence:        item.Evidence,
			Remediation: model.Remediation{
				Summary: item.Remediation,
			},
		})
	}
	return findings, nil
}
