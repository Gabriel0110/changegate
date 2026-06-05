package adapters

import (
	"encoding/json"
	"fmt"

	"github.com/Gabriel0110/changegate/internal/model"
)

type kicsOutput struct {
	Queries *[]kicsQuery `json:"queries"`
}

type kicsQuery struct {
	QueryID     string     `json:"query_id"`
	QueryName   string     `json:"query_name"`
	Severity    string     `json:"severity"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	Platform    string     `json:"platform"`
	Files       []kicsFile `json:"files"`
}

type kicsFile struct {
	FileName     string `json:"file_name"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	SearchKey    string `json:"search_key"`
	IssueType    string `json:"issue_type"`
	Line         int    `json:"line"`
}

func parseKICS(body []byte) ([]model.Finding, error) {
	var output kicsOutput
	if err := json.Unmarshal(body, &output); err != nil {
		return nil, fmt.Errorf("parse KICS JSON: %w", err)
	}
	if output.Queries == nil {
		return nil, fmt.Errorf("parse KICS JSON: missing queries")
	}
	findings := make([]model.Finding, 0)
	for _, query := range *output.Queries {
		for _, file := range query.Files {
			resource := firstNonEmpty(file.ResourceID, file.SearchKey, file.FileName)
			path := file.FileName
			if file.Line > 0 {
				path = fmt.Sprintf("%s:%d", file.FileName, file.Line)
			}
			findings = append(findings, model.Finding{
				RuleID:          query.QueryID,
				RuleName:        query.QueryName,
				Title:           firstNonEmpty(query.QueryName, query.QueryID),
				Description:     query.Description,
				ResourceAddress: resource,
				Provider:        "external",
				Category:        category(firstNonEmpty(query.Category, file.IssueType, file.ResourceType)),
				Severity:        severity(query.Severity),
				Confidence:      model.ConfidenceMedium,
				Evidence: []model.Evidence{{
					Type:     "external_location",
					Resource: resource,
					Path:     path,
					Value:    file.ResourceType,
					Message:  "KICS query match",
				}},
			})
		}
	}
	return findings, nil
}
