package adapters

import (
	"encoding/json"
	"fmt"

	"github.com/Gabriel0110/changegate/internal/model"
)

type checkovOutput struct {
	Results struct {
		FailedChecks []checkovCheck `json:"failed_checks"`
	} `json:"results"`
}

type checkovCheck struct {
	CheckID       string         `json:"check_id"`
	CheckName     string         `json:"check_name"`
	Resource      string         `json:"resource"`
	FilePath      string         `json:"file_path"`
	FileLineRange []int          `json:"file_line_range"`
	Guideline     string         `json:"guideline"`
	Severity      string         `json:"severity"`
	CheckResult   map[string]any `json:"check_result"`
}

func parseCheckov(body []byte) ([]model.Finding, error) {
	var output checkovOutput
	if err := json.Unmarshal(body, &output); err != nil {
		return nil, fmt.Errorf("parse Checkov JSON: %w", err)
	}
	findings := make([]model.Finding, 0, len(output.Results.FailedChecks))
	for _, check := range output.Results.FailedChecks {
		line := ""
		if len(check.FileLineRange) > 0 {
			line = fmt.Sprintf("%s:%d", check.FilePath, check.FileLineRange[0])
		} else {
			line = check.FilePath
		}
		findings = append(findings, model.Finding{
			RuleID:          check.CheckID,
			RuleName:        check.CheckName,
			Title:           firstNonEmpty(check.CheckName, check.CheckID),
			ResourceAddress: firstNonEmpty(check.Resource, check.FilePath),
			Provider:        "external",
			Category:        category(firstNonEmpty(check.CheckName, check.CheckID)),
			Severity:        severity(check.Severity),
			Confidence:      model.ConfidenceMedium,
			Evidence: []model.Evidence{{
				Type:     "external_location",
				Resource: firstNonEmpty(check.Resource, check.FilePath),
				Path:     line,
				Value:    check.CheckResult,
				Message:  "Checkov failed check",
			}},
			Remediation: model.Remediation{
				Summary: check.Guideline,
			},
		})
	}
	return findings, nil
}
