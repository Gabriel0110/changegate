package adapters

import (
	"encoding/json"
	"fmt"

	"github.com/Gabriel0110/changegate/internal/model"
)

type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name  string      `json:"name"`
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	Properties map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text     string `json:"text"`
		Markdown string `json:"markdown"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

func parseSARIF(body []byte) ([]model.Finding, error) {
	var log sarifLog
	if err := json.Unmarshal(body, &log); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}
	if log.Version != "" && log.Version != "2.1.0" {
		return nil, fmt.Errorf("unsupported SARIF version %q", log.Version)
	}
	findings := make([]model.Finding, 0)
	for _, run := range log.Runs {
		rules := sarifRulesByID(run.Tool.Driver.Rules)
		for _, result := range run.Results {
			rule := rules[result.RuleID]
			resource := sarifResource(result)
			title := result.Message.Text
			if title == "" {
				title = result.Message.Markdown
			}
			if title == "" {
				title = rule.Name
			}
			if title == "" {
				title = result.RuleID
			}
			finding := model.Finding{
				RuleID:          result.RuleID,
				RuleName:        rule.Name,
				Title:           title,
				Description:     firstNonEmpty(rule.FullDescription.Text, rule.ShortDescription.Text),
				ResourceAddress: resource,
				Provider:        "external",
				Category:        category(firstNonEmpty(asString(result.Properties["category"]), asString(rule.Properties["category"]), result.RuleID, title)),
				Severity:        severity(firstNonEmpty(asString(result.Properties["severity"]), asString(rule.Properties["severity"]), result.Level)),
				Confidence:      confidence(firstNonEmpty(asString(result.Properties["confidence"]), asString(rule.Properties["confidence"]))),
				Evidence: []model.Evidence{{
					Type:     "external_location",
					Resource: resource,
					Path:     sarifLocation(result),
					Value:    result.PartialFingerprints,
					Message:  "SARIF result location",
				}},
			}
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func sarifRulesByID(rules []sarifRule) map[string]sarifRule {
	out := make(map[string]sarifRule, len(rules))
	for _, rule := range rules {
		out[rule.ID] = rule
	}
	return out
}

func sarifResource(result sarifResult) string {
	for _, key := range []string{"resource_address", "resource", "address"} {
		if value := asString(result.Properties[key]); value != "" {
			return value
		}
	}
	if len(result.Locations) == 0 {
		return ""
	}
	return result.Locations[0].PhysicalLocation.ArtifactLocation.URI
}

func sarifLocation(result sarifResult) string {
	if len(result.Locations) == 0 {
		return ""
	}
	location := result.Locations[0].PhysicalLocation
	if location.Region.StartLine > 0 {
		return fmt.Sprintf("%s:%d", location.ArtifactLocation.URI, location.Region.StartLine)
	}
	return location.ArtifactLocation.URI
}
