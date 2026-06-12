package adapters

import (
	"encoding/json"
	"fmt"

	"github.com/Gabriel0110/changegate/internal/model"
)

type trivyOutput struct {
	Results *[]trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string                 `json:"Target"`
	Type              string                 `json:"Type"`
	Misconfigurations []trivyMisconfig       `json:"Misconfigurations"`
	Vulnerabilities   []trivyVulnerability   `json:"Vulnerabilities"`
	Secrets           []trivySecret          `json:"Secrets"`
	Licenses          []trivyLicenseFinding  `json:"Licenses"`
	CustomResources   map[string]interface{} `json:"CustomResources"`
}

type trivyMisconfig struct {
	ID            string `json:"ID"`
	Title         string `json:"Title"`
	Description   string `json:"Description"`
	Message       string `json:"Message"`
	Severity      string `json:"Severity"`
	Resolution    string `json:"Resolution"`
	CauseMetadata struct {
		Resource  string `json:"Resource"`
		Provider  string `json:"Provider"`
		Service   string `json:"Service"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	Severity         string `json:"Severity"`
	PrimaryURL       string `json:"PrimaryURL"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Title     string `json:"Title"`
	Severity  string `json:"Severity"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

type trivyLicenseFinding struct {
	Name     string `json:"Name"`
	Severity string `json:"Severity"`
}

func parseTrivy(body []byte) ([]model.Finding, error) {
	var output trivyOutput
	if err := json.Unmarshal(body, &output); err != nil {
		return nil, fmt.Errorf("parse Trivy JSON: %w", err)
	}
	if output.Results == nil {
		return nil, fmt.Errorf("parse Trivy JSON: missing Results")
	}
	findings := make([]model.Finding, 0)
	for _, result := range *output.Results {
		for _, item := range result.Misconfigurations {
			resource := firstNonEmpty(item.CauseMetadata.Resource, result.Target)
			path := result.Target
			if item.CauseMetadata.StartLine > 0 {
				path = fmt.Sprintf("%s:%d", result.Target, item.CauseMetadata.StartLine)
			}
			findings = append(findings, model.Finding{
				RuleID:          item.ID,
				Title:           firstNonEmpty(item.Title, item.ID),
				Description:     firstNonEmpty(item.Description, item.Message),
				ResourceAddress: resource,
				Provider:        "external",
				Category:        category(firstNonEmpty(item.CauseMetadata.Service, item.Title, item.ID)),
				Severity:        severity(item.Severity),
				Confidence:      model.ConfidenceMedium,
				Evidence: []model.Evidence{{
					Type:     "external_location",
					Resource: resource,
					Path:     path,
					Message:  "Trivy misconfiguration",
				}},
				Remediation: model.Remediation{Summary: item.Resolution},
			})
		}
		for _, item := range result.Vulnerabilities {
			resource := firstNonEmpty(item.PkgName, result.Target)
			findings = append(findings, model.Finding{
				RuleID:          item.VulnerabilityID,
				Title:           firstNonEmpty(item.Title, item.VulnerabilityID),
				Description:     item.Description,
				ResourceAddress: resource,
				Provider:        "external",
				Category:        model.RiskCategoryCompliance,
				Severity:        severity(item.Severity),
				Confidence:      model.ConfidenceMedium,
				Evidence: []model.Evidence{{
					Type:     "external_vulnerability",
					Resource: resource,
					Path:     result.Target,
					Value:    item.InstalledVersion,
					Message:  "Trivy vulnerability",
				}},
				Remediation: model.Remediation{
					Summary:    "Upgrade or replace the affected package version, or document an accepted vulnerability exception with an owner and expiration.",
					References: stringSlice(item.PrimaryURL),
				},
			})
		}
		for _, item := range result.Secrets {
			resource := result.Target
			path := result.Target
			if item.StartLine > 0 {
				path = fmt.Sprintf("%s:%d", result.Target, item.StartLine)
			}
			findings = append(findings, model.Finding{
				RuleID:          item.RuleID,
				Title:           firstNonEmpty(item.Title, item.RuleID),
				ResourceAddress: resource,
				Provider:        "external",
				Category:        model.RiskCategorySensitiveData,
				Severity:        severity(item.Severity),
				Confidence:      model.ConfidenceMedium,
				Evidence: []model.Evidence{{
					Type:     "external_secret",
					Resource: resource,
					Path:     path,
					Message:  "Trivy secret finding",
				}},
			})
		}
		for _, item := range result.Licenses {
			findings = append(findings, model.Finding{
				RuleID:          item.Name,
				Title:           item.Name,
				ResourceAddress: result.Target,
				Provider:        "external",
				Category:        model.RiskCategoryCompliance,
				Severity:        severity(item.Severity),
				Confidence:      model.ConfidenceMedium,
				Evidence: []model.Evidence{{
					Type:     "external_license",
					Resource: result.Target,
					Path:     result.Target,
					Message:  "Trivy license finding",
				}},
			})
		}
	}
	return findings, nil
}

func stringSlice(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}
