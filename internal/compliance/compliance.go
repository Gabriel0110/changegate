// Package compliance attaches framework metadata to real ChangeGate findings.
package compliance

import (
	"sort"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
)

// BuildReport maps findings to compliance metadata without changing decisions.
func BuildReport(findings []model.Finding) output.ComplianceReport {
	mappings := defaultMappings()
	report := output.ComplianceReport{
		Mappings: mappings,
		Findings: make([]output.ComplianceFinding, 0),
		Summary:  make(map[string]int),
	}
	for _, finding := range findings {
		mapping, ok := mappings[finding.RuleID]
		if !ok {
			continue
		}
		report.Findings = append(report.Findings, output.ComplianceFinding{
			FindingID:  finding.ID,
			RuleID:     finding.RuleID,
			Resource:   finding.ResourceAddress,
			Frameworks: copyFrameworks(mapping.Frameworks),
			ActualRisk: true,
			Suppressed: findingSuppressed(finding),
		})
		for framework := range mapping.Frameworks {
			report.Summary[framework]++
		}
	}
	sort.SliceStable(report.Findings, func(i int, j int) bool {
		left := report.Findings[i]
		right := report.Findings[j]
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		if left.Resource != right.Resource {
			return left.Resource < right.Resource
		}
		return left.FindingID < right.FindingID
	})
	return report
}

func defaultMappings() map[string]output.ComplianceMapping {
	return map[string]output.ComplianceMapping{
		"AWS_PUBLIC_RDS_INSTANCE": mapping(map[string][]string{
			"cis_aws":     {"2.3.3"},
			"nist_800_53": {"SC-7", "AC-4"},
			"pci_dss":     {"1.2"},
		}),
		"AWS_SG_WORLD_OPEN_ADMIN_PORT": mapping(map[string][]string{
			"cis_aws":     {"4.1"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2.1"},
		}),
		"AWS_SG_WORLD_OPEN_DB_PORT": mapping(map[string][]string{
			"cis_aws":     {"4.2"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2.1"},
		}),
		"AWS_IAM_WILDCARD_ADMIN": mapping(map[string][]string{
			"cis_aws":     {"1.16"},
			"nist_800_53": {"AC-2", "AC-6"},
			"pci_dss":     {"7.2"},
		}),
		"AWS_IAM_ADMIN_POLICY_ATTACHMENT": mapping(map[string][]string{
			"cis_aws":     {"1.16"},
			"nist_800_53": {"AC-2", "AC-6"},
			"pci_dss":     {"7.2"},
		}),
		"AWS_KMS_DECRYPT_BROAD": mapping(map[string][]string{
			"nist_800_53": {"SC-12", "SC-28"},
			"pci_dss":     {"3.6"},
		}),
		"AWS_SECRETS_READ_BROAD": mapping(map[string][]string{
			"nist_800_53": {"AC-6", "IA-5"},
			"pci_dss":     {"8.2"},
		}),
		"AWS_SENSITIVE_STORAGE_ENCRYPTION_DISABLED": mapping(map[string][]string{
			"cis_aws":     {"2.1.1"},
			"nist_800_53": {"SC-28"},
			"pci_dss":     {"3.5"},
		}),
		"AWS_RDS_BACKUP_RETENTION_DISABLED_PROD": mapping(map[string][]string{
			"nist_800_53": {"CP-9"},
			"pci_dss":     {"12.10"},
		}),
		"AWS_RDS_DELETION_PROTECTION_DISABLED_PROD": mapping(map[string][]string{
			"nist_800_53": {"CP-10", "SI-13"},
		}),
		"AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD": mapping(map[string][]string{
			"cis_aws":     {"2.1.5"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2"},
		}),
		"AWS_S3_SENSITIVE_BUCKET_LOGGING_DISABLED": mapping(map[string][]string{
			"cis_aws":     {"2.1.4"},
			"nist_800_53": {"AU-2", "AU-12"},
			"pci_dss":     {"10.2"},
		}),
	}
}

func mapping(frameworks map[string][]string) output.ComplianceMapping {
	return output.ComplianceMapping{Frameworks: copyFrameworks(frameworks)}
}

func copyFrameworks(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for framework, controls := range in {
		copied := append([]string{}, controls...)
		sort.Strings(copied)
		out[framework] = copied
	}
	return out
}

func findingSuppressed(finding model.Finding) bool {
	for _, suppression := range finding.Suppressions {
		if suppression.Active {
			return true
		}
	}
	return false
}
