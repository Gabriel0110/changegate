// Package compliance attaches framework metadata to real ChangeGate findings.
package compliance

import (
	"sort"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
)

// BuildReport maps findings to compliance metadata without changing decisions.
func BuildReport(findings []model.Finding) output.ComplianceReport {
	return BuildReportWithMappings(findings, nil)
}

// BuildReportWithMappings maps findings to bundled and organization-provided compliance metadata.
func BuildReportWithMappings(findings []model.Finding, customMappings map[string]map[string][]string) output.ComplianceReport {
	mappings := defaultMappings()
	for ruleID, frameworks := range customMappings {
		mappings[ruleID] = mapping(frameworks)
	}
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
		"AWS_PUBLIC_ADMIN_SERVICE": mapping(map[string][]string{
			"cis_aws":     {"4.1"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2.1"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_PUBLIC_ADMIN_SERVICE_PATH": mapping(map[string][]string{
			"cis_aws":     {"4.1"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2.1"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_PUBLIC_INTERNAL_SERVICE": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7"},
			"soc2":        {"CC6.6"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_PUBLIC_RDS_INSTANCE": mapping(map[string][]string{
			"cis_aws":     {"2.3.3"},
			"nist_800_53": {"SC-7", "AC-4"},
			"pci_dss":     {"1.2"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_PUBLIC_OPENSEARCH_DOMAIN": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_PUBLIC_EKS_ENDPOINT_PROD": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_SG_WORLD_OPEN_ADMIN_PORT": mapping(map[string][]string{
			"cis_aws":     {"4.1"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2.1"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_SG_WORLD_OPEN_DB_PORT": mapping(map[string][]string{
			"cis_aws":     {"4.2"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2.1"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_EC2_PUBLIC_IP_ADMIN_INGRESS": mapping(map[string][]string{
			"cis_aws":     {"4.1"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2.1"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_IAM_WILDCARD_ADMIN": mapping(map[string][]string{
			"cis_aws":     {"1.16"},
			"nist_800_53": {"AC-2", "AC-6"},
			"pci_dss":     {"7.2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.15", "A.5.18"},
		}),
		"AWS_PASSROLE_WITH_COMPUTE_MUTATION": mapping(map[string][]string{
			"nist_800_53": {"AC-2", "AC-6"},
			"pci_dss":     {"7.2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.15", "A.5.18"},
		}),
		"AWS_IAM_PASSROLE_FUNCTION_ESCALATION": mapping(map[string][]string{
			"nist_800_53": {"AC-2", "AC-6"},
			"pci_dss":     {"7.2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.15", "A.5.18"},
		}),
		"AWS_ROLE_ASSUME_ADMIN_PATH": mapping(map[string][]string{
			"nist_800_53": {"AC-2", "AC-6"},
			"pci_dss":     {"7.2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.15", "A.5.18"},
		}),
		"AWS_IAM_ASSUME_ADMIN_PATH": mapping(map[string][]string{
			"nist_800_53": {"AC-2", "AC-6"},
			"pci_dss":     {"7.2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.15", "A.5.18"},
		}),
		"AWS_IAM_ADMIN_POLICY_ATTACHMENT": mapping(map[string][]string{
			"cis_aws":     {"1.16"},
			"nist_800_53": {"AC-2", "AC-6"},
			"pci_dss":     {"7.2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.15", "A.5.18"},
		}),
		"AWS_EXTERNAL_ACCOUNT_TRUST": mapping(map[string][]string{
			"nist_800_53": {"AC-2", "AC-6", "IA-2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.15", "A.5.16"},
		}),
		"AWS_GITHUB_OIDC_TRUST_BROAD": mapping(map[string][]string{
			"nist_800_53": {"AC-2", "AC-6", "IA-2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.15", "A.5.16"},
		}),
		"AWS_KMS_DECRYPT_BROAD": mapping(map[string][]string{
			"nist_800_53": {"SC-12", "SC-28"},
			"pci_dss":     {"3.6"},
			"soc2":        {"CC6.1", "CC6.7"},
			"iso_27001":   {"A.8.24"},
		}),
		"AWS_SECRETS_READ_BROAD": mapping(map[string][]string{
			"nist_800_53": {"AC-6", "IA-5"},
			"pci_dss":     {"8.2"},
			"soc2":        {"CC6.1", "CC6.3"},
			"iso_27001":   {"A.5.17", "A.8.24"},
		}),
		"AWS_SENSITIVE_STORAGE_ENCRYPTION_DISABLED": mapping(map[string][]string{
			"cis_aws":     {"2.1.1"},
			"nist_800_53": {"SC-28"},
			"pci_dss":     {"3.5"},
			"soc2":        {"CC6.7"},
			"iso_27001":   {"A.8.24"},
		}),
		"AWS_RDS_BACKUP_RETENTION_DISABLED_PROD": mapping(map[string][]string{
			"nist_800_53": {"CP-9"},
			"pci_dss":     {"12.10"},
			"soc2":        {"A1.2", "CC7.4"},
			"iso_27001":   {"A.5.30", "A.8.13"},
		}),
		"AWS_RDS_DELETION_PROTECTION_DISABLED_PROD": mapping(map[string][]string{
			"nist_800_53": {"CP-10", "SI-13"},
			"soc2":        {"A1.2", "CC7.4"},
			"iso_27001":   {"A.5.30", "A.8.13"},
		}),
		"AWS_RDS_REPLACEMENT_PROD": mapping(map[string][]string{
			"nist_800_53": {"CP-9", "CP-10", "SI-13"},
			"pci_dss":     {"12.10"},
			"soc2":        {"A1.2", "CC7.4"},
			"iso_27001":   {"A.5.30", "A.8.13"},
		}),
		"AWS_STATEFUL_REPLACEMENT": mapping(map[string][]string{
			"nist_800_53": {"CP-9", "CP-10", "SI-13"},
			"soc2":        {"A1.2", "CC7.4"},
			"iso_27001":   {"A.5.30", "A.8.13"},
		}),
		"AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD": mapping(map[string][]string{
			"cis_aws":     {"2.1.5"},
			"nist_800_53": {"AC-4", "SC-7"},
			"pci_dss":     {"1.2"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_S3_SENSITIVE_BUCKET_LOGGING_DISABLED": mapping(map[string][]string{
			"cis_aws":     {"2.1.4"},
			"nist_800_53": {"AU-2", "AU-12"},
			"pci_dss":     {"10.2"},
			"soc2":        {"CC7.2", "CC7.3"},
			"iso_27001":   {"A.8.15", "A.8.16"},
		}),
		"AWS_CLOUDFRONT_S3_PUBLIC_MISMATCH": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7"},
			"soc2":        {"CC6.6", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_PUBLIC_TO_SENSITIVE_DATASTORE": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7", "SC-28"},
			"pci_dss":     {"1.2", "3.5"},
			"soc2":        {"CC6.6", "CC6.7", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22", "A.8.24"},
		}),
		"AWS_PUBLIC_TO_SENSITIVE_DATA_PATH": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7", "SC-28"},
			"pci_dss":     {"1.2", "3.5"},
			"soc2":        {"CC6.6", "CC6.7", "CC7.1"},
			"iso_27001":   {"A.8.20", "A.8.22", "A.8.24"},
		}),
		"AWS_PRIVATE_SUBNET_ROUTE_TO_IGW": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7"},
			"soc2":        {"CC6.6"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_PRIVATE_WORKLOAD_EXPOSED_BY_NAT_OR_SG": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7"},
			"soc2":        {"CC6.6"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_TGW_ROUTE_TO_SENSITIVE_SUBNET": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7"},
			"soc2":        {"CC6.6"},
			"iso_27001":   {"A.8.20", "A.8.22"},
		}),
		"AWS_EGRESS_OPEN_FROM_SENSITIVE_WORKLOAD": mapping(map[string][]string{
			"nist_800_53": {"AC-4", "SC-7"},
			"soc2":        {"CC6.6"},
			"iso_27001":   {"A.8.20", "A.8.22"},
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
