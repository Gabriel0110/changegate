package output

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
)

// RiskCluster groups related low-level findings into one human-review risk.
type RiskCluster struct {
	ID                 string                     `json:"id"`
	Title              string                     `json:"title"`
	Description        string                     `json:"description,omitempty"`
	Decision           model.Decision             `json:"decision"`
	Severity           model.Severity             `json:"severity"`
	Confidence         model.Confidence           `json:"confidence"`
	Category           model.RiskCategory         `json:"category"`
	AffectedResources  []string                   `json:"affected_resources"`
	SupportingFindings []string                   `json:"supporting_findings"`
	RuleIDs            []string                   `json:"rule_ids"`
	ReasonCodes        []model.DecisionReasonCode `json:"reason_codes,omitempty"`
	PrimaryFindingID   string                     `json:"primary_finding_id,omitempty"`
	RemediationSummary string                     `json:"remediation_summary,omitempty"`
}

type clusterDraft struct {
	key      string
	title    string
	category model.RiskCategory
	findings []model.Finding
}

// BuildRiskClusters creates deterministic human-review clusters without removing raw findings.
func BuildRiskClusters(findings []model.Finding) []RiskCluster {
	if len(findings) == 0 {
		return nil
	}
	drafts := make(map[string]*clusterDraft)
	publicAdminResources := publicAdminResources(findings)
	for _, finding := range findings {
		key, title, category := classifyCluster(finding, publicAdminResources)
		draft := drafts[key]
		if draft == nil {
			draft = &clusterDraft{key: key, title: title, category: category}
			drafts[key] = draft
		}
		draft.findings = append(draft.findings, finding)
	}

	clusters := make([]RiskCluster, 0, len(drafts))
	for _, draft := range drafts {
		clusters = append(clusters, buildCluster(*draft))
	}
	sort.SliceStable(clusters, func(i int, j int) bool {
		for _, cmp := range []int{
			compareInt(severityRank(clusters[j].Severity), severityRank(clusters[i].Severity)),
			compareInt(confidenceRank(clusters[j].Confidence), confidenceRank(clusters[i].Confidence)),
			compareInt(decisionRank(clusters[j].Decision), decisionRank(clusters[i].Decision)),
			strings.Compare(clusters[i].Title, clusters[j].Title),
			strings.Compare(clusters[i].ID, clusters[j].ID),
		} {
			if cmp < 0 {
				return true
			}
			if cmp > 0 {
				return false
			}
		}
		return false
	})
	return clusters
}

func classifyCluster(finding model.Finding, publicAdminResources map[string]bool) (string, string, model.RiskCategory) {
	switch {
	case isPublicAdminSensitivePath(finding, publicAdminResources):
		return "public-admin-sensitive-path", "Public admin service reaches sensitive data", model.RiskCategorySensitiveData
	case isPublicSensitiveDataPath(finding):
		return "public-sensitive-data-path", "Public entrypoint reaches sensitive data", model.RiskCategorySensitiveData
	case isRDSResilienceFinding(finding):
		return "production-rds-resilience", "Production RDS resilience controls disabled", model.RiskCategoryAvailability
	case isIAMEscalationFinding(finding):
		return "iam-privilege-escalation-path", "IAM principal can reach elevated access", model.RiskCategoryPrivilegeEscalation
	default:
		key := "rule:" + finding.RuleID
		title := firstNonEmpty(finding.Title, finding.RuleName, finding.RuleID)
		return key, title, finding.Category
	}
}

func publicAdminResources(findings []model.Finding) map[string]bool {
	out := make(map[string]bool)
	for _, finding := range findings {
		if finding.RuleID == "AWS_PUBLIC_ADMIN_SERVICE" || finding.RuleID == "AWS_PUBLIC_ADMIN_SERVICE_PATH" {
			out[finding.ResourceAddress] = true
			for _, evidence := range finding.Evidence {
				for _, resource := range evidenceResources(evidence) {
					out[resource] = true
				}
			}
		}
	}
	return out
}

func isPublicAdminSensitivePath(finding model.Finding, publicAdminResources map[string]bool) bool {
	switch finding.RuleID {
	case "AWS_PUBLIC_ADMIN_SERVICE", "AWS_PUBLIC_ADMIN_SERVICE_PATH":
		return true
	case "AWS_PUBLIC_TO_SENSITIVE_DATA_PATH", "AWS_PUBLIC_TO_SENSITIVE_DATASTORE":
		return findingReferencesAnyResource(finding, publicAdminResources)
	default:
		return false
	}
}

func findingReferencesAnyResource(finding model.Finding, resources map[string]bool) bool {
	if len(resources) == 0 {
		return false
	}
	if resources[finding.ResourceAddress] {
		return true
	}
	for _, evidence := range finding.Evidence {
		for _, resource := range evidenceResources(evidence) {
			if resources[resource] {
				return true
			}
		}
	}
	return false
}

func evidenceResources(evidence model.Evidence) []string {
	out := make([]string, 0, 4)
	if evidence.Resource != "" {
		out = append(out, evidence.Resource)
	}
	collectEvidenceValueResources(evidence.Value, &out)
	return out
}

func collectEvidenceValueResources(value any, out *[]string) {
	switch typed := value.(type) {
	case string:
		if looksLikeResourceAddress(typed) {
			*out = append(*out, typed)
		}
	case []string:
		for _, item := range typed {
			if looksLikeResourceAddress(item) {
				*out = append(*out, item)
			}
		}
	case []any:
		for _, item := range typed {
			collectEvidenceValueResources(item, out)
		}
	case map[string]any:
		for _, item := range typed {
			collectEvidenceValueResources(item, out)
		}
	}
}

func looksLikeResourceAddress(value string) bool {
	return strings.Contains(value, ".") && !strings.ContainsAny(value, " \t\n")
}

func isPublicSensitiveDataPath(finding model.Finding) bool {
	switch finding.RuleID {
	case "AWS_PUBLIC_TO_SENSITIVE_DATA_PATH",
		"AWS_PUBLIC_TO_SENSITIVE_DATASTORE",
		"AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA",
		"AWS_PUBLIC_API_GATEWAY_TO_SENSITIVE_DATA",
		"AWS_PUBLIC_WORKLOAD_READS_SECRET",
		"AWS_PUBLIC_WORKLOAD_KMS_KEY_ACCESS",
		"AWS_PUBLIC_WORKLOAD_S3_DATA_ACCESS":
		return true
	default:
		return false
	}
}

func isRDSResilienceFinding(finding model.Finding) bool {
	if !strings.HasPrefix(finding.RuleID, "AWS_RDS_") {
		return false
	}
	if finding.Category == model.RiskCategoryAvailability {
		return true
	}
	rule := strings.ToUpper(finding.RuleID)
	return strings.Contains(rule, "BACKUP") || strings.Contains(rule, "DELETION_PROTECTION") || strings.Contains(rule, "FINAL_SNAPSHOT") || strings.Contains(rule, "REPLACEMENT")
}

func isIAMEscalationFinding(finding model.Finding) bool {
	rule := strings.ToUpper(finding.RuleID)
	if finding.Category == model.RiskCategoryPrivilegeEscalation {
		return true
	}
	return strings.Contains(rule, "PASSROLE") || strings.Contains(rule, "ASSUME_ADMIN") || strings.Contains(rule, "FUNCTION_ESCALATION")
}

func buildCluster(draft clusterDraft) RiskCluster {
	sortFindingsForCluster(draft.findings)
	resources := make([]string, 0)
	ruleIDs := make([]string, 0)
	findingIDs := make([]string, 0, len(draft.findings))
	reasons := make([]model.DecisionReasonCode, 0)
	seenResources := make(map[string]bool)
	seenRules := make(map[string]bool)
	seenReasons := make(map[model.DecisionReasonCode]bool)

	cluster := RiskCluster{
		Title:      draft.title,
		Category:   draft.category,
		Decision:   model.DecisionAllow,
		Severity:   model.SeverityInfo,
		Confidence: model.ConfidenceUnknown,
	}
	for index, finding := range draft.findings {
		if index == 0 {
			cluster.PrimaryFindingID = finding.ID
			cluster.Description = finding.Description
			cluster.RemediationSummary = finding.Remediation.Summary
		}
		cluster.Severity = maxSeverity(cluster.Severity, finding.Severity)
		cluster.Confidence = maxConfidence(cluster.Confidence, finding.Confidence)
		cluster.Decision = maxDecision(cluster.Decision, decisionForFinding(finding))
		findingIDs = append(findingIDs, finding.ID)
		if finding.ResourceAddress != "" && !seenResources[finding.ResourceAddress] {
			seenResources[finding.ResourceAddress] = true
			resources = append(resources, finding.ResourceAddress)
		}
		if finding.RuleID != "" && !seenRules[finding.RuleID] {
			seenRules[finding.RuleID] = true
			ruleIDs = append(ruleIDs, finding.RuleID)
		}
		for _, reason := range finding.DecisionReasonCodes {
			if !seenReasons[reason] {
				seenReasons[reason] = true
				reasons = append(reasons, reason)
			}
		}
	}
	sort.Strings(resources)
	sort.Strings(ruleIDs)
	sort.Slice(reasons, func(i int, j int) bool { return reasons[i] < reasons[j] })
	cluster.AffectedResources = resources
	cluster.RuleIDs = ruleIDs
	cluster.SupportingFindings = findingIDs
	cluster.ReasonCodes = reasons
	cluster.ID = stableClusterID(draft.key, findingIDs)
	return cluster
}

func sortFindingsForCluster(findings []model.Finding) {
	sort.SliceStable(findings, func(i int, j int) bool {
		left := findings[i]
		right := findings[j]
		for _, cmp := range []int{
			compareInt(severityRank(right.Severity), severityRank(left.Severity)),
			compareInt(confidenceRank(right.Confidence), confidenceRank(left.Confidence)),
			compareInt(decisionRank(decisionForFinding(right)), decisionRank(decisionForFinding(left))),
			strings.Compare(left.ResourceAddress, right.ResourceAddress),
			strings.Compare(left.RuleID, right.RuleID),
			strings.Compare(left.Fingerprint, right.Fingerprint),
		} {
			if cmp < 0 {
				return true
			}
			if cmp > 0 {
				return false
			}
		}
		return false
	})
}

func stableClusterID(key string, findingIDs []string) string {
	hash := sha256.New()
	hash.Write([]byte(key))
	for _, id := range findingIDs {
		hash.Write([]byte{0})
		hash.Write([]byte(id))
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	return "RISK-" + strings.ToUpper(sum[:16])
}

func decisionForFinding(finding model.Finding) model.Decision {
	if len(finding.DecisionReasonCodes) > 0 {
		decision := model.DecisionAllow
		for _, code := range finding.DecisionReasonCodes {
			switch code {
			case model.ReasonSuppressed, model.ReasonExistingRisk, model.ReasonChangedResourceOnly:
				decision = maxDecision(decision, model.DecisionAllow)
			case model.ReasonMeetsBlockThreshold:
				decision = maxDecision(decision, model.DecisionBlock)
			case model.ReasonBelowBlockThreshold, model.ReasonDowngraded, model.ReasonUpgraded, model.ReasonCorrelated:
				decision = maxDecision(decision, model.DecisionWarn)
			}
		}
		return decision
	}
	switch finding.Severity {
	case model.SeverityCritical, model.SeverityHigh:
		if finding.Confidence == model.ConfidenceHigh {
			return model.DecisionBlock
		}
		return model.DecisionWarn
	case model.SeverityMedium:
		return model.DecisionWarn
	default:
		return model.DecisionAllow
	}
}

func maxSeverity(left model.Severity, right model.Severity) model.Severity {
	if severityRank(right) > severityRank(left) {
		return right
	}
	return left
}

func maxConfidence(left model.Confidence, right model.Confidence) model.Confidence {
	if confidenceRank(right) > confidenceRank(left) {
		return right
	}
	return left
}

func maxDecision(left model.Decision, right model.Decision) model.Decision {
	if decisionRank(right) > decisionRank(left) {
		return right
	}
	return left
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidenceRank(confidence model.Confidence) int {
	switch confidence {
	case model.ConfidenceHigh:
		return 4
	case model.ConfidenceMedium:
		return 3
	case model.ConfidenceLow:
		return 2
	case model.ConfidenceUnknown:
		return 1
	default:
		return 0
	}
}

func decisionRank(decision model.Decision) int {
	switch decision {
	case model.DecisionError:
		return 4
	case model.DecisionBlock:
		return 3
	case model.DecisionWarn:
		return 2
	case model.DecisionAllow:
		return 1
	default:
		return 0
	}
}

func compareInt(left int, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
