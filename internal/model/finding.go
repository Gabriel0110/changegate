package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity describes risk impact.
type Severity string

const (
	// SeverityCritical is material risk likely to expose sensitive assets or enable privilege escalation.
	SeverityCritical Severity = "critical"
	// SeverityHigh is material risk requiring security review or default CI block in production.
	SeverityHigh Severity = "high"
	// SeverityMedium is meaningful risk, but context-dependent.
	SeverityMedium Severity = "medium"
	// SeverityLow is a hygiene issue or defense-in-depth gap.
	SeverityLow Severity = "low"
	// SeverityInfo is useful metadata, not a risk by itself.
	SeverityInfo Severity = "info"
)

// Confidence describes evidence quality.
type Confidence string

const (
	// ConfidenceHigh means strong evidence from plan graph and/or cloud context.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium means likely risk but missing some contextual proof.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow means heuristic signal only.
	ConfidenceLow Confidence = "low"
	// ConfidenceUnknown means ChangeGate cannot establish enough context.
	ConfidenceUnknown Confidence = "unknown"
)

// Decision describes the final deployment outcome.
type Decision string

const (
	// DecisionAllow means no blocking risk was found.
	DecisionAllow Decision = "allow"
	// DecisionWarn means risk exists but policy does not block.
	DecisionWarn Decision = "warn"
	// DecisionBlock means risk violates the policy gate.
	DecisionBlock Decision = "block"
	// DecisionError means the scan could not complete reliably.
	DecisionError Decision = "error"
)

// RiskCategory groups findings by risk family.
type RiskCategory string

const (
	// RiskCategoryPublicExposure covers internet exposure and ingress risks.
	RiskCategoryPublicExposure RiskCategory = "public_exposure"
	// RiskCategoryPrivilegeEscalation covers IAM and authorization escalation paths.
	RiskCategoryPrivilegeEscalation RiskCategory = "privilege_escalation"
	// RiskCategorySensitiveData covers secrets, unencrypted storage, and data exposure.
	RiskCategorySensitiveData RiskCategory = "sensitive_data"
	// RiskCategoryNetworkBlastRadius covers network reachability expansion.
	RiskCategoryNetworkBlastRadius RiskCategory = "network_blast_radius"
	// RiskCategoryAvailability covers replacement, deletion, and downtime risks.
	RiskCategoryAvailability RiskCategory = "availability"
	// RiskCategoryCompliance covers policy and governance evidence.
	RiskCategoryCompliance RiskCategory = "compliance"
	// RiskCategoryUnknown is used when a rule cannot classify risk more specifically.
	RiskCategoryUnknown RiskCategory = "unknown"
)

// DecisionReasonCode explains why a finding or outcome did or did not block.
type DecisionReasonCode string

const (
	// ReasonNoFindings means no findings were produced.
	ReasonNoFindings DecisionReasonCode = "NO_FINDINGS"
	// ReasonBelowBlockThreshold means findings exist but do not meet block thresholds.
	ReasonBelowBlockThreshold DecisionReasonCode = "BELOW_BLOCK_THRESHOLD"
	// ReasonMeetsBlockThreshold means at least one finding meets block thresholds.
	ReasonMeetsBlockThreshold DecisionReasonCode = "MEETS_BLOCK_THRESHOLD"
	// ReasonAuditMode means enforcement is disabled for audit mode.
	ReasonAuditMode DecisionReasonCode = "AUDIT_MODE"
	// ReasonWarnMode means blockable findings are reported as warnings.
	ReasonWarnMode DecisionReasonCode = "WARN_MODE"
	// ReasonSuppressed means a finding is suppressed by policy, waiver, or baseline.
	ReasonSuppressed DecisionReasonCode = "SUPPRESSED"
	// ReasonDowngraded means context reduced severity or confidence.
	ReasonDowngraded DecisionReasonCode = "DOWNGRADED"
	// ReasonUpgraded means context increased severity or confidence.
	ReasonUpgraded DecisionReasonCode = "UPGRADED"
	// ReasonChangedResourceOnly means unchanged resources were suppressed by policy.
	ReasonChangedResourceOnly DecisionReasonCode = "CHANGED_RESOURCE_ONLY"
	// ReasonExistingRisk means a finding was suppressed because only new risks are enforced.
	ReasonExistingRisk DecisionReasonCode = "EXISTING_RISK"
	// ReasonCorrelated means related findings were correlated into the decision context.
	ReasonCorrelated DecisionReasonCode = "CORRELATED"
)

// Evidence supports a finding with resource-specific facts.
type Evidence struct {
	Type      string `json:"type"`
	Resource  string `json:"resource,omitempty"`
	Path      string `json:"path,omitempty"`
	Value     any    `json:"value,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
	Message   string `json:"message"`
}

// Remediation describes how a user can address a finding.
type Remediation struct {
	Summary          string            `json:"summary"`
	Steps            []string          `json:"steps,omitempty"`
	References       []string          `json:"references,omitempty"`
	WhyThisWorks     string            `json:"why_this_works,omitempty"`
	FixConfidence    Confidence        `json:"fix_confidence,omitempty"`
	Effort           string            `json:"effort,omitempty"`
	DowntimeRisk     string            `json:"downtime_risk,omitempty"`
	Destructive      bool              `json:"destructive,omitempty"`
	AutoFixAvailable bool              `json:"auto_fix_available,omitempty"`
	FixOptions       []FixOption       `json:"fix_options,omitempty"`
	TerraformHints   []TerraformHint   `json:"terraform_hints,omitempty"`
	Patches          []PatchSuggestion `json:"patches,omitempty"`
	OwnerHints       []string          `json:"owner_hints,omitempty"`
	NextSteps        []string          `json:"next_steps,omitempty"`
	Docs             []string          `json:"docs,omitempty"`
}

// FixOption describes one remediation route with operational tradeoffs.
type FixOption struct {
	Title        string `json:"title"`
	Description  string `json:"description"`
	Effort       string `json:"effort,omitempty"`
	DowntimeRisk string `json:"downtime_risk,omitempty"`
	Preferred    bool   `json:"preferred,omitempty"`
}

// TerraformHint identifies a likely Terraform/OpenTofu attribute or resource to inspect.
type TerraformHint struct {
	ResourceType string `json:"resource_type,omitempty"`
	Attribute    string `json:"attribute,omitempty"`
	Preferred    string `json:"preferred,omitempty"`
	Notes        string `json:"notes,omitempty"`
}

// PatchSuggestion describes an advisory patch without applying it automatically.
type PatchSuggestion struct {
	Title        string   `json:"title"`
	Format       string   `json:"format"`
	Language     string   `json:"language,omitempty"`
	Snippet      string   `json:"snippet"`
	AppliesTo    []string `json:"applies_to,omitempty"`
	SafeToApply  bool     `json:"safe_to_apply"`
	Rationale    string   `json:"rationale"`
	ReviewNeeded bool     `json:"review_needed"`
}

// Suppression records why a finding is visible but not enforcing.
type Suppression struct {
	Kind      string     `json:"kind"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Active    bool       `json:"active"`
}

// DecisionReason explains a finding's contribution to the final policy outcome.
type DecisionReason struct {
	FindingID string             `json:"finding_id,omitempty"`
	Resource  string             `json:"resource,omitempty"`
	Policy    string             `json:"policy,omitempty"`
	Code      DecisionReasonCode `json:"code"`
	Reason    string             `json:"reason"`
}

// Finding is the normalized risk object emitted by rules and consumed by policy/output layers.
type Finding struct {
	ID                   string               `json:"id"`
	RuleID               string               `json:"rule_id"`
	RuleName             string               `json:"rule_name,omitempty"`
	PolicyPack           string               `json:"policy_pack,omitempty"`
	PolicyPackVersion    string               `json:"policy_pack_version,omitempty"`
	Title                string               `json:"title"`
	Description          string               `json:"description,omitempty"`
	ResourceAddress      string               `json:"resource_address"`
	Provider             string               `json:"provider,omitempty"`
	Environment          string               `json:"environment,omitempty"`
	Category             RiskCategory         `json:"category"`
	Severity             Severity             `json:"severity"`
	Confidence           Confidence           `json:"confidence"`
	Evidence             []Evidence           `json:"evidence"`
	Remediation          Remediation          `json:"remediation"`
	Fingerprint          string               `json:"fingerprint"`
	DeduplicationKey     string               `json:"deduplication_key"`
	Suppressions         []Suppression        `json:"suppressions,omitempty"`
	DecisionReasonCodes  []DecisionReasonCode `json:"decision_reason_codes,omitempty"`
	DecisionReasons      []DecisionReason     `json:"decision_reasons,omitempty"`
	CorrelatedFindingIDs []string             `json:"correlated_finding_ids,omitempty"`
}

// Override describes severity and confidence overrides applied after rule evaluation.
type Override struct {
	Severity   *Severity   `json:"severity,omitempty"`
	Confidence *Confidence `json:"confidence,omitempty"`
	Reason     string      `json:"reason"`
}

// Threshold describes the minimum severity and confidence for a policy action.
type Threshold struct {
	MinSeverity   Severity   `json:"min_severity"`
	MinConfidence Confidence `json:"min_confidence"`
}

// PolicyMode controls enforcement behavior.
type PolicyMode string

const (
	// PolicyModeBlock enforces block decisions.
	PolicyModeBlock PolicyMode = "block"
	// PolicyModeWarn reports blockable findings without non-zero policy enforcement.
	PolicyModeWarn PolicyMode = "warn"
	// PolicyModeAudit reports findings without enforcement.
	PolicyModeAudit PolicyMode = "audit"
)

// PolicyConfig is the decision model input.
type PolicyConfig struct {
	Mode                  PolicyMode             `json:"mode"`
	BlockOn               Threshold              `json:"block_on"`
	WarnOn                Threshold              `json:"warn_on"`
	AttackPaths           AttackPathPolicy       `json:"attack_paths,omitempty"`
	Overrides             map[string]Override    `json:"overrides,omitempty"`
	EnvironmentThresholds map[string]Thresholds  `json:"environment_thresholds,omitempty"`
	BranchThresholds      map[string]Thresholds  `json:"branch_thresholds,omitempty"`
	Branch                string                 `json:"branch,omitempty"`
	ChangedResourcesOnly  bool                   `json:"changed_resources_only,omitempty"`
	ChangedResources      map[string]bool        `json:"changed_resources,omitempty"`
	NewRiskOnly           bool                   `json:"new_risk_only,omitempty"`
	ExistingFingerprints  map[string]bool        `json:"existing_fingerprints,omitempty"`
	ExistingRisks         map[string]RiskContext `json:"existing_risks,omitempty"`
	BaselineWarnings      []string               `json:"baseline_warnings,omitempty"`
	WaiverFile            string                 `json:"waiver_file,omitempty"`
	FailExpiredWaivers    bool                   `json:"fail_expired_waivers,omitempty"`
	DocumentationLinks    map[string]string      `json:"documentation_links,omitempty"`
}

// AttackPathPolicy controls which attack path types can become findings.
type AttackPathPolicy struct {
	Enabled bool                  `json:"enabled"`
	Block   []AttackPathThreshold `json:"block,omitempty"`
	Warn    []AttackPathThreshold `json:"warn,omitempty"`
}

// AttackPathThreshold configures a decision threshold for one attack path type.
type AttackPathThreshold struct {
	Type          string     `json:"type"`
	MinConfidence Confidence `json:"min_confidence"`
}

// RiskContext captures non-secret movement signals for a finding.
type RiskContext struct {
	Severity             Severity   `json:"severity,omitempty"`
	Confidence           Confidence `json:"confidence,omitempty"`
	Decision             Decision   `json:"decision,omitempty"`
	GraphSensitiveData   bool       `json:"graph_sensitive_data,omitempty"`
	CloudContextEvidence bool       `json:"cloud_context_evidence,omitempty"`
	ActiveWaiver         bool       `json:"active_waiver,omitempty"`
	AnyActiveSuppression bool       `json:"any_active_suppression,omitempty"`
}

// Thresholds contains block and warn thresholds for a contextual scope.
type Thresholds struct {
	BlockOn Threshold `json:"block_on"`
	WarnOn  Threshold `json:"warn_on"`
}

// PolicyOutcome is the normalized deploy decision with ordered findings.
type PolicyOutcome struct {
	Decision    Decision             `json:"decision"`
	ReasonCodes []DecisionReasonCode `json:"reason_codes"`
	Reasons     []DecisionReason     `json:"reasons"`
	Summary     RiskSummary          `json:"summary"`
	Findings    []Finding            `json:"findings"`
}

// RiskSummary summarizes findings by enforcement-relevant dimensions.
type RiskSummary struct {
	Total              int                  `json:"total"`
	Blocking           int                  `json:"blocking"`
	Warnings           int                  `json:"warnings"`
	Informational      int                  `json:"informational"`
	Suppressed         int                  `json:"suppressed"`
	Downgraded         int                  `json:"downgraded"`
	Upgraded           int                  `json:"upgraded"`
	BySeverity         map[Severity]int     `json:"by_severity,omitempty"`
	ByCategory         map[RiskCategory]int `json:"by_category,omitempty"`
	SuppressedByReason map[string]int       `json:"suppressed_by_reason,omitempty"`
}

// DefaultPolicyConfig returns ChangeGate's default high-confidence blocking policy.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		Mode: PolicyModeBlock,
		BlockOn: Threshold{
			MinSeverity:   SeverityHigh,
			MinConfidence: ConfidenceHigh,
		},
		WarnOn: Threshold{
			MinSeverity:   SeverityMedium,
			MinConfidence: ConfidenceMedium,
		},
		AttackPaths: DefaultAttackPathPolicy(),
	}
}

// DefaultAttackPathPolicy returns conservative default attack path enforcement thresholds.
func DefaultAttackPathPolicy() AttackPathPolicy {
	return AttackPathPolicy{
		Enabled: true,
		Block: []AttackPathThreshold{
			{Type: "public_to_sensitive_data", MinConfidence: ConfidenceHigh},
			{Type: "iam_privilege_escalation", MinConfidence: ConfidenceHigh},
		},
		Warn: []AttackPathThreshold{
			{Type: "public_to_sensitive_data", MinConfidence: ConfidenceMedium},
			{Type: "iam_privilege_escalation", MinConfidence: ConfidenceMedium},
		},
	}
}

// NormalizeFinding applies redaction, stable fingerprinting, ID generation, and dedup key generation.
func NormalizeFinding(f Finding) Finding {
	f.Evidence = RedactEvidence(f.Evidence)
	f.Fingerprint = FindingFingerprint(f)
	f.ID = StableFindingID(f.Fingerprint)
	f.DeduplicationKey = DeduplicationKey(f)
	return f
}

// FindingFingerprint returns a deterministic SHA-256 fingerprint for a finding.
func FindingFingerprint(f Finding) string {
	input := fingerprintInput{
		RuleID:            f.RuleID,
		ResourceAddress:   f.ResourceAddress,
		Provider:          f.Provider,
		Category:          f.Category,
		EvidenceTypes:     evidenceTypes(f.Evidence),
		ConfigPaths:       evidencePaths(f.Evidence),
		Environment:       f.Environment,
		PolicyPackVersion: f.PolicyPackVersion,
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// StableFindingID returns a short stable finding identifier derived from a fingerprint.
func StableFindingID(fingerprint string) string {
	if len(fingerprint) < 16 {
		return "CHG-" + strings.ToUpper(fingerprint)
	}
	return "CHG-" + strings.ToUpper(fingerprint[:16])
}

// DeduplicationKey returns the deterministic deduplication key for a finding.
func DeduplicationKey(f Finding) string {
	parts := []string{
		f.RuleID,
		f.ResourceAddress,
		f.Provider,
		string(f.Category),
		f.Environment,
	}
	return strings.Join(parts, "|")
}

// RedactEvidence returns evidence with sensitive values replaced by a marker.
func RedactEvidence(evidence []Evidence) []Evidence {
	out := make([]Evidence, len(evidence))
	for index, item := range evidence {
		out[index] = item
		if item.Sensitive {
			out[index].Value = "(sensitive)"
		} else {
			out[index].Value = redactArbitrary(item.Value)
		}
	}
	return out
}

// RenderEvidence returns deterministic human-readable evidence lines.
func RenderEvidence(evidence []Evidence) []string {
	redacted := RedactEvidence(evidence)
	lines := make([]string, 0, len(redacted))
	for _, item := range redacted {
		line := item.Message
		if item.Resource != "" {
			line = item.Resource + ": " + line
		}
		if item.Path != "" {
			line += " (" + item.Path + ")"
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

// ApplyOverride applies a severity/confidence override.
func ApplyOverride(f Finding, override Override) Finding {
	if override.Severity != nil {
		f.Severity = *override.Severity
	}
	if override.Confidence != nil {
		f.Confidence = *override.Confidence
	}
	return NormalizeFinding(f)
}

// EvaluatePolicy normalizes findings, applies overrides, sorts/deduplicates, and returns the deploy outcome.
func EvaluatePolicy(findings []Finding, config PolicyConfig) PolicyOutcome {
	config = normalizePolicyConfig(config)

	normalized := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		current := NormalizeFinding(finding)
		if override, ok := config.Overrides[current.Fingerprint]; ok {
			current = ApplyOverride(current, override)
			current.DecisionReasonCodes = appendUniqueReason(current.DecisionReasonCodes, ReasonDowngraded)
			current.DecisionReasons = append(current.DecisionReasons, DecisionReason{
				FindingID: current.ID,
				Resource:  current.ResourceAddress,
				Code:      ReasonDowngraded,
				Reason:    override.Reason,
			})
		}
		current = applyContext(current, config)
		normalized = append(normalized, current)
	}

	normalized = DeduplicateFindings(normalized)
	SortFindings(normalized)
	correlateFindings(normalized)

	summary := BuildRiskSummary(normalized, config)
	outcome := PolicyOutcome{
		Decision:    DecisionAllow,
		ReasonCodes: []DecisionReasonCode{ReasonNoFindings},
		Reasons:     []DecisionReason{{Code: ReasonNoFindings, Reason: "no findings met warn or block thresholds"}},
		Summary:     summary,
		Findings:    normalized,
	}

	if len(normalized) > 0 {
		outcome.ReasonCodes = []DecisionReasonCode{ReasonBelowBlockThreshold}
		outcome.Reasons = buildOutcomeReasons(normalized, ReasonBelowBlockThreshold, "findings did not meet block threshold")
		if summary.Warnings > 0 {
			outcome.Decision = DecisionWarn
		}
	}
	if summary.Blocking > 0 {
		switch config.Mode {
		case PolicyModeAudit:
			outcome.Decision = DecisionWarn
			outcome.ReasonCodes = []DecisionReasonCode{ReasonAuditMode}
			outcome.Reasons = buildOutcomeReasons(normalized, ReasonAuditMode, "audit mode reports blockable findings without blocking")
		case PolicyModeWarn:
			outcome.Decision = DecisionWarn
			outcome.ReasonCodes = []DecisionReasonCode{ReasonWarnMode}
			outcome.Reasons = buildOutcomeReasons(normalized, ReasonWarnMode, "warn mode reports blockable findings without blocking")
		default:
			outcome.Decision = DecisionBlock
			outcome.ReasonCodes = []DecisionReasonCode{ReasonMeetsBlockThreshold}
			outcome.Reasons = buildOutcomeReasons(normalized, ReasonMeetsBlockThreshold, "finding meets block threshold")
		}
	}

	return outcome
}

func normalizePolicyConfig(config PolicyConfig) PolicyConfig {
	defaults := DefaultPolicyConfig()
	if config.Mode == "" {
		config.Mode = defaults.Mode
	}
	if config.BlockOn.MinSeverity == "" {
		config.BlockOn.MinSeverity = defaults.BlockOn.MinSeverity
	}
	if config.BlockOn.MinConfidence == "" {
		config.BlockOn.MinConfidence = defaults.BlockOn.MinConfidence
	}
	if config.WarnOn.MinSeverity == "" {
		config.WarnOn.MinSeverity = defaults.WarnOn.MinSeverity
	}
	if config.WarnOn.MinConfidence == "" {
		config.WarnOn.MinConfidence = defaults.WarnOn.MinConfidence
	}
	if scoped, ok := config.EnvironmentThresholds["*"]; ok {
		mergeThreshold(&config.BlockOn, scoped.BlockOn)
		mergeThreshold(&config.WarnOn, scoped.WarnOn)
	}
	if config.Branch != "" {
		if scoped, ok := config.BranchThresholds[config.Branch]; ok {
			mergeThreshold(&config.BlockOn, scoped.BlockOn)
			mergeThreshold(&config.WarnOn, scoped.WarnOn)
		}
	}
	return config
}

// SortFindings sorts findings deterministically by severity, confidence, category, resource, rule, and fingerprint.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i int, j int) bool {
		left := findings[i]
		right := findings[j]
		for _, cmp := range []int{
			compareInt(severityRank(right.Severity), severityRank(left.Severity)),
			compareInt(confidenceRank(right.Confidence), confidenceRank(left.Confidence)),
			strings.Compare(string(left.Category), string(right.Category)),
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

// DeduplicateFindings removes duplicate findings using DeduplicationKey while retaining the strongest finding.
func DeduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}
	SortFindings(findings)
	seen := make(map[string]Finding, len(findings))
	for _, finding := range findings {
		key := finding.DeduplicationKey
		if key == "" {
			key = DeduplicationKey(finding)
		}
		if _, ok := seen[key]; !ok {
			seen[key] = finding
		}
	}

	out := make([]Finding, 0, len(seen))
	for _, finding := range seen {
		out = append(out, finding)
	}
	SortFindings(out)
	return out
}

// BuildRiskSummary summarizes normalized findings for policy decisions and output.
func BuildRiskSummary(findings []Finding, config PolicyConfig) RiskSummary {
	summary := RiskSummary{
		Total:              len(findings),
		BySeverity:         make(map[Severity]int),
		ByCategory:         make(map[RiskCategory]int),
		SuppressedByReason: make(map[string]int),
	}
	for index := range findings {
		finding := &findings[index]
		summary.BySeverity[finding.Severity]++
		summary.ByCategory[finding.Category]++
		if hasReason(*finding, ReasonDowngraded) {
			summary.Downgraded++
		}
		if hasReason(*finding, ReasonUpgraded) {
			summary.Upgraded++
		}
		if activeSuppression(finding.Suppressions) {
			summary.Suppressed++
			finding.DecisionReasonCodes = appendUniqueReason(finding.DecisionReasonCodes, ReasonSuppressed)
			for _, suppression := range finding.Suppressions {
				if suppression.Active {
					summary.SuppressedByReason[suppression.Kind]++
				}
			}
			continue
		}
		if meetsThreshold(finding.Severity, finding.Confidence, config.BlockOn) {
			summary.Blocking++
			finding.DecisionReasonCodes = appendUniqueReason(finding.DecisionReasonCodes, ReasonMeetsBlockThreshold)
			continue
		}
		if meetsThreshold(finding.Severity, finding.Confidence, config.WarnOn) {
			summary.Warnings++
			finding.DecisionReasonCodes = appendUniqueReason(finding.DecisionReasonCodes, ReasonBelowBlockThreshold)
			continue
		}
		summary.Informational++
	}
	return summary
}

type fingerprintInput struct {
	RuleID            string       `json:"rule_id"`
	ResourceAddress   string       `json:"resource_address"`
	Provider          string       `json:"provider,omitempty"`
	Category          RiskCategory `json:"category"`
	EvidenceTypes     []string     `json:"evidence_types,omitempty"`
	ConfigPaths       []string     `json:"config_paths,omitempty"`
	Environment       string       `json:"environment,omitempty"`
	PolicyPackVersion string       `json:"policy_pack_version,omitempty"`
}

func evidenceTypes(evidence []Evidence) []string {
	types := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if item.Type != "" {
			types = append(types, item.Type)
		}
	}
	sort.Strings(types)
	return dedupeStrings(types)
}

func evidencePaths(evidence []Evidence) []string {
	paths := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if item.Path != "" {
			paths = append(paths, item.Path)
		}
	}
	sort.Strings(paths)
	return dedupeStrings(paths)
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := []string{values[0]}
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func redactArbitrary(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			if looksSensitive(key) {
				out[key] = "(sensitive)"
				continue
			}
			out[key] = redactArbitrary(value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, value := range typed {
			out[index] = redactArbitrary(value)
		}
		return out
	case string:
		return redactString(typed)
	default:
		return typed
	}
}

func looksSensitive(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "private_key")
}

func redactString(value string) string {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") {
		return "(sensitive)"
	}
	return value
}

func meetsThreshold(severity Severity, confidence Confidence, threshold Threshold) bool {
	return severityRank(severity) >= severityRank(threshold.MinSeverity) &&
		confidenceRank(confidence) >= confidenceRank(threshold.MinConfidence)
}

func decisionImpact(f Finding) Decision {
	if hasReason(f, ReasonMeetsBlockThreshold) {
		return DecisionBlock
	}
	if hasReason(f, ReasonBelowBlockThreshold) {
		return DecisionWarn
	}
	return DecisionAllow
}

func decisionRank(decision Decision) int {
	switch decision {
	case DecisionError:
		return 4
	case DecisionBlock:
		return 3
	case DecisionWarn:
		return 2
	case DecisionAllow:
		return 1
	default:
		return 0
	}
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidenceRank(confidence Confidence) int {
	switch confidence {
	case ConfidenceHigh:
		return 4
	case ConfidenceMedium:
		return 3
	case ConfidenceLow:
		return 2
	case ConfidenceUnknown:
		return 1
	default:
		return 0
	}
}

func compareInt(left int, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func mergeThreshold(target *Threshold, source Threshold) {
	if source.MinSeverity != "" {
		target.MinSeverity = source.MinSeverity
	}
	if source.MinConfidence != "" {
		target.MinConfidence = source.MinConfidence
	}
}

func findingGraphReachesSensitiveData(f Finding) bool {
	for _, evidence := range f.Evidence {
		lower := strings.ToLower(evidence.Type + " " + evidence.Path + " " + evidence.Message + " " + fmt.Sprint(evidence.Value))
		if strings.Contains(lower, "graph") && containsSensitiveAsset(lower) {
			return true
		}
	}
	return false
}

func findingHasCloudContext(f Finding) bool {
	for _, evidence := range f.Evidence {
		if strings.Contains(strings.ToLower(evidence.Type+" "+evidence.Path), "cloud_context") {
			return true
		}
	}
	return false
}

func containsSensitiveAsset(value string) bool {
	for _, token := range []string{
		"aws_db_instance",
		"aws_rds_cluster",
		"aws_secretsmanager_secret",
		"secretsmanager",
		"secret",
		"rds",
		"dynamodb",
		"opensearch",
		"elasticache",
		"s3_bucket",
	} {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func applyContext(f Finding, config PolicyConfig) Finding {
	if config.ChangedResourcesOnly && !config.ChangedResources[f.ResourceAddress] {
		f.Suppressions = append(f.Suppressions, Suppression{
			Kind:   "changed_resource_only",
			Reason: "finding is outside the changed resource set",
			Active: true,
		})
		f.DecisionReasonCodes = appendUniqueReason(f.DecisionReasonCodes, ReasonChangedResourceOnly)
		f.DecisionReasons = append(f.DecisionReasons, DecisionReason{FindingID: f.ID, Resource: f.ResourceAddress, Code: ReasonChangedResourceOnly, Reason: "suppressed because changed-resource-only mode is enabled"})
	}
	if config.NewRiskOnly && config.ExistingFingerprints[f.Fingerprint] {
		if existing, ok := config.ExistingRisks[f.Fingerprint]; ok && RiskContextWorsened(RiskContextFromFinding(f), existing) {
			f.DecisionReasonCodes = appendUniqueReason(f.DecisionReasonCodes, ReasonUpgraded)
			f.DecisionReasons = append(f.DecisionReasons, DecisionReason{FindingID: f.ID, Resource: f.ResourceAddress, Code: ReasonUpgraded, Reason: "existing baseline risk worsened; new-risk-only does not suppress it"})
			return NormalizeFinding(f)
		}
		f.Suppressions = append(f.Suppressions, Suppression{
			Kind:   "existing_risk",
			Reason: "finding fingerprint exists in baseline",
			Active: true,
		})
		f.DecisionReasonCodes = appendUniqueReason(f.DecisionReasonCodes, ReasonExistingRisk)
		f.DecisionReasons = append(f.DecisionReasons, DecisionReason{FindingID: f.ID, Resource: f.ResourceAddress, Code: ReasonExistingRisk, Reason: "suppressed because new-risk-only mode is enabled"})
	}
	if scoped, ok := config.EnvironmentThresholds[f.Environment]; ok {
		beforeSeverity := f.Severity
		beforeConfidence := f.Confidence
		if scoped.BlockOn.MinSeverity != "" && severityRank(f.Severity) < severityRank(scoped.BlockOn.MinSeverity) {
			f.Severity = scoped.BlockOn.MinSeverity
		}
		if scoped.BlockOn.MinConfidence != "" && confidenceRank(f.Confidence) < confidenceRank(scoped.BlockOn.MinConfidence) {
			f.Confidence = scoped.BlockOn.MinConfidence
		}
		if severityRank(f.Severity) > severityRank(beforeSeverity) || confidenceRank(f.Confidence) > confidenceRank(beforeConfidence) {
			f.DecisionReasonCodes = appendUniqueReason(f.DecisionReasonCodes, ReasonUpgraded)
			f.DecisionReasons = append(f.DecisionReasons, DecisionReason{FindingID: f.ID, Resource: f.ResourceAddress, Code: ReasonUpgraded, Reason: "environment-specific threshold upgraded risk context"})
		}
	}
	return NormalizeFinding(f)
}

// RiskContextFromFinding extracts non-secret movement signals from a finding.
func RiskContextFromFinding(f Finding) RiskContext {
	return RiskContext{
		Severity:             f.Severity,
		Confidence:           f.Confidence,
		Decision:             decisionImpact(f),
		GraphSensitiveData:   findingGraphReachesSensitiveData(f),
		CloudContextEvidence: findingHasCloudContext(f),
		ActiveWaiver:         activeSuppressionKind(f.Suppressions, "waiver"),
		AnyActiveSuppression: activeSuppression(f.Suppressions),
	}
}

// RiskContextWorsened reports whether current context is materially worse than baseline context.
func RiskContextWorsened(current RiskContext, baseline RiskContext) bool {
	if severityRank(current.Severity) > severityRank(baseline.Severity) {
		return true
	}
	if current.Confidence == ConfidenceHigh && baseline.Confidence != ConfidenceHigh {
		return true
	}
	if baseline.Decision != "" && decisionRank(current.Decision) > decisionRank(baseline.Decision) {
		return true
	}
	if current.GraphSensitiveData && !baseline.GraphSensitiveData {
		return true
	}
	if current.CloudContextEvidence && !baseline.CloudContextEvidence {
		return true
	}
	if baseline.ActiveWaiver && !current.ActiveWaiver {
		return true
	}
	if baseline.AnyActiveSuppression && !current.AnyActiveSuppression && decisionRank(current.Decision) > decisionRank(DecisionAllow) {
		return true
	}
	return false
}

// RiskContextImproved reports whether current context is materially better than baseline context.
func RiskContextImproved(current RiskContext, baseline RiskContext) bool {
	if RiskContextWorsened(current, baseline) {
		return false
	}
	return severityRank(current.Severity) < severityRank(baseline.Severity) ||
		confidenceRank(current.Confidence) < confidenceRank(baseline.Confidence) ||
		(baseline.Decision != "" && decisionRank(current.Decision) < decisionRank(baseline.Decision)) ||
		(!current.GraphSensitiveData && baseline.GraphSensitiveData) ||
		(!current.CloudContextEvidence && baseline.CloudContextEvidence) ||
		(!baseline.ActiveWaiver && current.ActiveWaiver)
}

func correlateFindings(findings []Finding) {
	byResource := make(map[string][]int)
	for index, finding := range findings {
		byResource[finding.ResourceAddress] = append(byResource[finding.ResourceAddress], index)
	}
	for _, indexes := range byResource {
		if len(indexes) < 2 {
			continue
		}
		ids := make([]string, 0, len(indexes))
		for _, index := range indexes {
			ids = append(ids, findings[index].ID)
		}
		sort.Strings(ids)
		for _, index := range indexes {
			findings[index].CorrelatedFindingIDs = withoutString(ids, findings[index].ID)
			findings[index].DecisionReasonCodes = appendUniqueReason(findings[index].DecisionReasonCodes, ReasonCorrelated)
		}
	}
}

func withoutString(values []string, drop string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != drop {
			out = append(out, value)
		}
	}
	return out
}

func buildOutcomeReasons(findings []Finding, code DecisionReasonCode, fallback string) []DecisionReason {
	reasons := make([]DecisionReason, 0)
	for _, finding := range findings {
		if code == ReasonMeetsBlockThreshold && !hasReason(finding, ReasonMeetsBlockThreshold) {
			continue
		}
		if code == ReasonBelowBlockThreshold && activeSuppression(finding.Suppressions) {
			continue
		}
		reason := fallback
		if len(finding.DecisionReasons) > 0 {
			reason = finding.DecisionReasons[0].Reason
		}
		reasons = append(reasons, DecisionReason{
			FindingID: finding.ID,
			Resource:  finding.ResourceAddress,
			Policy:    finding.PolicyPack,
			Code:      code,
			Reason:    reason,
		})
	}
	if len(reasons) == 0 {
		return []DecisionReason{{Code: code, Reason: fallback}}
	}
	return reasons
}

func hasReason(f Finding, reason DecisionReasonCode) bool {
	for _, existing := range f.DecisionReasonCodes {
		if existing == reason {
			return true
		}
	}
	return false
}

func activeSuppression(suppressions []Suppression) bool {
	now := time.Now().UTC()
	for _, suppression := range suppressions {
		if !suppression.Active {
			continue
		}
		if suppression.ExpiresAt != nil && suppression.ExpiresAt.Before(now) {
			continue
		}
		return true
	}
	return false
}

func activeSuppressionKind(suppressions []Suppression, kind string) bool {
	now := time.Now().UTC()
	for _, suppression := range suppressions {
		if suppression.Kind != kind || !suppression.Active {
			continue
		}
		if suppression.ExpiresAt != nil && suppression.ExpiresAt.Before(now) {
			continue
		}
		return true
	}
	return false
}

func appendUniqueReason(reasons []DecisionReasonCode, reason DecisionReasonCode) []DecisionReasonCode {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

// ValidateOutcome checks invariants required by output and CI enforcement layers.
func ValidateOutcome(outcome PolicyOutcome) error {
	for _, finding := range outcome.Findings {
		if finding.Fingerprint == "" {
			return fmt.Errorf("finding %s has empty fingerprint", finding.RuleID)
		}
		if finding.ID == "" {
			return fmt.Errorf("finding %s has empty stable ID", finding.RuleID)
		}
		if meetsThreshold(finding.Severity, finding.Confidence, DefaultPolicyConfig().BlockOn) && len(finding.Evidence) == 0 {
			return fmt.Errorf("blockable finding %s has no evidence", finding.ID)
		}
	}
	return nil
}
