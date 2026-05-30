// Package policy loads and validates ChangeGate policy configuration.
package policy

import (
	"fmt"
	"io"
	"os"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
	"gopkg.in/yaml.v3"
)

// Config is the user-facing policy configuration loaded from .changegate.yaml.
type Config struct {
	Version            int                          `json:"version" yaml:"version"`
	Mode               model.PolicyMode             `json:"mode" yaml:"mode"`
	Decision           DecisionConfig               `json:"decision" yaml:"decision"`
	PolicyPacks        []string                     `json:"policy_packs" yaml:"policy_packs"`
	PolicyPackVersions map[string]string            `json:"policy_pack_versions" yaml:"policy_pack_versions"`
	PolicyPackSigning  PolicyPackSigningConfig      `json:"policy_pack_signing" yaml:"policy_pack_signing"`
	Rules              RulesConfig                  `json:"rules" yaml:"rules"`
	Overrides          map[string]OverrideConfig    `json:"overrides" yaml:"overrides"`
	Environments       map[string]EnvironmentConfig `json:"environments" yaml:"environments"`
	Branches           map[string]EnvironmentConfig `json:"branches" yaml:"branches"`
	Scope              ScopeConfig                  `json:"scope" yaml:"scope"`
	Baseline           BaselineConfig               `json:"baseline" yaml:"baseline"`
	Waivers            WaiverConfig                 `json:"waivers" yaml:"waivers"`
	CustomRules        CustomRulesConfig            `json:"custom_rules" yaml:"custom_rules"`
	Rego               RegoConfig                   `json:"rego" yaml:"rego"`
	Docs               DocsConfig                   `json:"docs" yaml:"docs"`
	Review             ReviewConfig                 `json:"review" yaml:"review"`
	Impact             ImpactConfig                 `json:"impact" yaml:"impact"`
	AttackPaths        AttackPathsConfig            `json:"attack_paths" yaml:"attack_paths"`
}

// DecisionConfig contains global policy thresholds.
type DecisionConfig struct {
	BlockOn ThresholdConfig `json:"block_on" yaml:"block_on"`
	WarnOn  ThresholdConfig `json:"warn_on" yaml:"warn_on"`
}

// ThresholdConfig maps YAML threshold names to model thresholds.
type ThresholdConfig struct {
	MinSeverity   model.Severity   `json:"min_severity" yaml:"min_severity"`
	Severity      model.Severity   `json:"severity" yaml:"severity"`
	MinConfidence model.Confidence `json:"min_confidence" yaml:"min_confidence"`
	Confidence    model.Confidence `json:"confidence" yaml:"confidence"`
}

// RulesConfig controls individual rules.
type RulesConfig struct {
	Enabled  []string `json:"enabled" yaml:"enabled"`
	Disabled []string `json:"disabled" yaml:"disabled"`
}

// PolicyPackSigningConfig reserves explicit signing controls for future remote packs.
type PolicyPackSigningConfig struct {
	RequireSigned bool     `json:"require_signed" yaml:"require_signed"`
	TrustedKeys   []string `json:"trusted_keys" yaml:"trusted_keys"`
}

// OverrideConfig changes rule severity/confidence.
type OverrideConfig struct {
	Severity   model.Severity   `json:"severity" yaml:"severity"`
	Confidence model.Confidence `json:"confidence" yaml:"confidence"`
	Reason     string           `json:"reason" yaml:"reason"`
}

// EnvironmentConfig contains per-environment thresholds.
type EnvironmentConfig struct {
	Decision DecisionConfig `json:"decision" yaml:"decision"`
}

// ScopeConfig controls which findings are eligible for enforcement.
type ScopeConfig struct {
	ChangedResourcesOnly bool `json:"changed_resources_only" yaml:"changed_resources_only"`
}

// BaselineConfig controls existing-risk handling.
type BaselineConfig struct {
	File              string   `json:"file" yaml:"file"`
	Mode              string   `json:"mode" yaml:"mode"`
	Fingerprints      []string `json:"fingerprints" yaml:"fingerprints"`
	MaxAgeDays        int      `json:"max_age_days" yaml:"max_age_days"`
	RequireExpiration bool     `json:"require_expiration" yaml:"require_expiration"`
}

// WaiverConfig controls exception governance.
type WaiverConfig struct {
	File              string `json:"file" yaml:"file"`
	RequireExpiration bool   `json:"require_expiration" yaml:"require_expiration"`
	MaxDurationDays   int    `json:"max_duration_days" yaml:"max_duration_days"`
	FailExpired       bool   `json:"fail_expired" yaml:"fail_expired"`
}

// CustomRulesConfig controls declarative custom rule loading.
type CustomRulesConfig struct {
	Files       []string `json:"files" yaml:"files"`
	Required    bool     `json:"required" yaml:"required"`
	MaxFileSize int64    `json:"max_file_size" yaml:"max_file_size"`
}

// RegoConfig controls optional OPA/Rego policy evaluation.
type RegoConfig struct {
	Files         []string `json:"files" yaml:"files"`
	Query         string   `json:"query" yaml:"query"`
	Timeout       string   `json:"timeout" yaml:"timeout"`
	MaxInputBytes int64    `json:"max_input_bytes" yaml:"max_input_bytes"`
}

// DocsConfig controls developer-facing documentation links.
type DocsConfig struct {
	Links map[string]string `json:"links" yaml:"links"`
}

// ReviewConfig controls pull request and merge request review output.
type ReviewConfig struct {
	Enabled             *bool  `json:"enabled" yaml:"enabled"`
	MaxCommentFindings  *int   `json:"max_comment_findings" yaml:"max_comment_findings"`
	MaxGraphPaths       *int   `json:"max_graph_paths" yaml:"max_graph_paths"`
	StickyCommentMarker string `json:"sticky_comment_marker" yaml:"sticky_comment_marker"`
}

// ImpactConfig controls Security Impact Statement rendering.
type ImpactConfig struct {
	IncludeExistingRisks *bool `json:"include_existing_risks" yaml:"include_existing_risks"`
	IncludeResolvedRisks *bool `json:"include_resolved_risks" yaml:"include_resolved_risks"`
	IncludeWaivers       *bool `json:"include_waivers" yaml:"include_waivers"`
}

// AttackPathsConfig controls attack path detection and enforcement.
type AttackPathsConfig struct {
	Enabled             *bool `json:"enabled" yaml:"enabled"`
	BlockHighConfidence *bool `json:"block_high_confidence" yaml:"block_high_confidence"`
}

// ValidationResult is returned by policy validation commands.
type ValidationResult struct {
	Valid       bool               `json:"valid"`
	Policy      Config             `json:"policy"`
	Diagnostics []model.Diagnostic `json:"diagnostics,omitempty"`
}

// LoadFile loads policy config from path.
func LoadFile(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open policy %q: %w", path, err)
	}
	defer closeFile(file)
	return Load(file)
}

// Load reads policy config YAML.
func Load(r io.Reader) (Config, error) {
	var config Config
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode policy: %w", err)
	}
	return config, nil
}

// Validate validates policy config against registered rules and packs.
func Validate(config Config, registry *rules.Registry, packs []rules.PolicyPack) ValidationResult {
	diagnostics := make([]model.Diagnostic, 0)
	config = applyReviewIntelligenceDefaults(config)

	if config.Version != 0 && config.Version != 1 {
		diagnostics = append(diagnostics, errorDiagnostic("POLICY_VERSION_UNSUPPORTED", "policy version must be 1"))
	}
	if config.Mode != "" && config.Mode != model.PolicyModeBlock && config.Mode != model.PolicyModeWarn && config.Mode != model.PolicyModeAudit {
		diagnostics = append(diagnostics, errorDiagnostic("POLICY_MODE_INVALID", "mode must be block, warn, or audit"))
	}

	packIDs := make(map[string]bool, len(packs))
	for _, pack := range packs {
		packIDs[pack.ID] = true
	}
	for _, packID := range config.PolicyPacks {
		if !packIDs[packID] {
			diagnostics = append(diagnostics, errorDiagnostic("POLICY_PACK_UNKNOWN", "unknown policy pack "+packID))
		}
	}
	for packID, version := range config.PolicyPackVersions {
		if !packIDs[packID] {
			diagnostics = append(diagnostics, errorDiagnostic("POLICY_PACK_VERSION_UNKNOWN", "policy_pack_versions references unknown policy pack "+packID))
			continue
		}
		for _, pack := range packs {
			if pack.ID == packID && pack.Version != version {
				diagnostics = append(diagnostics, errorDiagnostic("POLICY_PACK_VERSION_MISMATCH", fmt.Sprintf("policy pack %s version is %s, pinned version is %s", packID, pack.Version, version)))
			}
		}
	}
	if config.PolicyPackSigning.RequireSigned {
		diagnostics = append(diagnostics, errorDiagnostic("POLICY_PACK_SIGNING_UNSUPPORTED", "policy_pack_signing.require_signed is reserved for future remote policy packs; built-in packs are bundled with the signed ChangeGate binary"))
	}

	for _, ruleID := range append(config.Rules.Enabled, config.Rules.Disabled...) {
		if _, ok := registry.Get(ruleID); !ok {
			diagnostics = append(diagnostics, errorDiagnostic("RULE_UNKNOWN", "unknown rule "+ruleID))
		}
	}
	for ruleID := range config.Overrides {
		if _, ok := registry.Get(ruleID); !ok {
			diagnostics = append(diagnostics, errorDiagnostic("RULE_OVERRIDE_UNKNOWN", "override references unknown rule "+ruleID))
		}
	}
	if config.Baseline.Mode != "" && config.Baseline.Mode != "new-findings-only" && config.Baseline.Mode != "new-risk-only" {
		diagnostics = append(diagnostics, errorDiagnostic("BASELINE_MODE_INVALID", "baseline.mode must be new-findings-only or new-risk-only"))
	}
	if config.Baseline.MaxAgeDays < 0 {
		diagnostics = append(diagnostics, errorDiagnostic("BASELINE_MAX_AGE_INVALID", "baseline.max_age_days must be non-negative"))
	}
	if config.Waivers.MaxDurationDays < 0 {
		diagnostics = append(diagnostics, errorDiagnostic("WAIVER_MAX_DURATION_INVALID", "waivers.max_duration_days must be non-negative"))
	}
	if config.CustomRules.MaxFileSize < 0 {
		diagnostics = append(diagnostics, errorDiagnostic("CUSTOM_RULES_MAX_FILE_SIZE_INVALID", "custom_rules.max_file_size must be non-negative"))
	}
	if config.Rego.MaxInputBytes < 0 {
		diagnostics = append(diagnostics, errorDiagnostic("REGO_MAX_INPUT_BYTES_INVALID", "rego.max_input_bytes must be non-negative"))
	}
	if config.Rego.Query == "" && len(config.Rego.Files) > 0 {
		config.Rego.Query = "data.changegate.findings"
	}
	if config.Review.MaxCommentFindings != nil && *config.Review.MaxCommentFindings < 0 {
		diagnostics = append(diagnostics, errorDiagnostic("REVIEW_MAX_COMMENT_FINDINGS_INVALID", "review.max_comment_findings must be non-negative"))
	}
	if config.Review.MaxGraphPaths != nil && *config.Review.MaxGraphPaths < 0 {
		diagnostics = append(diagnostics, errorDiagnostic("REVIEW_MAX_GRAPH_PATHS_INVALID", "review.max_graph_paths must be non-negative"))
	}
	if reviewEnabled(config.Review) && config.Review.StickyCommentMarker == "" {
		diagnostics = append(diagnostics, errorDiagnostic("REVIEW_STICKY_COMMENT_MARKER_INVALID", "review.sticky_comment_marker must be non-empty when review is enabled"))
	}

	return ValidationResult{
		Valid:       len(diagnostics) == 0,
		Policy:      config,
		Diagnostics: diagnostics,
	}
}

// ModelConfig converts user config to model policy config.
func ModelConfig(config Config, environment string) model.PolicyConfig {
	out := model.DefaultPolicyConfig()
	if config.Mode != "" {
		out.Mode = config.Mode
	}
	if threshold := toThreshold(config.Decision.BlockOn); threshold.MinSeverity != "" || threshold.MinConfidence != "" {
		mergeThreshold(&out.BlockOn, threshold)
	}
	if threshold := toThreshold(config.Decision.WarnOn); threshold.MinSeverity != "" || threshold.MinConfidence != "" {
		mergeThreshold(&out.WarnOn, threshold)
	}
	if env, ok := config.Environments[environment]; ok {
		if threshold := toThreshold(env.Decision.BlockOn); threshold.MinSeverity != "" || threshold.MinConfidence != "" {
			mergeThreshold(&out.BlockOn, threshold)
		}
		if threshold := toThreshold(env.Decision.WarnOn); threshold.MinSeverity != "" || threshold.MinConfidence != "" {
			mergeThreshold(&out.WarnOn, threshold)
		}
	}
	out.EnvironmentThresholds = make(map[string]model.Thresholds, len(config.Environments))
	for name, env := range config.Environments {
		out.EnvironmentThresholds[name] = model.Thresholds{
			BlockOn: toThreshold(env.Decision.BlockOn),
			WarnOn:  toThreshold(env.Decision.WarnOn),
		}
	}
	out.BranchThresholds = make(map[string]model.Thresholds, len(config.Branches))
	for name, branch := range config.Branches {
		out.BranchThresholds[name] = model.Thresholds{
			BlockOn: toThreshold(branch.Decision.BlockOn),
			WarnOn:  toThreshold(branch.Decision.WarnOn),
		}
	}
	out.ChangedResourcesOnly = config.Scope.ChangedResourcesOnly
	out.NewRiskOnly = config.Baseline.Mode == "new-findings-only" || config.Baseline.Mode == "new-risk-only"
	out.DocumentationLinks = copyStringMap(config.Docs.Links)
	out.ExistingFingerprints = make(map[string]bool, len(config.Baseline.Fingerprints))
	for _, fingerprint := range config.Baseline.Fingerprints {
		out.ExistingFingerprints[fingerprint] = true
	}
	out.Overrides = make(map[string]model.Override, len(config.Overrides))
	for ruleID, override := range config.Overrides {
		modelOverride := model.Override{Reason: override.Reason}
		if override.Severity != "" {
			severity := override.Severity
			modelOverride.Severity = &severity
		}
		if override.Confidence != "" {
			confidence := override.Confidence
			modelOverride.Confidence = &confidence
		}
		out.Overrides[ruleID] = modelOverride
	}
	return out
}

// RuleSelection converts policy config to rule selection.
func RuleSelection(config Config, packs []rules.PolicyPack) rules.Selection {
	enabled := make(map[string]bool)
	if len(config.PolicyPacks) > 0 {
		packRules := make(map[string][]string, len(packs))
		for _, pack := range packs {
			packRules[pack.ID] = pack.Rules
		}
		for _, packID := range config.PolicyPacks {
			for _, ruleID := range packRules[packID] {
				enabled[ruleID] = true
			}
		}
	}
	for _, ruleID := range config.Rules.Enabled {
		enabled[ruleID] = true
	}

	disabled := make(map[string]bool, len(config.Rules.Disabled))
	for _, ruleID := range config.Rules.Disabled {
		disabled[ruleID] = true
	}

	overrides := make(map[string]model.Override, len(config.Overrides))
	for ruleID, override := range config.Overrides {
		modelOverride := model.Override{Reason: override.Reason}
		if override.Severity != "" {
			severity := override.Severity
			modelOverride.Severity = &severity
		}
		if override.Confidence != "" {
			confidence := override.Confidence
			modelOverride.Confidence = &confidence
		}
		overrides[ruleID] = modelOverride
	}

	return rules.Selection{
		EnabledRules:  enabled,
		DisabledRules: disabled,
		Overrides:     overrides,
	}
}

func toThreshold(config ThresholdConfig) model.Threshold {
	severity := config.MinSeverity
	if severity == "" {
		severity = config.Severity
	}
	confidence := config.MinConfidence
	if confidence == "" {
		confidence = config.Confidence
	}
	return model.Threshold{
		MinSeverity:   severity,
		MinConfidence: confidence,
	}
}

func applyReviewIntelligenceDefaults(config Config) Config {
	if config.Review.Enabled == nil {
		enabled := true
		config.Review.Enabled = &enabled
	}
	if config.Review.MaxCommentFindings == nil {
		config.Review.MaxCommentFindings = intPtr(10)
	}
	if config.Review.MaxGraphPaths == nil {
		config.Review.MaxGraphPaths = intPtr(5)
	}
	if config.Review.StickyCommentMarker == "" {
		config.Review.StickyCommentMarker = "<!-- changegate-review -->"
	}
	if config.Impact.IncludeExistingRisks == nil {
		config.Impact.IncludeExistingRisks = boolPtr(true)
	}
	if config.Impact.IncludeResolvedRisks == nil {
		config.Impact.IncludeResolvedRisks = boolPtr(true)
	}
	if config.Impact.IncludeWaivers == nil {
		config.Impact.IncludeWaivers = boolPtr(true)
	}
	if config.AttackPaths.Enabled == nil {
		config.AttackPaths.Enabled = boolPtr(true)
	}
	if config.AttackPaths.BlockHighConfidence == nil {
		config.AttackPaths.BlockHighConfidence = boolPtr(true)
	}
	return config
}

func reviewEnabled(config ReviewConfig) bool {
	return config.Enabled == nil || *config.Enabled
}

func boolPtr(value bool) *bool {
	return &value
}

func intPtr(value int) *int {
	return &value
}

func mergeThreshold(target *model.Threshold, source model.Threshold) {
	if source.MinSeverity != "" {
		target.MinSeverity = source.MinSeverity
	}
	if source.MinConfidence != "" {
		target.MinConfidence = source.MinConfidence
	}
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func errorDiagnostic(code string, message string) model.Diagnostic {
	return model.Diagnostic{
		Severity: model.DiagnosticError,
		Code:     code,
		Message:  message,
	}
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}
