package custompolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
	"github.com/open-policy-agent/opa/v1/rego"
)

const (
	defaultRegoQuery         = "data.changegate.findings"
	defaultRegoTimeout       = 250 * time.Millisecond
	defaultRegoMaxInputBytes = int64(5 * 1024 * 1024)
)

// RegoOptions controls optional OPA/Rego rule loading.
type RegoOptions struct {
	PolicyPath    string
	Files         []string
	Query         string
	Timeout       time.Duration
	MaxInputBytes int64
}

// LoadRegoRule loads one policy-configured OPA/Rego rule.
func LoadRegoRule(options RegoOptions) (rules.Rule, []Diagnostic) {
	if len(options.Files) == 0 {
		return nil, nil
	}
	if options.Query == "" {
		options.Query = defaultRegoQuery
	}
	if options.Timeout == 0 {
		options.Timeout = defaultRegoTimeout
	}
	if options.MaxInputBytes == 0 {
		options.MaxInputBytes = defaultRegoMaxInputBytes
	}
	modules := make(map[string]string)
	var diagnostics []Diagnostic
	for _, pattern := range options.Files {
		matches, err := resolvePolicyPattern(options.PolicyPath, pattern)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "REGO_PATTERN_INVALID", Message: err.Error()})
			continue
		}
		if len(matches) == 0 {
			diagnostics = append(diagnostics, Diagnostic{Code: "REGO_PATTERN_EMPTY", Message: "no Rego policy files matched " + pattern})
			continue
		}
		for _, path := range matches {
			body, err := os.ReadFile(path)
			if err != nil {
				diagnostics = append(diagnostics, Diagnostic{Code: "REGO_FILE_READ_FAILED", Message: fmt.Sprintf("%s: %v", path, err)})
				continue
			}
			if unsafeBuiltin := unsafeRegoBuiltin(string(body)); unsafeBuiltin != "" {
				diagnostics = append(diagnostics, Diagnostic{Code: "REGO_UNSAFE_BUILTIN", Message: fmt.Sprintf("%s uses disabled builtin %s", path, unsafeBuiltin)})
				continue
			}
			modules[filepath.Base(path)] = string(body)
		}
	}
	if len(modules) == 0 {
		return nil, diagnostics
	}
	if err := validateRegoModules(options.Query, modules, options.Timeout); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "REGO_COMPILE_FAILED", Message: err.Error()})
		return nil, diagnostics
	}
	return regoRule{modules: modules, query: options.Query, timeout: options.Timeout, maxInputBytes: options.MaxInputBytes}, diagnostics
}

type regoRule struct {
	modules       map[string]string
	query         string
	timeout       time.Duration
	maxInputBytes int64
}

// Metadata returns metadata for the synthetic Rego rule.
func (r regoRule) Metadata() rules.Metadata {
	return rules.Metadata{
		ID:           "CUSTOM_OPA_REGO",
		Title:        "Custom OPA/Rego policy",
		Description:  "Evaluates policy-configured OPA/Rego modules over the ChangeGate scan input.",
		Category:     model.RiskCategoryCompliance,
		Severity:     model.SeverityMedium,
		Confidence:   model.ConfidenceMedium,
		Capabilities: []rules.Capability{rules.CapabilityResourceChanges, rules.CapabilityPlannedValues, rules.CapabilityGraph},
		Status:       rules.StatusStable,
		Version:      "opa-rego/v1",
		PolicyPack:   "custom-rego",
		Documentation: rules.Documentation{
			Summary:     "Custom Rego policies return ChangeGate findings from a bounded input object.",
			Remediation: []string{"Review the custom Rego policy and the returned finding remediation."},
		},
	}
}

// Evaluate executes configured Rego modules with a timeout and bounded redacted input.
func (r regoRule) Evaluate(ctx context.Context, input rules.RuleInput) ([]model.Finding, error) {
	opaInput := OPAInput{
		Plan:        input.Plan,
		Resources:   resources(input.Plan),
		Changes:     changes(input.Plan),
		Graph:       input.Graph,
		Environment: input.Environment,
		Policy: map[string]any{
			"query": r.query,
		},
	}
	encoded, err := json.Marshal(opaInput)
	if err != nil {
		return nil, fmt.Errorf("marshal Rego input: %w", err)
	}
	if int64(len(encoded)) > r.maxInputBytes {
		return nil, fmt.Errorf("Rego input exceeds %d bytes", r.maxInputBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	args := []func(*rego.Rego){rego.Query(r.query), rego.Input(opaInput)}
	for name, module := range r.modules {
		args = append(args, rego.Module(name, module))
	}
	results, err := rego.New(args...).Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluate Rego: %w", err)
	}
	return findingsFromRegoResults(results), nil
}

// OPAInput is the documented input schema passed to optional Rego policies.
type OPAInput struct {
	Plan         *model.Plan      `json:"plan"`
	Resources    []model.Resource `json:"resources"`
	Changes      []model.Change   `json:"changes"`
	Graph        *graph.Graph     `json:"graph"`
	Environment  string           `json:"environment"`
	CloudContext any              `json:"cloud_context"`
	Policy       map[string]any   `json:"policy"`
}

func findingsFromRegoResults(results rego.ResultSet) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, result := range results {
		for _, expression := range result.Expressions {
			findings = append(findings, findingsFromRegoValue(expression.Value)...)
		}
	}
	return findings
}

func findingsFromRegoValue(value any) []model.Finding {
	switch typed := value.(type) {
	case []any:
		findings := make([]model.Finding, 0, len(typed))
		for _, item := range typed {
			finding, ok := findingFromMap(item)
			if ok {
				findings = append(findings, finding)
			}
		}
		return findings
	case map[string]any:
		if finding, ok := findingFromMap(typed); ok {
			return []model.Finding{finding}
		}
	case bool:
		if typed {
			return []model.Finding{{
				ResourceAddress: "custom-rego",
				Title:           "Custom Rego policy matched",
				Evidence: []model.Evidence{{
					Type:     "custom_rego",
					Resource: "custom-rego",
					Path:     "rego",
					Message:  "Rego query returned true",
				}},
			}}
		}
	}
	return nil
}

func findingFromMap(value any) (model.Finding, bool) {
	item, ok := value.(map[string]any)
	if !ok {
		return model.Finding{}, false
	}
	resource := firstNonEmpty(asString(item["resource_address"]), asString(item["resource"]))
	if resource == "" {
		resource = "custom-rego"
	}
	title := firstNonEmpty(asString(item["title"]), asString(item["message"]), "Custom Rego policy matched")
	finding := model.Finding{
		RuleID:          firstNonEmpty(asString(item["rule_id"]), "CUSTOM_OPA_REGO"),
		Title:           title,
		Description:     asString(item["description"]),
		ResourceAddress: resource,
		Provider:        firstNonEmpty(asString(item["provider"]), "custom-rego"),
		Category:        riskCategory(asString(item["category"])),
		Severity:        severity(asString(item["severity"])),
		Confidence:      confidence(asString(item["confidence"])),
		Evidence: []model.Evidence{{
			Type:     "custom_rego",
			Resource: resource,
			Path:     "rego",
			Value:    item["evidence"],
			Message:  "Rego policy returned finding",
		}},
		Remediation: model.Remediation{Summary: asString(item["remediation"])},
	}
	return finding, true
}

func unsafeRegoBuiltin(module string) string {
	disabled := []string{
		"http.send",
		"net.lookup_ip_addr",
		"opa.runtime",
		"rego.parse_module",
		"trace",
	}
	for _, builtin := range disabled {
		if strings.Contains(module, builtin) {
			return builtin
		}
	}
	return ""
}

func validateRegoModules(query string, modules map[string]string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args := []func(*rego.Rego){rego.Query(query)}
	for name, module := range modules {
		args = append(args, rego.Module(name, module))
	}
	_, err := rego.New(args...).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("compile Rego modules: %w", err)
	}
	return nil
}

func resources(plan *model.Plan) []model.Resource {
	if plan == nil {
		return nil
	}
	out := append([]model.Resource(nil), plan.Resources...)
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].Address < out[j].Address
	})
	return out
}

func changes(plan *model.Plan) []model.Change {
	if plan == nil {
		return nil
	}
	out := append([]model.Change(nil), plan.Changes...)
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].Address < out[j].Address
	})
	return out
}

func riskCategory(value string) model.RiskCategory {
	switch strings.ToLower(value) {
	case string(model.RiskCategoryPublicExposure):
		return model.RiskCategoryPublicExposure
	case string(model.RiskCategoryPrivilegeEscalation):
		return model.RiskCategoryPrivilegeEscalation
	case string(model.RiskCategorySensitiveData):
		return model.RiskCategorySensitiveData
	case string(model.RiskCategoryNetworkBlastRadius):
		return model.RiskCategoryNetworkBlastRadius
	case string(model.RiskCategoryAvailability):
		return model.RiskCategoryAvailability
	case string(model.RiskCategoryCompliance):
		return model.RiskCategoryCompliance
	default:
		return model.RiskCategoryCompliance
	}
}

func severity(value string) model.Severity {
	switch strings.ToLower(value) {
	case string(model.SeverityCritical):
		return model.SeverityCritical
	case string(model.SeverityHigh):
		return model.SeverityHigh
	case string(model.SeverityLow):
		return model.SeverityLow
	case string(model.SeverityInfo):
		return model.SeverityInfo
	default:
		return model.SeverityMedium
	}
}

func confidence(value string) model.Confidence {
	switch strings.ToLower(value) {
	case string(model.ConfidenceHigh):
		return model.ConfidenceHigh
	case string(model.ConfidenceLow):
		return model.ConfidenceLow
	case string(model.ConfidenceUnknown):
		return model.ConfidenceUnknown
	default:
		return model.ConfidenceMedium
	}
}
