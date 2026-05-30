// Package custompolicy loads policy-configured custom rule engines.
package custompolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/rules"
	"gopkg.in/yaml.v3"
)

const (
	defaultCustomRuleFileSize = int64(1024 * 1024)
	customRulePackVersion     = "custom-yaml/v1"
)

// Diagnostic captures non-fatal custom policy loading issues.
type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// LoadYAMLRules loads declarative custom rules from files or glob patterns.
func LoadYAMLRules(policyPath string, patterns []string, maxFileSize int64) ([]rules.Rule, []Diagnostic) {
	if len(patterns) == 0 {
		return nil, nil
	}
	if maxFileSize == 0 {
		maxFileSize = defaultCustomRuleFileSize
	}
	var diagnostics []Diagnostic
	var loaded []rules.Rule
	for _, pattern := range patterns {
		matches, err := resolvePolicyPattern(policyPath, pattern)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "CUSTOM_RULE_PATTERN_INVALID", Message: err.Error()})
			continue
		}
		if len(matches) == 0 {
			diagnostics = append(diagnostics, Diagnostic{Code: "CUSTOM_RULE_PATTERN_EMPTY", Message: "no custom rule files matched " + pattern})
			continue
		}
		for _, path := range matches {
			ruleSet, fileDiagnostics := loadYAMLRuleFile(path, maxFileSize)
			diagnostics = append(diagnostics, fileDiagnostics...)
			loaded = append(loaded, ruleSet...)
		}
	}
	sort.SliceStable(loaded, func(i int, j int) bool {
		return loaded[i].Metadata().ID < loaded[j].Metadata().ID
	})
	return loaded, diagnostics
}

type yamlRuleFile struct {
	Rules []yamlRuleConfig `json:"rules" yaml:"rules"`
}

type yamlRuleConfig struct {
	ID          string             `json:"id" yaml:"id"`
	Title       string             `json:"title" yaml:"title"`
	Description string             `json:"description" yaml:"description"`
	Category    model.RiskCategory `json:"category" yaml:"category"`
	Severity    model.Severity     `json:"severity" yaml:"severity"`
	Confidence  model.Confidence   `json:"confidence" yaml:"confidence"`
	Select      selector           `json:"select" yaml:"select"`
	Where       condition          `json:"where" yaml:"where"`
	Remediation string             `json:"remediation" yaml:"remediation"`
	References  []string           `json:"references" yaml:"references"`
}

type selector struct {
	Type     string            `json:"type" yaml:"type"`
	Provider string            `json:"provider" yaml:"provider"`
	Address  string            `json:"address" yaml:"address"`
	Tags     map[string]string `json:"tags" yaml:"tags"`
	Actions  []model.Action    `json:"actions" yaml:"actions"`
}

type condition struct {
	All                  []condition `json:"all" yaml:"all"`
	Any                  []condition `json:"any" yaml:"any"`
	Not                  *condition  `json:"not" yaml:"not"`
	Field                string      `json:"field" yaml:"field"`
	Equals               any         `json:"equals" yaml:"equals"`
	NotEquals            any         `json:"not_equals" yaml:"not_equals"`
	Contains             string      `json:"contains" yaml:"contains"`
	In                   []any       `json:"in" yaml:"in"`
	Exists               *bool       `json:"exists" yaml:"exists"`
	GraphRoutesToTag     *tagMatch   `json:"graph.routes_to.tag" yaml:"graph.routes_to.tag"`
	GraphInternetExposed *bool       `json:"graph.internet_exposed" yaml:"graph.internet_exposed"`
	GraphSensitiveData   *bool       `json:"graph.sensitive_data_access" yaml:"graph.sensitive_data_access"`
}

type tagMatch struct {
	Key   string `json:"key" yaml:"key"`
	Value string `json:"value" yaml:"value"`
}

type yamlRule struct {
	meta      rules.Metadata
	selectBy  selector
	where     condition
	remediate string
}

func loadYAMLRuleFile(path string, maxFileSize int64) ([]rules.Rule, []Diagnostic) {
	file, err := os.Open(path)
	if err != nil {
		return nil, []Diagnostic{{Code: "CUSTOM_RULE_FILE_OPEN_FAILED", Message: fmt.Sprintf("%s: %v", path, err)}}
	}
	defer closeFile(file)
	stat, err := file.Stat()
	if err != nil {
		return nil, []Diagnostic{{Code: "CUSTOM_RULE_FILE_STAT_FAILED", Message: fmt.Sprintf("%s: %v", path, err)}}
	}
	if stat.Size() > maxFileSize {
		return nil, []Diagnostic{{Code: "CUSTOM_RULE_FILE_TOO_LARGE", Message: fmt.Sprintf("%s exceeds %d bytes", path, maxFileSize)}}
	}
	body, err := io.ReadAll(file)
	if err != nil {
		return nil, []Diagnostic{{Code: "CUSTOM_RULE_FILE_READ_FAILED", Message: fmt.Sprintf("%s: %v", path, err)}}
	}
	ruleConfigs, err := decodeYAMLRuleFile(body)
	if err != nil {
		return nil, []Diagnostic{{Code: "CUSTOM_RULE_FILE_INVALID", Message: fmt.Sprintf("%s: %v", path, err)}}
	}
	out := make([]rules.Rule, 0, len(ruleConfigs))
	var diagnostics []Diagnostic
	for _, config := range ruleConfigs {
		rule, err := newYAMLRule(config)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "CUSTOM_RULE_INVALID", Message: fmt.Sprintf("%s: %v", path, err)})
			continue
		}
		out = append(out, rule)
	}
	return out, diagnostics
}

func decodeYAMLRuleFile(body []byte) ([]yamlRuleConfig, error) {
	var file yamlRuleFile
	decoder := yaml.NewDecoder(strings.NewReader(string(body)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err == nil && len(file.Rules) > 0 {
		return file.Rules, nil
	}
	var single yamlRuleConfig
	decoder = yaml.NewDecoder(strings.NewReader(string(body)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&single); err != nil {
		return nil, err
	}
	return []yamlRuleConfig{single}, nil
}

func newYAMLRule(config yamlRuleConfig) (rules.Rule, error) {
	if config.ID == "" {
		return nil, fmt.Errorf("custom rule missing id")
	}
	if config.Title == "" {
		return nil, fmt.Errorf("custom rule %s missing title", config.ID)
	}
	if config.Category == "" {
		config.Category = model.RiskCategoryUnknown
	}
	if config.Severity == "" {
		config.Severity = model.SeverityMedium
	}
	if config.Confidence == "" {
		config.Confidence = model.ConfidenceMedium
	}
	meta := rules.Metadata{
		ID:          config.ID,
		Title:       config.Title,
		Description: config.Description,
		Category:    config.Category,
		Severity:    config.Severity,
		Confidence:  config.Confidence,
		Resources:   stringSlice(config.Select.Type),
		Capabilities: []rules.Capability{
			rules.CapabilityResourceChanges,
			rules.CapabilityPlannedValues,
			rules.CapabilityGraph,
		},
		Status:     rules.StatusStable,
		Version:    customRulePackVersion,
		PolicyPack: "custom-yaml",
		Documentation: rules.Documentation{
			Summary:     firstNonEmpty(config.Description, config.Title),
			Remediation: stringSlice(config.Remediation),
			References:  config.References,
		},
	}
	if err := rules.ValidateMetadata(meta); err != nil {
		return nil, err
	}
	return yamlRule{meta: meta, selectBy: config.Select, where: config.Where, remediate: config.Remediation}, nil
}

// Metadata returns declarative rule metadata.
func (r yamlRule) Metadata() rules.Metadata {
	return r.meta
}

// Evaluate evaluates a declarative YAML rule over changed resources.
func (r yamlRule) Evaluate(ctx context.Context, input rules.RuleInput) ([]model.Finding, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("custom rule %s cancelled: %w", r.meta.ID, ctx.Err())
	default:
	}
	matches := r.matchingChanges(input)
	findings := make([]model.Finding, 0, len(matches))
	for _, change := range matches {
		if !evalCondition(r.where, change, input.Graph) {
			continue
		}
		findings = append(findings, model.Finding{
			ResourceAddress: change.Address,
			Provider:        change.Provider,
			Environment:     envFromTags(change.Tags, change.After),
			Evidence: []model.Evidence{{
				Type:     "custom_rule",
				Resource: change.Address,
				Path:     "custom_rules." + r.meta.ID,
				Value:    evidenceValue(change),
				Message:  "custom YAML rule matched changed resource",
			}},
			Remediation: model.Remediation{Summary: r.remediate},
		})
	}
	return findings, nil
}

func (r yamlRule) matchingChanges(input rules.RuleInput) []model.Change {
	if input.Plan == nil {
		return nil
	}
	out := make([]model.Change, 0)
	for _, change := range input.Plan.Changes {
		if !selectorMatches(r.selectBy, change) {
			continue
		}
		out = append(out, change)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].Address < out[j].Address
	})
	return out
}

func selectorMatches(selectBy selector, change model.Change) bool {
	if selectBy.Type != "" && change.Type != selectBy.Type {
		return false
	}
	if selectBy.Provider != "" && !strings.Contains(change.Provider, selectBy.Provider) {
		return false
	}
	if selectBy.Address != "" && change.Address != selectBy.Address {
		return false
	}
	if len(selectBy.Actions) > 0 && !actionsIntersect(selectBy.Actions, change.Actions) {
		return false
	}
	for key, value := range selectBy.Tags {
		if !strings.EqualFold(change.Tags[key], value) {
			return false
		}
	}
	return true
}

func evalCondition(cond condition, change model.Change, g *graph.Graph) bool {
	for _, child := range cond.All {
		if !evalCondition(child, change, g) {
			return false
		}
	}
	if len(cond.Any) > 0 {
		matched := false
		for _, child := range cond.Any {
			if evalCondition(child, change, g) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if cond.Not != nil && evalCondition(*cond.Not, change, g) {
		return false
	}
	if cond.Field != "" && !evalFieldCondition(cond, change) {
		return false
	}
	if cond.GraphRoutesToTag != nil && !routesToTag(g, graph.ResourceID(change.Address), *cond.GraphRoutesToTag) {
		return false
	}
	if cond.GraphInternetExposed != nil && g.IsInternetExposed(graph.ResourceID(change.Address)) != *cond.GraphInternetExposed {
		return false
	}
	if cond.GraphSensitiveData != nil && g.HasSensitiveDataAccess(graph.ResourceID(change.Address)) != *cond.GraphSensitiveData {
		return false
	}
	return true
}

func evalFieldCondition(cond condition, change model.Change) bool {
	value, exists := fieldValue(change, cond.Field)
	if cond.Exists != nil && exists != *cond.Exists {
		return false
	}
	if cond.Equals != nil && !valuesEqual(value, cond.Equals) {
		return false
	}
	if cond.NotEquals != nil && valuesEqual(value, cond.NotEquals) {
		return false
	}
	if cond.Contains != "" && !strings.Contains(strings.ToLower(asString(value)), strings.ToLower(cond.Contains)) {
		return false
	}
	if len(cond.In) > 0 {
		for _, item := range cond.In {
			if valuesEqual(value, item) {
				return true
			}
		}
		return false
	}
	return true
}

func fieldValue(change model.Change, field string) (any, bool) {
	switch {
	case field == "address":
		return change.Address, change.Address != ""
	case field == "type":
		return change.Type, change.Type != ""
	case field == "name":
		return change.Name, change.Name != ""
	case field == "provider":
		return change.Provider, change.Provider != ""
	case strings.HasPrefix(field, "tags."):
		key := strings.TrimPrefix(field, "tags.")
		value, ok := change.Tags[key]
		return value, ok
	case strings.HasPrefix(field, "before."):
		return pathValue(change.Before, strings.TrimPrefix(field, "before."))
	case strings.HasPrefix(field, "after."):
		return pathValue(change.After, strings.TrimPrefix(field, "after."))
	default:
		value, ok := pathValue(change.After, field)
		return value, ok
	}
}

func pathValue(values map[string]any, path string) (any, bool) {
	if values == nil {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var current any = values
	for _, part := range parts {
		asMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = asMap[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func routesToTag(g *graph.Graph, from graph.ResourceID, match tagMatch) bool {
	if g == nil || match.Key == "" {
		return false
	}
	for _, edge := range g.OutgoingEdges(from) {
		if edge.Type != graph.EdgeRoutesTo && edge.Type != graph.EdgeAttachedTo {
			continue
		}
		node := g.Nodes[edge.To]
		if node != nil && strings.EqualFold(node.Tags[match.Key], match.Value) {
			return true
		}
	}
	return false
}

func actionsIntersect(want []model.Action, got []model.Action) bool {
	for _, left := range want {
		for _, right := range got {
			if left == right {
				return true
			}
		}
	}
	return false
}

func valuesEqual(left any, right any) bool {
	return strings.EqualFold(asString(left), asString(right))
}

func evidenceValue(change model.Change) any {
	return map[string]any{"actions": change.Actions, "type": change.Type}
}

func envFromTags(tags map[string]string, after map[string]any) string {
	for _, key := range []string{"env", "environment", "stage"} {
		value := strings.ToLower(tags[key])
		if value == "" {
			if rawTags, ok := after["tags"].(map[string]any); ok {
				value = strings.ToLower(asString(rawTags[key]))
			}
		}
		switch value {
		case "prod", "production":
			return "production"
		case "stage", "staging":
			return "staging"
		case "dev", "development":
			return "development"
		}
	}
	return ""
}

func resolvePolicyPattern(policyPath string, pattern string) ([]string, error) {
	if pattern == "" {
		return nil, nil
	}
	resolved := pattern
	if !filepath.IsAbs(pattern) && policyPath != "" {
		resolved = filepath.Join(filepath.Dir(policyPath), pattern)
	}
	matches, err := filepath.Glob(resolved)
	if err != nil {
		return nil, fmt.Errorf("glob %q: %w", pattern, err)
	}
	sort.Strings(matches)
	return matches, nil
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(encoded)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func stringSlice(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}
