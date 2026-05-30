// Package rules contains the native ChangeGate rule engine.
package rules

import (
	"context"
	"fmt"
	"sort"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

// Status describes a rule lifecycle state.
type Status string

const (
	// StatusExperimental rules are visible but do not block by default.
	StatusExperimental Status = "experimental"
	// StatusStable rules are production-ready for default enforcement.
	StatusStable Status = "stable"
	// StatusDeprecated rules remain visible for compatibility but should not be enabled by default.
	StatusDeprecated Status = "deprecated"
)

// Capability declares which plan capabilities a rule needs.
type Capability string

const (
	// CapabilityResourceChanges means the rule consumes plan resource_changes.
	CapabilityResourceChanges Capability = "resource_changes"
	// CapabilityPlannedValues means the rule consumes planned_values resources.
	CapabilityPlannedValues Capability = "planned_values"
	// CapabilityPriorState means the rule consumes prior_state resources.
	CapabilityPriorState Capability = "prior_state"
	// CapabilityConfiguration means the rule consumes configuration expressions.
	CapabilityConfiguration Capability = "configuration"
	// CapabilityGraph means the rule needs graph relationships.
	CapabilityGraph Capability = "graph"
)

// Documentation is generated from rule metadata for CLI and docs output.
type Documentation struct {
	Summary     string   `json:"summary"`
	Rationale   string   `json:"rationale,omitempty"`
	Remediation []string `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Metadata describes a rule without executing it.
type Metadata struct {
	ID            string             `json:"id"`
	Title         string             `json:"title"`
	Description   string             `json:"description"`
	Category      model.RiskCategory `json:"category"`
	Severity      model.Severity     `json:"severity"`
	Confidence    model.Confidence   `json:"confidence"`
	Providers     []string           `json:"providers,omitempty"`
	Resources     []string           `json:"resources,omitempty"`
	Capabilities  []Capability       `json:"capabilities,omitempty"`
	Status        Status             `json:"status"`
	Version       string             `json:"version"`
	PolicyPack    string             `json:"policy_pack,omitempty"`
	Documentation Documentation      `json:"documentation"`
}

// RuleInput contains normalized plan data and execution context for rules.
type RuleInput struct {
	Plan        *model.Plan
	Graph       *graph.Graph
	Environment string
}

// Rule evaluates a normalized plan and returns zero or more findings.
type Rule interface {
	Metadata() Metadata
	Evaluate(ctx context.Context, input RuleInput) ([]model.Finding, error)
}

// StaticRule is a metadata-only placeholder useful before concrete provider rules exist.
type StaticRule struct {
	Meta Metadata
}

// Metadata returns static rule metadata.
func (r StaticRule) Metadata() Metadata {
	return r.Meta
}

// Evaluate returns no findings for metadata-only rules.
func (r StaticRule) Evaluate(context.Context, RuleInput) ([]model.Finding, error) {
	return nil, nil
}

// Registry stores rules by ID without requiring runner edits for new registrations.
type Registry struct {
	rules map[string]Rule
}

// NewRegistry returns an empty rule registry.
func NewRegistry() *Registry {
	return &Registry{rules: make(map[string]Rule)}
}

// Register adds a rule to the registry.
func (r *Registry) Register(rule Rule) error {
	if rule == nil {
		return fmt.Errorf("register rule: nil rule")
	}
	meta := rule.Metadata()
	if err := ValidateMetadata(meta); err != nil {
		return err
	}
	if _, exists := r.rules[meta.ID]; exists {
		return fmt.Errorf("register rule %s: duplicate ID", meta.ID)
	}
	r.rules[meta.ID] = rule
	return nil
}

// Get returns a rule by ID.
func (r *Registry) Get(id string) (Rule, bool) {
	rule, ok := r.rules[id]
	return rule, ok
}

// Rules returns registered rules sorted by ID.
func (r *Registry) Rules() []Rule {
	out := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule)
	}
	sort.Slice(out, func(i int, j int) bool {
		return out[i].Metadata().ID < out[j].Metadata().ID
	})
	return out
}

// ValidateMetadata checks the required metadata contract for a rule.
func ValidateMetadata(meta Metadata) error {
	if meta.ID == "" {
		return fmt.Errorf("rule metadata missing ID")
	}
	if meta.Title == "" {
		return fmt.Errorf("rule %s metadata missing title", meta.ID)
	}
	if meta.Category == "" {
		return fmt.Errorf("rule %s metadata missing category", meta.ID)
	}
	if meta.Severity == "" {
		return fmt.Errorf("rule %s metadata missing severity", meta.ID)
	}
	if meta.Confidence == "" {
		return fmt.Errorf("rule %s metadata missing confidence", meta.ID)
	}
	if meta.Status == "" {
		return fmt.Errorf("rule %s metadata missing status", meta.ID)
	}
	if meta.Version == "" {
		return fmt.Errorf("rule %s metadata missing version", meta.ID)
	}
	return nil
}

// DocumentationMarkdown renders deterministic Markdown documentation from metadata.
func DocumentationMarkdown(meta Metadata) string {
	return fmt.Sprintf(`# %s

%s

* ID: %s
* Category: %s
* Severity: %s
* Confidence: %s
* Status: %s
* Version: %s

## Remediation

%s
`, meta.Title, meta.Description, meta.ID, meta.Category, meta.Severity, meta.Confidence, meta.Status, meta.Version, markdownBullets(meta.Documentation.Remediation))
}

func markdownBullets(values []string) string {
	if len(values) == 0 {
		return "* No remediation guidance available yet."
	}
	out := ""
	for _, value := range values {
		out += "* " + value + "\n"
	}
	return out
}
