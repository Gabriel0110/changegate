// Package risktest parses and evaluates ChangeGate risk test manifests.
package risktest

import (
	"fmt"
	"io"
	"os"

	"github.com/Gabriel0110/changegate/internal/model"
	"gopkg.in/yaml.v3"
)

const (
	// ManifestVersion is the current risk test manifest schema version.
	ManifestVersion = 1
)

// Manifest describes deterministic ChangeGate regression tests for Terraform modules.
type Manifest struct {
	Version int        `json:"version" yaml:"version"`
	Tests   []TestCase `json:"tests" yaml:"tests"`
}

// TestCase is one risk test entry from a manifest.
type TestCase struct {
	Name        string       `json:"name" yaml:"name"`
	Plan        string       `json:"plan" yaml:"plan"`
	Config      string       `json:"config,omitempty" yaml:"config,omitempty"`
	Baseline    string       `json:"baseline,omitempty" yaml:"baseline,omitempty"`
	NewOnly     bool         `json:"new_only,omitempty" yaml:"new_only,omitempty"`
	ContextFile string       `json:"context_file,omitempty" yaml:"context_file,omitempty"`
	Expect      Expectations `json:"expect" yaml:"expect"`
}

// Expectations captures supported assertions for a test case.
type Expectations struct {
	Decision      model.Decision         `json:"decision,omitempty" yaml:"decision,omitempty"`
	Findings      FindingExpectations    `json:"findings,omitempty" yaml:"findings,omitempty"`
	SeverityCount map[model.Severity]int `json:"severity_count,omitempty" yaml:"severity_count,omitempty"`
	AttackPaths   PathExpectations       `json:"attack_paths,omitempty" yaml:"attack_paths,omitempty"`
	GraphPaths    PathExpectations       `json:"graph_paths,omitempty" yaml:"graph_paths,omitempty"`
	RiskMovement  RiskMovementExpect     `json:"risk_movement,omitempty" yaml:"risk_movement,omitempty"`
	Waivers       WaiverExpectations     `json:"waivers,omitempty" yaml:"waivers,omitempty"`
	Snapshot      string                 `json:"snapshot,omitempty" yaml:"snapshot,omitempty"`
}

// FindingExpectations asserts rule IDs that must or must not be present.
type FindingExpectations struct {
	Include []string `json:"include,omitempty" yaml:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}

// PathExpectations asserts attack path types or graph path fragments.
type PathExpectations struct {
	Include []string `json:"include,omitempty" yaml:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}

// RiskMovementExpect asserts selected baseline movement counters.
type RiskMovementExpect struct {
	NewCritical       *int `json:"new_critical,omitempty" yaml:"new_critical,omitempty"`
	NewHigh           *int `json:"new_high,omitempty" yaml:"new_high,omitempty"`
	NewMedium         *int `json:"new_medium,omitempty" yaml:"new_medium,omitempty"`
	ResolvedCritical  *int `json:"resolved_critical,omitempty" yaml:"resolved_critical,omitempty"`
	ResolvedHigh      *int `json:"resolved_high,omitempty" yaml:"resolved_high,omitempty"`
	ExistingUnchanged *int `json:"existing_unchanged,omitempty" yaml:"existing_unchanged,omitempty"`
	ExistingWorsened  *int `json:"existing_worsened,omitempty" yaml:"existing_worsened,omitempty"`
	ExistingImproved  *int `json:"existing_improved,omitempty" yaml:"existing_improved,omitempty"`
	WaivedActive      *int `json:"waived_active,omitempty" yaml:"waived_active,omitempty"`
	WaivedExpired     *int `json:"waived_expired,omitempty" yaml:"waived_expired,omitempty"`
}

// WaiverExpectations asserts waiver suppression state by rule ID.
type WaiverExpectations struct {
	Applied    []string `json:"applied,omitempty" yaml:"applied,omitempty"`
	NotApplied []string `json:"not_applied,omitempty" yaml:"not_applied,omitempty"`
}

// LoadFile loads a risk test manifest from disk.
func LoadFile(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open risk test manifest %q: %w", path, err)
	}
	defer closeFile(file)
	manifest, err := Load(file)
	if err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", path, err)
	}
	return manifest, nil
}

// Load reads a strict risk test manifest.
func Load(r io.Reader) (Manifest, error) {
	var manifest Manifest
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode risk test manifest: %w", err)
	}
	if err := Validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate validates manifest-level invariants.
func Validate(manifest Manifest) error {
	if manifest.Version != ManifestVersion {
		return fmt.Errorf("version must be %d", ManifestVersion)
	}
	if len(manifest.Tests) == 0 {
		return fmt.Errorf("tests must contain at least one test")
	}
	seen := make(map[string]bool, len(manifest.Tests))
	for index, test := range manifest.Tests {
		if test.Name == "" {
			return fmt.Errorf("tests[%d].name is required", index)
		}
		if seen[test.Name] {
			return fmt.Errorf("tests[%d].name %q is duplicated", index, test.Name)
		}
		seen[test.Name] = true
		if test.Plan == "" {
			return fmt.Errorf("tests[%d].plan is required", index)
		}
	}
	return nil
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}
