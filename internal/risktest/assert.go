package risktest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/baseline"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
)

// Failure describes one failed risk test assertion.
type Failure struct {
	TestName  string `json:"test_name"`
	Assertion string `json:"assertion"`
	Message   string `json:"message"`
}

// Assert evaluates expectations against a scan report.
func Assert(testName string, report output.Report, expect Expectations, baseDir string, updateSnapshots bool) []Failure {
	var failures []Failure
	failures = append(failures, assertDecision(testName, report, expect)...)
	failures = append(failures, assertFindings(testName, report, expect.Findings)...)
	failures = append(failures, assertSeverityCounts(testName, report, expect.SeverityCount)...)
	failures = append(failures, assertAttackPaths(testName, report, expect.AttackPaths)...)
	failures = append(failures, assertGraphPaths(testName, report, expect.GraphPaths)...)
	failures = append(failures, assertRiskMovement(testName, report.RiskMovement, expect.RiskMovement)...)
	failures = append(failures, assertWaivers(testName, report, expect.Waivers)...)
	failures = append(failures, assertSnapshot(testName, report, expect.Snapshot, baseDir, updateSnapshots)...)
	return failures
}

func assertDecision(testName string, report output.Report, expect Expectations) []Failure {
	if expect.Decision == "" || report.Decision == expect.Decision {
		return nil
	}
	return []Failure{{
		TestName:  testName,
		Assertion: "decision",
		Message:   fmt.Sprintf("expected decision %q, got %q", expect.Decision, report.Decision),
	}}
}

func assertFindings(testName string, report output.Report, expect FindingExpectations) []Failure {
	var failures []Failure
	present := findingRuleSet(report.Findings)
	for _, ruleID := range expect.Include {
		if !present[ruleID] {
			failures = append(failures, Failure{TestName: testName, Assertion: "findings.include", Message: fmt.Sprintf("expected finding %s to be present", ruleID)})
		}
	}
	for _, ruleID := range expect.Exclude {
		if present[ruleID] {
			failures = append(failures, Failure{TestName: testName, Assertion: "findings.exclude", Message: fmt.Sprintf("expected finding %s to be absent", ruleID)})
		}
	}
	counts := findingRuleCounts(report.Findings)
	for ruleID, want := range expect.Counts {
		if got := counts[ruleID]; got != want {
			failures = append(failures, Failure{TestName: testName, Assertion: "findings.counts." + ruleID, Message: fmt.Sprintf("expected %d findings for %s, got %d", want, ruleID, got)})
		}
	}
	resources := findingRuleResources(report.Findings)
	for ruleID, want := range expect.Resources {
		got := resources[ruleID]
		if !sameStringSet(got, want) {
			failures = append(failures, Failure{TestName: testName, Assertion: "findings.resources." + ruleID, Message: fmt.Sprintf("expected resources %s for %s, got %s", displayValues(sortedStrings(want)), ruleID, displayValues(got))})
		}
	}
	return failures
}

func assertSeverityCounts(testName string, report output.Report, expect map[model.Severity]int) []Failure {
	if len(expect) == 0 {
		return nil
	}
	counts := report.RiskSummary.BySeverity
	if counts == nil {
		counts = make(map[model.Severity]int)
		for _, finding := range report.Findings {
			counts[finding.Severity]++
		}
	}
	var failures []Failure
	for severity, want := range expect {
		if got := counts[severity]; got != want {
			failures = append(failures, Failure{TestName: testName, Assertion: "severity_count." + string(severity), Message: fmt.Sprintf("expected %d %s findings, got %d", want, severity, got)})
		}
	}
	return failures
}

func assertAttackPaths(testName string, report output.Report, expect PathExpectations) []Failure {
	if len(expect.Include) == 0 && len(expect.Exclude) == 0 {
		return nil
	}
	types := attackPathTypes(report.Findings)
	return assertStringSet(testName, "attack_paths", types, expect)
}

func assertGraphPaths(testName string, report output.Report, expect PathExpectations) []Failure {
	if len(expect.Include) == 0 && len(expect.Exclude) == 0 {
		return nil
	}
	paths := graphPathStrings(report.Findings)
	return assertStringSet(testName, "graph_paths", paths, expect)
}

func assertRiskMovement(testName string, movement *baseline.RiskMovement, expect RiskMovementExpect) []Failure {
	if expect == (RiskMovementExpect{}) {
		return nil
	}
	actual := baseline.RiskMovement{}
	if movement != nil {
		actual = *movement
	}
	checks := []struct {
		name string
		want *int
		got  int
	}{
		{name: "new_critical", want: expect.NewCritical, got: actual.NewCritical},
		{name: "new_high", want: expect.NewHigh, got: actual.NewHigh},
		{name: "new_medium", want: expect.NewMedium, got: actual.NewMedium},
		{name: "resolved_critical", want: expect.ResolvedCritical, got: actual.ResolvedCritical},
		{name: "resolved_high", want: expect.ResolvedHigh, got: actual.ResolvedHigh},
		{name: "existing_unchanged", want: expect.ExistingUnchanged, got: actual.ExistingUnchanged},
		{name: "existing_worsened", want: expect.ExistingWorsened, got: actual.ExistingWorsened},
		{name: "existing_improved", want: expect.ExistingImproved, got: actual.ExistingImproved},
		{name: "waived_active", want: expect.WaivedActive, got: actual.WaivedActive},
		{name: "waived_expired", want: expect.WaivedExpired, got: actual.WaivedExpired},
	}
	var failures []Failure
	for _, check := range checks {
		if check.want != nil && *check.want != check.got {
			failures = append(failures, Failure{TestName: testName, Assertion: "risk_movement." + check.name, Message: fmt.Sprintf("expected %d, got %d", *check.want, check.got)})
		}
	}
	return failures
}

func assertWaivers(testName string, report output.Report, expect WaiverExpectations) []Failure {
	if len(expect.Applied) == 0 && len(expect.NotApplied) == 0 {
		return nil
	}
	var failures []Failure
	for _, ruleID := range expect.Applied {
		if !waiverApplied(report.Findings, ruleID) {
			failures = append(failures, Failure{TestName: testName, Assertion: "waivers.applied", Message: fmt.Sprintf("expected waiver to apply to %s", ruleID)})
		}
	}
	for _, ruleID := range expect.NotApplied {
		if waiverApplied(report.Findings, ruleID) {
			failures = append(failures, Failure{TestName: testName, Assertion: "waivers.not_applied", Message: fmt.Sprintf("expected waiver not to apply to %s", ruleID)})
		}
	}
	return failures
}

func assertSnapshot(testName string, report output.Report, snapshot string, baseDir string, update bool) []Failure {
	if snapshot == "" {
		return nil
	}
	path := resolveRelative(baseDir, snapshot)
	body, err := stableSnapshot(report)
	if err != nil {
		return []Failure{{TestName: testName, Assertion: "snapshot", Message: err.Error()}}
	}
	if update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return []Failure{{TestName: testName, Assertion: "snapshot", Message: fmt.Sprintf("create snapshot directory: %v", err)}}
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return []Failure{{TestName: testName, Assertion: "snapshot", Message: fmt.Sprintf("write snapshot %s: %v", path, err)}}
		}
		return nil
	}
	want, err := os.ReadFile(path)
	if err != nil {
		return []Failure{{TestName: testName, Assertion: "snapshot", Message: fmt.Sprintf("read snapshot %s: %v", path, err)}}
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(body)) {
		return []Failure{{TestName: testName, Assertion: "snapshot", Message: fmt.Sprintf("snapshot %s does not match current report", path)}}
	}
	return nil
}

func assertStringSet(testName string, assertion string, values []string, expect PathExpectations) []Failure {
	var failures []Failure
	for _, want := range expect.Include {
		if !containsPathValue(values, want) {
			failures = append(failures, Failure{TestName: testName, Assertion: assertion + ".include", Message: fmt.Sprintf("expected %q in %s; got %s", want, assertion, displayValues(values))})
		}
	}
	for _, want := range expect.Exclude {
		if containsPathValue(values, want) {
			failures = append(failures, Failure{TestName: testName, Assertion: assertion + ".exclude", Message: fmt.Sprintf("expected %q to be absent from %s", want, assertion)})
		}
	}
	return failures
}

func displayValues(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func findingRuleSet(findings []model.Finding) map[string]bool {
	out := make(map[string]bool, len(findings))
	for _, finding := range findings {
		out[finding.RuleID] = true
	}
	return out
}

func findingRuleCounts(findings []model.Finding) map[string]int {
	out := make(map[string]int)
	for _, finding := range findings {
		out[finding.RuleID]++
	}
	return out
}

func findingRuleResources(findings []model.Finding) map[string][]string {
	sets := make(map[string]map[string]bool)
	for _, finding := range findings {
		if finding.RuleID == "" || finding.ResourceAddress == "" {
			continue
		}
		set := sets[finding.RuleID]
		if set == nil {
			set = make(map[string]bool)
			sets[finding.RuleID] = set
		}
		set[finding.ResourceAddress] = true
	}
	out := make(map[string][]string, len(sets))
	for ruleID, set := range sets {
		out[ruleID] = sortedKeys(set)
	}
	return out
}

func attackPathTypes(findings []model.Finding) []string {
	seen := make(map[string]bool)
	for _, finding := range findings {
		for _, evidence := range finding.Evidence {
			if evidence.Path == "attack_path.type" {
				if value, ok := evidence.Value.(string); ok && value != "" {
					seen[value] = true
				}
			}
		}
	}
	return sortedKeys(seen)
}

func graphPathStrings(findings []model.Finding) []string {
	seen := make(map[string]bool)
	for _, finding := range findings {
		for _, evidence := range finding.Evidence {
			if evidence.Path != "graph.path" && !strings.Contains(evidence.Type, "graph_path") {
				continue
			}
			for _, value := range evidenceValues(evidence.Value) {
				seen[value] = true
			}
		}
	}
	return sortedKeys(seen)
}

func evidenceValues(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return []string{strings.Join(typed, " -> "), strings.Join(typed, " ")}
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, fmt.Sprint(item))
		}
		return []string{strings.Join(parts, " -> "), strings.Join(parts, " ")}
	default:
		return []string{fmt.Sprint(value)}
	}
}

func waiverApplied(findings []model.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID != ruleID {
			continue
		}
		for _, suppression := range finding.Suppressions {
			if suppression.Kind == "waiver" && suppression.Active {
				return true
			}
		}
	}
	return false
}

func stableSnapshot(report output.Report) ([]byte, error) {
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	return append(body, '\n'), nil
}

func containsPathValue(values []string, want string) bool {
	for _, value := range values {
		if value == want || strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func sameStringSet(a []string, b []string) bool {
	a = sortedStrings(a)
	b = sortedStrings(b)
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
