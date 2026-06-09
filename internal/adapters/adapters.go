// Package adapters imports external scanner findings into ChangeGate's model.
package adapters

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/graph"
	"github.com/Gabriel0110/changegate/internal/model"
)

// Source identifies an external scanner adapter.
type Source string

const (
	SourceSARIF   Source = "sarif"
	SourceGeneric Source = "generic-json"
	SourceCheckov Source = "checkov"
	SourceTrivy   Source = "trivy"
	SourceKICS    Source = "kics"
	SourceGrype   Source = "grype"
)

// ImportRequest identifies one external scanner output.
type ImportRequest struct {
	Source Source `json:"source"`
	Path   string `json:"path"`
}

// Summary describes import and merge results.
type Summary struct {
	Imported           int            `json:"imported"`
	Retained           int            `json:"retained"`
	Deduplicated       int            `json:"deduplicated"`
	SupersededByNative int            `json:"superseded_by_native"`
	Correlated         int            `json:"correlated"`
	Downgraded         int            `json:"downgraded"`
	Upgraded           int            `json:"upgraded"`
	BySource           map[Source]int `json:"by_source,omitempty"`
	Insights           []Insight      `json:"insights,omitempty"`
}

// Insight explains how ChangeGate handled an imported scanner finding.
type Insight struct {
	Action          string `json:"action"`
	Source          Source `json:"source"`
	RuleID          string `json:"rule_id,omitempty"`
	Resource        string `json:"resource,omitempty"`
	NativeRuleID    string `json:"native_rule_id,omitempty"`
	NativeFindingID string `json:"native_finding_id,omitempty"`
	Reason          string `json:"reason"`
}

// Result contains imported findings plus non-fatal diagnostics.
type Result struct {
	Findings    []model.Finding    `json:"findings"`
	Summary     Summary            `json:"summary"`
	Diagnostics []model.Diagnostic `json:"diagnostics,omitempty"`
}

// ImportFile imports scanner findings from a file path.
func ImportFile(request ImportRequest) Result {
	file, err := os.Open(request.Path)
	if err != nil {
		return Result{Diagnostics: []model.Diagnostic{warning("ADAPTER_IMPORT_FAILED", fmt.Sprintf("%s: %v", request.Path, err))}}
	}
	defer closeFile(file)
	return Import(request.Source, file)
}

// Import imports scanner findings from a reader.
func Import(source Source, r io.Reader) Result {
	body, err := io.ReadAll(r)
	if err != nil {
		return Result{Diagnostics: []model.Diagnostic{warning("ADAPTER_IMPORT_FAILED", err.Error())}}
	}
	var findings []model.Finding
	switch source {
	case SourceSARIF:
		findings, err = parseSARIF(body)
	case SourceGeneric:
		findings, err = parseGeneric(body)
	case SourceCheckov:
		findings, err = parseCheckov(body)
	case SourceTrivy:
		findings, err = parseTrivy(body)
	case SourceKICS:
		findings, err = parseKICS(body)
	case SourceGrype:
		findings, err = parseGrype(body)
	default:
		err = fmt.Errorf("unsupported adapter source %q", source)
	}
	if err != nil {
		return Result{Diagnostics: []model.Diagnostic{warning("ADAPTER_IMPORT_FAILED", err.Error())}}
	}
	for index := range findings {
		findings[index] = normalizeImported(findings[index], source)
	}
	model.SortFindings(findings)
	return Result{
		Findings: findings,
		Summary: Summary{
			Imported: len(findings),
			BySource: map[Source]int{
				source: len(findings),
			},
		},
	}
}

// Merge combines native and imported findings and deduplicates lower-fidelity external duplicates.
func Merge(native []model.Finding, imported []model.Finding, resourceGraph *graph.Graph) ([]model.Finding, Summary) {
	summary := Summary{Imported: len(imported), BySource: make(map[Source]int)}
	merged := append([]model.Finding{}, native...)
	nativeKeys := make(map[string]model.Finding, len(native)*2)
	for _, finding := range native {
		nativeKeys[dedupAgainstNativeKey(finding)] = finding
		nativeKeys[finding.Fingerprint] = finding
	}
	importedFingerprints := make(map[string]model.Finding, len(imported))
	for _, finding := range imported {
		source := sourceFromFinding(finding)
		summary.BySource[source]++
		if previous, ok := importedFingerprints[finding.Fingerprint]; ok {
			summary.Deduplicated++
			summary.addInsight(Insight{
				Action:   "repeated_duplicate",
				Source:   source,
				RuleID:   finding.RuleID,
				Resource: finding.ResourceAddress,
				Reason:   fmt.Sprintf("duplicate imported finding already retained as %s", previous.RuleID),
			})
			continue
		}
		dedupFinding := canonicalFindingForDedup(finding, resourceGraph)
		if nativeFinding, ok := nativeKeys[finding.Fingerprint]; ok {
			summary.recordSuperseded(source, finding, nativeFinding, "native ChangeGate finding has the same fingerprint")
			continue
		}
		if nativeFinding, ok := nativeKeys[dedupAgainstNativeKey(dedupFinding)]; ok {
			finding.ResourceAddress = dedupFinding.ResourceAddress
			summary.recordSuperseded(source, finding, nativeFinding, "native ChangeGate finding covers the same resource and risk category with plan graph evidence")
			continue
		}
		importedFingerprints[finding.Fingerprint] = finding
		enriched := correlateImported(finding, resourceGraph, &summary)
		merged = append(merged, enriched)
		summary.Retained++
	}
	model.SortFindings(merged)
	summary.sortInsights()
	return merged, summary
}

func normalizeImported(f model.Finding, source Source) model.Finding {
	if f.Provider == "" {
		f.Provider = "external"
	}
	if f.Category == "" {
		f.Category = model.RiskCategoryUnknown
	}
	if f.Severity == "" {
		f.Severity = model.SeverityMedium
	}
	if f.Confidence == "" {
		f.Confidence = model.ConfidenceMedium
	}
	if f.RuleID == "" {
		f.RuleID = strings.ToUpper(string(source)) + "_FINDING"
	}
	if !strings.HasPrefix(f.RuleID, "EXT_") {
		f.RuleID = "EXT_" + strings.ToUpper(strings.ReplaceAll(string(source), "-", "_")) + "_" + sanitizeID(f.RuleID)
	}
	if f.PolicyPack == "" {
		f.PolicyPack = "external:" + string(source)
	}
	if f.PolicyPackVersion == "" {
		f.PolicyPackVersion = "import"
	}
	if f.Title == "" {
		f.Title = f.RuleID
	}
	if f.ResourceAddress == "" {
		f.ResourceAddress = "external:" + string(source)
	}
	f.Evidence = append([]model.Evidence{{
		Type:     "external_scanner",
		Resource: f.ResourceAddress,
		Path:     string(source),
		Value:    f.RuleID,
		Message:  "finding imported from " + string(source),
	}}, f.Evidence...)
	return model.NormalizeFinding(f)
}

func correlateImported(f model.Finding, resourceGraph *graph.Graph, summary *Summary) model.Finding {
	if resourceGraph == nil {
		return f
	}
	nodeID, node, reason := resolveImportedNode(f, resourceGraph)
	source := sourceFromFinding(f)
	if node == nil {
		reason := "imported finding did not correlate to a changed graph resource"
		f = downgrade(f, reason)
		summary.Downgraded++
		summary.addInsight(Insight{
			Action:   "downgraded",
			Source:   source,
			RuleID:   f.RuleID,
			Resource: f.ResourceAddress,
			Reason:   reason,
		})
		return f
	}
	summary.Correlated++
	originalResource := f.ResourceAddress
	f.ResourceAddress = string(nodeID)
	f.Evidence = append(f.Evidence, model.Evidence{
		Type:     "external_correlation",
		Resource: f.ResourceAddress,
		Path:     reason,
		Value:    node.Type,
		Message:  "imported finding correlated to changed graph resource",
	})
	if originalResource != f.ResourceAddress {
		f.Evidence = append(f.Evidence, model.Evidence{
			Type:     "external_correlation",
			Resource: f.ResourceAddress,
			Path:     "canonical_resource",
			Value:    originalResource,
			Message:  "scanner resource identifier mapped to canonical graph resource",
		})
	}
	summary.addInsight(Insight{
		Action:   "correlated",
		Source:   source,
		RuleID:   f.RuleID,
		Resource: f.ResourceAddress,
		Reason:   "scanner finding matched a changed graph resource through " + reason,
	})
	if resourceGraph.IsInternetExposed(nodeID) || resourceGraph.HasSensitiveDataAccess(nodeID) {
		reason := "graph context increases materiality of imported finding"
		f = upgrade(f, reason)
		summary.Upgraded++
		summary.addInsight(Insight{
			Action:   "upgraded",
			Source:   source,
			RuleID:   f.RuleID,
			Resource: f.ResourceAddress,
			Reason:   reason,
		})
	}
	return model.NormalizeFinding(f)
}

func downgrade(f model.Finding, reason string) model.Finding {
	if f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical {
		f.Severity = model.SeverityMedium
	}
	if f.Confidence == model.ConfidenceHigh {
		f.Confidence = model.ConfidenceMedium
	}
	f.DecisionReasonCodes = append(f.DecisionReasonCodes, model.ReasonDowngraded)
	f.DecisionReasons = append(f.DecisionReasons, model.DecisionReason{FindingID: f.ID, Resource: f.ResourceAddress, Code: model.ReasonDowngraded, Reason: reason})
	f.Evidence = append(f.Evidence, model.Evidence{
		Type:     "external_decision",
		Resource: f.ResourceAddress,
		Path:     "downgraded",
		Value:    reason,
		Message:  "external finding downgraded because graph evidence was incomplete",
	})
	return f
}

func upgrade(f model.Finding, reason string) model.Finding {
	if f.Severity == model.SeverityMedium || f.Severity == model.SeverityHigh {
		f.Severity = model.SeverityHigh
	}
	if f.Confidence == model.ConfidenceMedium {
		f.Confidence = model.ConfidenceHigh
	}
	f.DecisionReasonCodes = append(f.DecisionReasonCodes, model.ReasonUpgraded)
	f.DecisionReasons = append(f.DecisionReasons, model.DecisionReason{FindingID: f.ID, Resource: f.ResourceAddress, Code: model.ReasonUpgraded, Reason: reason})
	f.Evidence = append(f.Evidence, model.Evidence{
		Type:     "external_decision",
		Resource: f.ResourceAddress,
		Path:     "upgraded",
		Value:    reason,
		Message:  "external finding upgraded because graph evidence increases materiality",
	})
	return f
}

func dedupAgainstNativeKey(f model.Finding) string {
	return f.ResourceAddress + "|" + string(f.Category)
}

func canonicalFindingForDedup(f model.Finding, resourceGraph *graph.Graph) model.Finding {
	nodeID, _, _ := resolveImportedNode(f, resourceGraph)
	if nodeID == "" {
		return f
	}
	f.ResourceAddress = string(nodeID)
	return f
}

func resolveImportedNode(f model.Finding, resourceGraph *graph.Graph) (graph.ResourceID, *graph.Node, string) {
	if resourceGraph == nil {
		return "", nil, ""
	}
	index := graphAliasIndex(resourceGraph)
	for _, alias := range findingAliases(f) {
		if id, ok := index[normalizeAlias(alias)]; ok {
			return id, resourceGraph.Nodes[id], "graph.alias"
		}
	}
	return "", nil, ""
}

func graphAliasIndex(resourceGraph *graph.Graph) map[string]graph.ResourceID {
	index := make(map[string]graph.ResourceID, len(resourceGraph.Nodes)*6)
	ids := make([]string, 0, len(resourceGraph.Nodes))
	for id := range resourceGraph.Nodes {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, rawID := range ids {
		id := graph.ResourceID(rawID)
		node := resourceGraph.Nodes[id]
		for _, alias := range nodeAliases(node) {
			normalized := normalizeAlias(alias)
			if normalized == "" {
				continue
			}
			if _, exists := index[normalized]; !exists {
				index[normalized] = id
			}
		}
	}
	return index
}

func nodeAliases(node *graph.Node) []string {
	if node == nil {
		return nil
	}
	aliases := []string{
		string(node.ID),
		node.Address,
		node.Name,
	}
	for _, key := range []string{"arn", "id", "name", "bucket", "bucket_name", "identifier", "cluster_identifier", "function_name", "role", "role_arn"} {
		aliases = append(aliases, anyString(node.Values[key])...)
	}
	for _, value := range node.Tags {
		aliases = append(aliases, value)
	}
	return aliases
}

func findingAliases(f model.Finding) []string {
	aliases := []string{f.ResourceAddress}
	for _, evidence := range f.Evidence {
		aliases = append(aliases, evidence.Resource, evidence.Path)
		aliases = append(aliases, anyString(evidence.Value)...)
	}
	return aliases
}

func anyString(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return []string{typed}
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, anyString(item)...)
		}
		return out
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func normalizeAlias(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (s *Summary) recordSuperseded(source Source, imported model.Finding, native model.Finding, reason string) {
	s.Deduplicated++
	s.SupersededByNative++
	s.addInsight(Insight{
		Action:          "superseded_by_native",
		Source:          source,
		RuleID:          imported.RuleID,
		Resource:        imported.ResourceAddress,
		NativeRuleID:    native.RuleID,
		NativeFindingID: native.ID,
		Reason:          reason,
	})
}

func (s *Summary) addInsight(insight Insight) {
	if insight.Reason == "" {
		return
	}
	s.Insights = append(s.Insights, insight)
}

func (s *Summary) sortInsights() {
	sort.SliceStable(s.Insights, func(i int, j int) bool {
		left := s.Insights[i]
		right := s.Insights[j]
		for _, cmp := range []int{
			strings.Compare(left.Action, right.Action),
			strings.Compare(string(left.Source), string(right.Source)),
			strings.Compare(left.Resource, right.Resource),
			strings.Compare(left.RuleID, right.RuleID),
			strings.Compare(left.Reason, right.Reason),
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

func sourceFromFinding(f model.Finding) Source {
	if strings.HasPrefix(f.PolicyPack, "external:") {
		return Source(strings.TrimPrefix(f.PolicyPack, "external:"))
	}
	return SourceGeneric
}

func sanitizeID(value string) string {
	value = strings.ToUpper(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('_')
	}
	return strings.Trim(b.String(), "_")
}

func severity(value string) model.Severity {
	switch strings.ToUpper(value) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH", "ERROR":
		return model.SeverityHigh
	case "MEDIUM", "WARNING":
		return model.SeverityMedium
	case "LOW", "NOTE":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func confidence(value string) model.Confidence {
	switch strings.ToUpper(value) {
	case "HIGH":
		return model.ConfidenceHigh
	case "LOW":
		return model.ConfidenceLow
	case "UNKNOWN":
		return model.ConfidenceUnknown
	default:
		return model.ConfidenceMedium
	}
}

func category(value string) model.RiskCategory {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "public"), strings.Contains(lower, "network"), strings.Contains(lower, "security group"):
		return model.RiskCategoryPublicExposure
	case strings.Contains(lower, "iam"), strings.Contains(lower, "privilege"):
		return model.RiskCategoryPrivilegeEscalation
	case strings.Contains(lower, "secret"), strings.Contains(lower, "sensitive"), strings.Contains(lower, "encryption"):
		return model.RiskCategorySensitiveData
	case strings.Contains(lower, "availability"), strings.Contains(lower, "delete"):
		return model.RiskCategoryAvailability
	default:
		return model.RiskCategoryUnknown
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

func warning(code string, message string) model.Diagnostic {
	return model.Diagnostic{Severity: model.DiagnosticWarning, Code: code, Message: message}
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return ""
	default:
		bytes, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(bytes)
	}
}
