// Package adapters imports external scanner findings into ChangeGate's model.
package adapters

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	Imported     int            `json:"imported"`
	Deduplicated int            `json:"deduplicated"`
	Correlated   int            `json:"correlated"`
	Downgraded   int            `json:"downgraded"`
	Upgraded     int            `json:"upgraded"`
	BySource     map[Source]int `json:"by_source,omitempty"`
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
	nativeKeys := make(map[string]bool, len(native))
	for _, finding := range native {
		nativeKeys[dedupAgainstNativeKey(finding)] = true
		nativeKeys[finding.Fingerprint] = true
	}
	for _, finding := range imported {
		source := sourceFromFinding(finding)
		summary.BySource[source]++
		if nativeKeys[finding.Fingerprint] || nativeKeys[dedupAgainstNativeKey(finding)] {
			summary.Deduplicated++
			continue
		}
		enriched := correlateImported(finding, resourceGraph, &summary)
		merged = append(merged, enriched)
	}
	model.SortFindings(merged)
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
	node := resourceGraph.Nodes[graph.ResourceID(f.ResourceAddress)]
	if node == nil {
		f = downgrade(f, "imported finding did not correlate to a changed graph resource")
		summary.Downgraded++
		return f
	}
	summary.Correlated++
	f.Evidence = append(f.Evidence, model.Evidence{
		Type:     "external_correlation",
		Resource: f.ResourceAddress,
		Path:     "graph.node",
		Value:    node.Type,
		Message:  "imported finding correlated to changed graph resource",
	})
	if resourceGraph.IsInternetExposed(graph.ResourceID(f.ResourceAddress)) || resourceGraph.HasSensitiveDataAccess(graph.ResourceID(f.ResourceAddress)) {
		f = upgrade(f, "graph context increases materiality of imported finding")
		summary.Upgraded++
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
	return f
}

func dedupAgainstNativeKey(f model.Finding) string {
	return f.ResourceAddress + "|" + string(f.Category)
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
