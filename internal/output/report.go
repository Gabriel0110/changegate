// Package output renders ChangeGate scan reports for humans and CI systems.
package output

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/baseline"
	"github.com/Gabriel0110/changegate/internal/model"
)

const (
	// ReportSchemaVersion is the stable external scan report schema version.
	ReportSchemaVersion = "changegate.scan.report.v1"
	sarifSchema         = "https://json.schemastore.org/sarif-2.1.0.json"
)

// PlanSummary captures plan metadata needed by output integrations.
type PlanSummary struct {
	Path          string     `json:"path"`
	Tool          model.Tool `json:"tool"`
	FormatVersion string     `json:"format_version"`
	Resources     int        `json:"resources"`
	Changes       int        `json:"changes"`
}

// GraphSummary captures graph size without exposing node values.
type GraphSummary struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
}

// ImportSummary captures external scanner import and correlation counts.
type ImportSummary struct {
	Imported           int             `json:"imported"`
	Retained           int             `json:"retained,omitempty"`
	Deduplicated       int             `json:"deduplicated"`
	SupersededByNative int             `json:"superseded_by_native,omitempty"`
	Correlated         int             `json:"correlated"`
	Downgraded         int             `json:"downgraded"`
	Upgraded           int             `json:"upgraded"`
	BySource           map[string]int  `json:"by_source,omitempty"`
	Insights           []ImportInsight `json:"insights,omitempty"`
}

// ImportInsight explains how an imported scanner finding affected the report.
type ImportInsight struct {
	Action          string `json:"action"`
	Source          string `json:"source"`
	RuleID          string `json:"rule_id,omitempty"`
	Resource        string `json:"resource,omitempty"`
	NativeRuleID    string `json:"native_rule_id,omitempty"`
	NativeFindingID string `json:"native_finding_id,omitempty"`
	Reason          string `json:"reason"`
}

// RunMetadata captures deterministic machine-readable run evidence.
type RunMetadata struct {
	SchemaVersion         string            `json:"schema_version"`
	CLIVersion            string            `json:"cli_version"`
	CLICommit             string            `json:"cli_commit,omitempty"`
	CLIDate               string            `json:"cli_date,omitempty"`
	PlanHash              string            `json:"plan_hash,omitempty"`
	ConfigHash            string            `json:"config_hash,omitempty"`
	PolicyDigest          string            `json:"policy_digest,omitempty"`
	PlanDigest            string            `json:"plan_digest,omitempty"`
	PolicyPackVersions    map[string]string `json:"policy_pack_versions,omitempty"`
	CloudContextTimestamp string            `json:"cloud_context_timestamp,omitempty"`
	Redaction             RedactionReport   `json:"redaction_report"`
}

// RedactionReport records the redaction posture of evidence included in reports.
type RedactionReport struct {
	Status            string `json:"status"`
	SensitiveEvidence int    `json:"sensitive_evidence"`
	RedactedValues    int    `json:"redacted_values"`
}

// AuditReports carries optional evidence artifacts used by audit bundles.
type AuditReports struct {
	PolicyYAML            string `json:"-"`
	Waivers               any    `json:"waivers,omitempty"`
	Baseline              any    `json:"baseline,omitempty"`
	Impact                any    `json:"-"`
	ImpactMarkdown        string `json:"-"`
	Graph                 any    `json:"-"`
	AttackPaths           any    `json:"-"`
	CloudContextSummary   any    `json:"-"`
	ReviewCommentMarkdown string `json:"-"`
	RiskTests             any    `json:"-"`
	HCPRunTask            any    `json:"-"`
}

// ComplianceMapping describes non-enforcing rule metadata for frameworks.
type ComplianceMapping struct {
	Frameworks map[string][]string `json:"frameworks"`
}

// ComplianceFinding maps a real ChangeGate finding to framework metadata.
type ComplianceFinding struct {
	FindingID  string              `json:"finding_id"`
	RuleID     string              `json:"rule_id"`
	Resource   string              `json:"resource"`
	Frameworks map[string][]string `json:"frameworks"`
	ActualRisk bool                `json:"actual_risk"`
	Suppressed bool                `json:"suppressed"`
}

// ComplianceReport separates actual risks from checklist-oriented metadata.
type ComplianceReport struct {
	Mappings map[string]ComplianceMapping `json:"mappings"`
	Findings []ComplianceFinding          `json:"findings"`
	Summary  map[string]int               `json:"summary"`
}

// RuleSummary captures rule metadata needed by SARIF and other integrations.
type RuleSummary struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Category    model.RiskCategory `json:"category"`
	Severity    model.Severity     `json:"severity"`
	Confidence  model.Confidence   `json:"confidence"`
	Help        string             `json:"help,omitempty"`
	Remediation []string           `json:"remediation,omitempty"`
	References  []string           `json:"references,omitempty"`
}

// Report is the canonical serialized output for scan results.
type Report struct {
	SchemaVersion string                     `json:"schema_version"`
	Decision      model.Decision             `json:"decision"`
	Plan          PlanSummary                `json:"plan"`
	Graph         GraphSummary               `json:"graph"`
	Imports       *ImportSummary             `json:"imports,omitempty"`
	RiskSummary   model.RiskSummary          `json:"risk_summary"`
	RiskMovement  *baseline.RiskMovement     `json:"risk_movement,omitempty"`
	RiskClusters  []RiskCluster              `json:"risk_clusters,omitempty"`
	ReasonCodes   []model.DecisionReasonCode `json:"reason_codes"`
	Reasons       []model.DecisionReason     `json:"reasons"`
	Findings      []model.Finding            `json:"findings"`
	Diagnostics   []model.Diagnostic         `json:"diagnostics,omitempty"`
	Rules         map[string]RuleSummary     `json:"rules,omitempty"`
	Run           *RunMetadata               `json:"run,omitempty"`
	Audit         *AuditReports              `json:"audit,omitempty"`
	Compliance    *ComplianceReport          `json:"compliance,omitempty"`
	Message       string                     `json:"message,omitempty"`
}

// NewReport builds a deterministic scan report.
func NewReport(planPath string, plan *model.Plan, graphNodes int, graphEdges int, outcome model.PolicyOutcome, rules map[string]RuleSummary, message string) Report {
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		Decision:      outcome.Decision,
		Plan: PlanSummary{
			Path:          displayPlanPath(planPath),
			Tool:          plan.Tool,
			FormatVersion: plan.FormatVersion,
			Resources:     plan.Statistics.ResourceCount,
			Changes:       plan.Statistics.ChangeCount,
		},
		Graph: GraphSummary{
			Nodes: graphNodes,
			Edges: graphEdges,
		},
		RiskSummary:  outcome.Summary,
		ReasonCodes:  outcome.ReasonCodes,
		Reasons:      outcome.Reasons,
		Findings:     outcome.Findings,
		RiskClusters: BuildRiskClusters(outcome.Findings),
		Diagnostics:  plan.Diagnostics,
		Rules:        rules,
		Message:      message,
	}
	return report
}

// Render renders a report in a supported output format.
func Render(report Report, format string) ([]byte, string, error) {
	switch format {
	case "", "table":
		return []byte(RenderConsole(report)), "text/plain", nil
	case "json":
		body, err := RenderJSON(report)
		return body, "application/json", err
	case "sarif":
		body, err := RenderSARIF(report)
		return body, "application/sarif+json", err
	case "junit":
		body, err := RenderJUnit(report)
		return body, "application/xml", err
	case "markdown":
		return []byte(RenderMarkdown(report)), "text/markdown", nil
	case "pr-comment":
		return []byte(RenderPRComment(report)), "text/markdown", nil
	case "github-step-summary":
		return []byte(RenderGitHubStepSummary(report)), "text/markdown", nil
	case "github-annotations":
		return []byte(RenderGitHubAnnotations(report)), "text/plain", nil
	case "gitlab-code-quality":
		body, err := RenderGitLabCodeQuality(report)
		return body, "application/json", err
	case "audit-bundle":
		body, err := RenderAuditBundle(report)
		return body, "application/zip", err
	default:
		return nil, "", fmt.Errorf("unsupported scan output format %q", format)
	}
}

// RenderConsole renders local terminal output.
func RenderConsole(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Decision: %s\n\n", strings.ToUpper(string(report.Decision)))
	fmt.Fprintf(&b, "Plan: %s\n", report.Plan.Path)
	fmt.Fprintf(&b, "Tool: %s\n", report.Plan.Tool)
	fmt.Fprintf(&b, "Format: %s\n", report.Plan.FormatVersion)
	fmt.Fprintf(&b, "Resources: %d\n", report.Plan.Resources)
	fmt.Fprintf(&b, "Changes: %d\n", report.Plan.Changes)
	fmt.Fprintf(&b, "Graph: %d nodes, %d edges\n", report.Graph.Nodes, report.Graph.Edges)
	fmt.Fprintf(&b, "Findings: %d\n", report.RiskSummary.Total)
	clusters := clustersForReport(report)
	fmt.Fprintf(&b, "Risk clusters: %d\n", len(clusters))
	if report.Imports != nil {
		native := report.RiskSummary.Total - retainedImportCount(report.Imports)
		if native < 0 {
			native = 0
		}
		fmt.Fprintf(&b, "Native findings: %d\n", native)
		fmt.Fprintf(&b, "Imported findings: %d\n", report.Imports.Imported)
		fmt.Fprintf(&b, "Imported retained: %d\n", retainedImportCount(report.Imports))
		fmt.Fprintf(&b, "Deduplicated: %d\n", report.Imports.Deduplicated)
		if report.Imports.SupersededByNative > 0 {
			fmt.Fprintf(&b, "Superseded by native findings: %d\n", report.Imports.SupersededByNative)
		}
		fmt.Fprintf(&b, "Imported correlated: %d\n", report.Imports.Correlated)
		fmt.Fprintf(&b, "Imported downgraded: %d\n", report.Imports.Downgraded)
		fmt.Fprintf(&b, "Imported upgraded: %d\n", report.Imports.Upgraded)
	}
	fmt.Fprintf(&b, "Blocking: %d\n", report.RiskSummary.Blocking)
	fmt.Fprintf(&b, "Warnings: %d\n", report.RiskSummary.Warnings)
	fmt.Fprintf(&b, "Suppressed or downgraded: %d\n", report.RiskSummary.Suppressed+report.RiskSummary.Downgraded)
	for _, reason := range collapsedDecisionReasons(report) {
		if reason.Resource == "" {
			fmt.Fprintf(&b, "Reason: %s\n", reason.Reason)
			continue
		}
		fmt.Fprintf(&b, "Reason: %s %s - %s\n", reason.Code, reason.Resource, reason.Reason)
	}
	for _, diagnostic := range report.Diagnostics {
		fmt.Fprintf(&b, "Warning: %s\n", diagnostic.Message)
	}
	if len(clusters) > 0 {
		b.WriteString("\nRisk clusters:\n")
		for i, cluster := range clusters {
			if i >= 5 {
				fmt.Fprintf(&b, "... %d more risk clusters\n", len(clusters)-i)
				break
			}
			fmt.Fprintf(&b, "- [%s/%s] %s (%d resources, %d findings)\n", cluster.Severity, cluster.Confidence, cluster.Title, len(cluster.AffectedResources), len(cluster.SupportingFindings))
		}
	}
	return b.String()
}

// RenderJSON renders the canonical report JSON.
func RenderJSON(report Report) ([]byte, error) {
	report = normalizeReportSlices(report)
	return json.MarshalIndent(report, "", "  ")
}

func normalizeReportSlices(report Report) Report {
	if report.Findings == nil {
		report.Findings = []model.Finding{}
	}
	if report.Reasons == nil {
		report.Reasons = []model.DecisionReason{}
	}
	if report.ReasonCodes == nil {
		report.ReasonCodes = []model.DecisionReasonCode{}
	}
	if report.RiskClusters == nil {
		report.RiskClusters = []RiskCluster{}
	}
	return report
}

// RenderMarkdown renders PR-comment-friendly Markdown.
func RenderMarkdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ChangeGate: %s\n\n", strings.ToUpper(string(report.Decision)))
	clusters := clustersForReport(report)
	fmt.Fprintf(&b, "| Metric | Value |\n| --- | ---: |\n")
	fmt.Fprintf(&b, "| Risk clusters | %d |\n", len(clusters))
	fmt.Fprintf(&b, "| Findings | %d |\n", report.RiskSummary.Total)
	fmt.Fprintf(&b, "| Blocking | %d |\n", report.RiskSummary.Blocking)
	fmt.Fprintf(&b, "| Warnings | %d |\n", report.RiskSummary.Warnings)
	fmt.Fprintf(&b, "| Suppressed | %d |\n", report.RiskSummary.Suppressed)
	fmt.Fprintf(&b, "| Downgraded | %d |\n", report.RiskSummary.Downgraded)
	if report.Imports != nil {
		fmt.Fprintf(&b, "| Imported findings | %d |\n", report.Imports.Imported)
		fmt.Fprintf(&b, "| Retained imported findings | %d |\n", retainedImportCount(report.Imports))
		fmt.Fprintf(&b, "| Deduplicated imported findings | %d |\n", report.Imports.Deduplicated)
		if report.Imports.SupersededByNative > 0 {
			fmt.Fprintf(&b, "| Native findings superseded imports | %d |\n", report.Imports.SupersededByNative)
		}
		fmt.Fprintf(&b, "| Correlated imported findings | %d |\n", report.Imports.Correlated)
		if report.Imports.Downgraded > 0 {
			fmt.Fprintf(&b, "| Downgraded imported findings | %d |\n", report.Imports.Downgraded)
		}
		if report.Imports.Upgraded > 0 {
			fmt.Fprintf(&b, "| Upgraded imported findings | %d |\n", report.Imports.Upgraded)
		}
	}
	fmt.Fprintf(&b, "| Graph nodes | %d |\n", report.Graph.Nodes)
	fmt.Fprintf(&b, "| Graph edges | %d |\n\n", report.Graph.Edges)
	writeImportIntelligenceMarkdown(&b, report.Imports)
	reasons := collapsedDecisionReasons(report)
	if len(reasons) > 0 {
		b.WriteString("## Decision reasons\n\n")
		for _, reason := range reasons {
			if reason.Resource == "" {
				fmt.Fprintf(&b, "- `%s`: %s\n", reason.Code, reason.Reason)
				continue
			}
			fmt.Fprintf(&b, "- `%s` `%s`: %s\n", reason.Code, reason.Resource, reason.Reason)
		}
		b.WriteString("\n")
	}
	if len(clusters) > 0 {
		b.WriteString("## Risk clusters\n\n")
		for _, cluster := range clusters {
			fmt.Fprintf(&b, "### %s\n\n", cluster.Title)
			fmt.Fprintf(&b, "- Decision: `%s`\n", cluster.Decision)
			fmt.Fprintf(&b, "- Severity: `%s`, confidence: `%s`\n", cluster.Severity, cluster.Confidence)
			fmt.Fprintf(&b, "- Affected resources: %d\n", len(cluster.AffectedResources))
			fmt.Fprintf(&b, "- Supporting findings: %d\n", len(cluster.SupportingFindings))
			if len(cluster.RuleIDs) > 0 {
				fmt.Fprintf(&b, "- Rules: `%s`\n", strings.Join(cluster.RuleIDs, "`, `"))
			}
			if cluster.RemediationSummary != "" {
				fmt.Fprintf(&b, "- Primary fix: %s\n", cluster.RemediationSummary)
			}
			if len(cluster.AffectedResources) > 0 {
				limit := len(cluster.AffectedResources)
				if limit > 8 {
					limit = 8
				}
				fmt.Fprintf(&b, "- Resources: `%s`\n", strings.Join(cluster.AffectedResources[:limit], "`, `"))
				if len(cluster.AffectedResources) > limit {
					fmt.Fprintf(&b, "- ... %d more resources\n", len(cluster.AffectedResources)-limit)
				}
			}
			b.WriteString("\n")
		}
	}
	if len(report.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	b.WriteString("## Finding details\n\n")
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "### %s\n\n", finding.Title)
		fmt.Fprintf(&b, "- Rule: `%s`\n", finding.RuleID)
		fmt.Fprintf(&b, "- Resource: `%s`\n", finding.ResourceAddress)
		fmt.Fprintf(&b, "- Severity: `%s`, confidence: `%s`\n", finding.Severity, finding.Confidence)
		fmt.Fprintf(&b, "- Fingerprint: `%s`\n", finding.Fingerprint)
		if finding.Description != "" {
			fmt.Fprintf(&b, "\n%s\n", finding.Description)
		}
		if len(finding.Evidence) > 0 {
			b.WriteString("\nEvidence:\n")
			for _, evidence := range finding.Evidence {
				fmt.Fprintf(&b, "- `%s`", evidence.Type)
				if evidence.Path != "" {
					fmt.Fprintf(&b, " `%s`", evidence.Path)
				}
				if evidence.Message != "" {
					fmt.Fprintf(&b, ": %s", evidence.Message)
				}
				b.WriteString("\n")
			}
		}
		if finding.Remediation.Summary != "" || len(finding.Remediation.Steps) > 0 {
			b.WriteString("\nRemediation:\n")
			if finding.Remediation.Summary != "" {
				fmt.Fprintf(&b, "- %s\n", finding.Remediation.Summary)
			}
			for _, step := range finding.Remediation.Steps {
				fmt.Fprintf(&b, "- %s\n", step)
			}
			if finding.Remediation.WhyThisWorks != "" {
				fmt.Fprintf(&b, "- Why this works: %s\n", finding.Remediation.WhyThisWorks)
			}
			if finding.Remediation.FixConfidence != "" {
				fmt.Fprintf(&b, "- Fix confidence: `%s`\n", finding.Remediation.FixConfidence)
			}
			if finding.Remediation.AutoFixAvailable || len(finding.Remediation.Patches) > 0 || finding.Remediation.WhyThisWorks != "" || finding.Remediation.FixConfidence != "" {
				fmt.Fprintf(&b, "- Automatic patch: `%t`\n", finding.Remediation.AutoFixAvailable)
			}
			for _, patch := range finding.Remediation.Patches {
				if patch.Snippet == "" {
					fmt.Fprintf(&b, "- Patch suggestion: %s (%s)\n", patch.Title, patch.Rationale)
					continue
				}
				fmt.Fprintf(&b, "\nPatch suggestion: %s\n\n```%s\n%s\n```\n", patch.Title, patch.Language, strings.TrimSpace(patch.Snippet))
			}
			if len(finding.Remediation.OwnerHints) > 0 {
				fmt.Fprintf(&b, "- Owner hints: `%s`\n", strings.Join(finding.Remediation.OwnerHints, "`, `"))
			}
			for _, step := range finding.Remediation.NextSteps {
				fmt.Fprintf(&b, "- Next step: %s\n", step)
			}
			for _, doc := range finding.Remediation.Docs {
				fmt.Fprintf(&b, "- Doc: %s\n", doc)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// RenderPRComment renders a concise Markdown summary for pull request comments.
func RenderPRComment(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## ChangeGate: %s\n\n", strings.ToUpper(string(report.Decision)))
	clusters := clustersForReport(report)
	fmt.Fprintf(&b, "**%d %s** from %d %s: %d blocking, %d warnings, %d suppressed.\n\n",
		len(clusters),
		pluralize(len(clusters), "risk cluster", "risk clusters"),
		report.RiskSummary.Total,
		pluralize(report.RiskSummary.Total, "finding", "findings"),
		report.RiskSummary.Blocking,
		report.RiskSummary.Warnings,
		report.RiskSummary.Suppressed,
	)
	reasons := collapsedDecisionReasons(report)
	if len(reasons) > 0 {
		b.WriteString("### Decision Reasons\n\n")
		for index, reason := range reasons {
			if index >= 3 {
				fmt.Fprintf(&b, "- ... %d more reasons\n", len(reasons)-index)
				break
			}
			if reason.Resource == "" {
				fmt.Fprintf(&b, "- `%s`: %s\n", reason.Code, reason.Reason)
			} else {
				fmt.Fprintf(&b, "- `%s` `%s`: %s\n", reason.Code, reason.Resource, reason.Reason)
			}
		}
		b.WriteString("\n")
	}
	if len(report.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	b.WriteString("### Risk Clusters\n\n")
	displayedClusters := len(clusters)
	if displayedClusters > 3 {
		displayedClusters = 3
	}
	for index, cluster := range clusters {
		if index >= 3 {
			fmt.Fprintf(&b, "... %d more risk clusters\n", len(clusters)-index)
			break
		}
		fmt.Fprintf(&b, "#### %d. %s\n\n", index+1, cluster.Title)
		fmt.Fprintf(&b, "- Severity: `%s`\n", cluster.Severity)
		fmt.Fprintf(&b, "- Confidence: `%s`\n", cluster.Confidence)
		fmt.Fprintf(&b, "- Decision: `%s`\n", cluster.Decision)
		fmt.Fprintf(&b, "- Affected resources: %d\n", len(cluster.AffectedResources))
		fmt.Fprintf(&b, "- Supporting findings: %d\n\n", len(cluster.SupportingFindings))
		if cluster.RemediationSummary != "" {
			fmt.Fprintf(&b, "**Fix:** %s\n\n", cluster.RemediationSummary)
		}
		if len(cluster.RuleIDs) > 0 {
			b.WriteString("Rules:\n\n")
			for _, ruleID := range cluster.RuleIDs {
				fmt.Fprintf(&b, "- `%s`\n", ruleID)
			}
		}
		if index < displayedClusters-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func pluralize(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func retainedImportCount(imports *ImportSummary) int {
	if imports == nil {
		return 0
	}
	if imports.Retained > 0 || imports.Imported == 0 {
		return imports.Retained
	}
	retained := imports.Imported - imports.Deduplicated
	if retained < 0 {
		return 0
	}
	return retained
}

func writeImportIntelligenceMarkdown(b *strings.Builder, imports *ImportSummary) {
	if imports == nil {
		return
	}
	b.WriteString("## External scanner intelligence\n\n")
	fmt.Fprintf(b, "ChangeGate imported %d external %s, retained %d after deduplication, and correlated %d to the change graph.\n\n", imports.Imported, pluralize(imports.Imported, "finding", "findings"), retainedImportCount(imports), imports.Correlated)
	if len(imports.BySource) > 0 {
		b.WriteString("| Source | Findings |\n| --- | ---: |\n")
		sources := make([]string, 0, len(imports.BySource))
		for source := range imports.BySource {
			sources = append(sources, source)
		}
		sort.Strings(sources)
		for _, source := range sources {
			fmt.Fprintf(b, "| `%s` | %d |\n", source, imports.BySource[source])
		}
		b.WriteString("\n")
	}
	if len(imports.Insights) == 0 {
		return
	}
	b.WriteString("Key handling notes:\n")
	limit := len(imports.Insights)
	if limit > 8 {
		limit = 8
	}
	for _, insight := range imports.Insights[:limit] {
		target := insight.Resource
		if target == "" {
			target = insight.RuleID
		}
		if target == "" {
			target = insight.Source
		}
		fmt.Fprintf(b, "- `%s` `%s` `%s`: %s", insight.Source, insight.Action, target, insight.Reason)
		if insight.NativeRuleID != "" {
			fmt.Fprintf(b, " (`%s`)", insight.NativeRuleID)
		}
		b.WriteString("\n")
	}
	if len(imports.Insights) > limit {
		fmt.Fprintf(b, "- ... %d more scanner handling notes in JSON output\n", len(imports.Insights)-limit)
	}
	b.WriteString("\n")
}

// RenderGitHubStepSummary renders a compact Markdown summary for GITHUB_STEP_SUMMARY.
func RenderGitHubStepSummary(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## ChangeGate %s\n\n", strings.ToUpper(string(report.Decision)))
	clusters := clustersForReport(report)
	fmt.Fprintf(&b, "- Risk clusters: %d\n", len(clusters))
	fmt.Fprintf(&b, "- Findings: %d\n", report.RiskSummary.Total)
	fmt.Fprintf(&b, "- Blocking: %d\n", report.RiskSummary.Blocking)
	fmt.Fprintf(&b, "- Warnings: %d\n", report.RiskSummary.Warnings)
	fmt.Fprintf(&b, "- Suppressed: %d\n", report.RiskSummary.Suppressed)
	if report.Imports != nil {
		fmt.Fprintf(&b, "- Imported findings: %d\n", report.Imports.Imported)
		fmt.Fprintf(&b, "- Retained imported findings: %d\n", retainedImportCount(report.Imports))
		fmt.Fprintf(&b, "- Deduplicated imported findings: %d\n", report.Imports.Deduplicated)
		if report.Imports.SupersededByNative > 0 {
			fmt.Fprintf(&b, "- Native findings superseded imports: %d\n", report.Imports.SupersededByNative)
		}
		fmt.Fprintf(&b, "- Correlated imported findings: %d\n", report.Imports.Correlated)
		if report.Imports.Downgraded > 0 {
			fmt.Fprintf(&b, "- Downgraded imported findings: %d\n", report.Imports.Downgraded)
		}
		if report.Imports.Upgraded > 0 {
			fmt.Fprintf(&b, "- Upgraded imported findings: %d\n", report.Imports.Upgraded)
		}
	}
	if len(report.Findings) == 0 {
		b.WriteString("\nNo findings.\n")
		return b.String()
	}
	if len(clusters) > 0 {
		b.WriteString("\n| Severity | Confidence | Risk cluster | Resources | Findings |\n| --- | --- | --- | ---: | ---: |\n")
		for _, cluster := range clusters {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | %d | %d |\n", cluster.Severity, cluster.Confidence, escapeMarkdownTable(cluster.Title), len(cluster.AffectedResources), len(cluster.SupportingFindings))
		}
	}
	return b.String()
}

// RenderGitHubAnnotations renders GitHub workflow command annotations.
func RenderGitHubAnnotations(report Report) string {
	var b strings.Builder
	for _, finding := range report.Findings {
		level := "warning"
		if findingBlocks(finding) {
			level = "error"
		}
		title := githubAnnotationEscape(finding.RuleID + " " + string(finding.Severity) + "/" + string(finding.Confidence))
		message := githubAnnotationEscape(finding.Title + " on " + finding.ResourceAddress)
		fmt.Fprintf(&b, "::%s file=%s,line=1,title=%s::%s\n", level, githubAnnotationEscape(report.Plan.Path), title, message)
	}
	return b.String()
}

func displayPlanPath(path string) string {
	if path == "-" {
		return "stdin"
	}
	return path
}

func clustersForReport(report Report) []RiskCluster {
	if len(report.RiskClusters) > 0 {
		return append([]RiskCluster(nil), report.RiskClusters...)
	}
	return BuildRiskClusters(report.Findings)
}

func collapsedDecisionReasons(report Report) []model.DecisionReason {
	if len(report.Reasons) == 0 {
		return nil
	}
	clusters := clustersForReport(report)
	findingToCluster := make(map[string]RiskCluster)
	for _, cluster := range clusters {
		for _, findingID := range cluster.SupportingFindings {
			findingToCluster[findingID] = cluster
		}
	}
	seen := make(map[string]bool)
	out := make([]model.DecisionReason, 0, len(report.Reasons))
	for _, reason := range report.Reasons {
		current := reason
		if cluster, ok := findingToCluster[reason.FindingID]; ok {
			current.FindingID = cluster.ID
			current.Resource = cluster.Title
			current.Reason = clusterReason(cluster, reason)
		}
		key := string(current.Code) + "\x00" + current.Resource + "\x00" + current.Reason
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, current)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		for _, cmp := range []int{
			strings.Compare(out[i].Resource, out[j].Resource),
			strings.Compare(string(out[i].Code), string(out[j].Code)),
			strings.Compare(out[i].Reason, out[j].Reason),
		} {
			if cmp != 0 {
				return cmp < 0
			}
		}
		return false
	})
	return out
}

func clusterReason(cluster RiskCluster, reason model.DecisionReason) string {
	if len(cluster.SupportingFindings) == 1 {
		return reason.Reason
	}
	return fmt.Sprintf("%s: %d supporting findings across %d affected resources", cluster.Title, len(cluster.SupportingFindings), len(cluster.AffectedResources))
}

func escapeMarkdownTable(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func githubAnnotationEscape(value string) string {
	value = strings.ReplaceAll(value, "%", "%25")
	value = strings.ReplaceAll(value, "\r", "%0D")
	value = strings.ReplaceAll(value, "\n", "%0A")
	value = strings.ReplaceAll(value, ":", "%3A")
	value = strings.ReplaceAll(value, ",", "%2C")
	return value
}

func sortedRuleIDs(rules map[string]RuleSummary) []string {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifText           `json:"shortDescription"`
	FullDescription  sarifText           `json:"fullDescription,omitempty"`
	Help             sarifText           `json:"help,omitempty"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRuleProperties struct {
	Category   model.RiskCategory `json:"category"`
	Severity   model.Severity     `json:"severity"`
	Confidence model.Confidence   `json:"confidence"`
	Tags       []string           `json:"tags,omitempty"`
}

type sarifText struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	Level               string                 `json:"level"`
	Message             sarifText              `json:"message"`
	Locations           []sarifLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// RenderSARIF renders SARIF 2.1.0 for GitHub code scanning and compatible tools.
func RenderSARIF(report Report) ([]byte, error) {
	rules := make([]sarifRule, 0, len(report.Rules))
	for _, id := range sortedRuleIDs(report.Rules) {
		rule := report.Rules[id]
		rules = append(rules, sarifRule{
			ID:               rule.ID,
			Name:             rule.Name,
			ShortDescription: sarifText{Text: firstNonEmpty(rule.Name, rule.ID)},
			FullDescription:  sarifText{Text: rule.Description},
			Help:             sarifText{Markdown: remediationMarkdown(rule)},
			Properties: sarifRuleProperties{
				Category:   rule.Category,
				Severity:   rule.Severity,
				Confidence: rule.Confidence,
				Tags:       []string{"security", "terraform", "opentofu", string(rule.Category)},
			},
		})
	}

	results := make([]sarifResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		results = append(results, sarifResult{
			RuleID:  finding.RuleID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifText{Text: finding.Title + " on " + finding.ResourceAddress},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: report.Plan.Path},
					Region:           sarifRegion{StartLine: 1},
				},
			}},
			PartialFingerprints: map[string]string{
				"changegateFingerprint/v1": finding.Fingerprint,
				"changegateDedupKey/v1":    finding.DeduplicationKey,
			},
			Properties: map[string]interface{}{
				"resource":    finding.ResourceAddress,
				"severity":    finding.Severity,
				"confidence":  finding.Confidence,
				"category":    finding.Category,
				"remediation": finding.Remediation,
			},
		})
	}

	return json.MarshalIndent(sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ChangeGate",
				InformationURI: "https://github.com/Gabriel0110/changegate",
				Rules:          rules,
			}},
			Results: results,
		}},
	}, "", "  ")
}

type junitTestsuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Skipped  int              `xml:"skipped,attr"`
	Suites   []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Testcases []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// RenderJUnit renders findings as test cases for CI report views.
func RenderJUnit(report Report) ([]byte, error) {
	cases := make([]junitTestcase, 0, len(report.Findings)+1)
	failures := 0
	skipped := 0
	if len(report.Findings) == 0 {
		cases = append(cases, junitTestcase{Name: "no findings", Classname: "changegate.scan"})
	} else {
		for _, finding := range report.Findings {
			tc := junitTestcase{Name: finding.RuleID + " " + finding.ResourceAddress, Classname: "changegate." + string(finding.Category)}
			if findingBlocks(finding) {
				failures++
				tc.Failure = &junitFailure{
					Message: finding.Title,
					Type:    string(finding.Severity),
					Body:    finding.Description + "\n\nRemediation: " + finding.Remediation.Summary,
				}
			} else if findingSuppressed(finding) {
				skipped++
				tc.Skipped = &junitSkipped{Message: "suppressed by policy"}
			}
			cases = append(cases, tc)
		}
	}
	suite := junitTestsuite{
		Name:      "changegate.scan",
		Tests:     len(cases),
		Failures:  failures,
		Skipped:   skipped,
		Testcases: cases,
	}
	body, err := xml.MarshalIndent(junitTestsuites{
		Name:     "changegate",
		Tests:    len(cases),
		Failures: failures,
		Skipped:  skipped,
		Suites:   []junitTestsuite{suite},
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

type gitLabIssue struct {
	Description string         `json:"description"`
	CheckName   string         `json:"check_name"`
	Fingerprint string         `json:"fingerprint"`
	Severity    string         `json:"severity"`
	Location    gitLabLocation `json:"location"`
}

type gitLabLocation struct {
	Path  string        `json:"path"`
	Lines gitLabLineRef `json:"lines"`
}

type gitLabLineRef struct {
	Begin int `json:"begin"`
}

// RenderGitLabCodeQuality renders a GitLab Code Quality compatible issue array.
func RenderGitLabCodeQuality(report Report) ([]byte, error) {
	issues := make([]gitLabIssue, 0, len(report.Findings))
	for _, finding := range report.Findings {
		issues = append(issues, gitLabIssue{
			Description: finding.Title + " on " + finding.ResourceAddress,
			CheckName:   finding.RuleID,
			Fingerprint: finding.Fingerprint,
			Severity:    gitLabSeverity(finding.Severity),
			Location: gitLabLocation{
				Path:  report.Plan.Path,
				Lines: gitLabLineRef{Begin: 1},
			},
		})
	}
	return json.MarshalIndent(issues, "", "  ")
}

// RenderAuditBundle renders a deterministic zip containing audit evidence.
func RenderAuditBundle(report Report) ([]byte, error) {
	files, err := auditBundleFiles(report)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	modified := time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: modified}
		w, err := zw.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func auditBundleFiles(report Report) (map[string][]byte, error) {
	scanReportBody, err := RenderJSON(report)
	if err != nil {
		return nil, err
	}
	findingsBody, err := marshalAuditJSON(report.Findings)
	if err != nil {
		return nil, err
	}
	suppressedBody, err := marshalAuditJSON(suppressedFindings(report.Findings))
	if err != nil {
		return nil, err
	}
	decisionBody, err := marshalAuditJSON(decisionEvidence(report))
	if err != nil {
		return nil, err
	}
	evidenceBody, err := marshalAuditJSON(findingEvidence(report.Findings))
	if err != nil {
		return nil, err
	}
	waiversBody, err := marshalAuditJSON(auditValue(report.Audit, func(a *AuditReports) any { return a.Waivers }))
	if err != nil {
		return nil, err
	}
	baselineBody, err := marshalAuditJSON(auditValue(report.Audit, func(a *AuditReports) any { return a.Baseline }))
	if err != nil {
		return nil, err
	}
	ruleVersionsBody, err := marshalAuditJSON(policyPackVersions(report))
	if err != nil {
		return nil, err
	}
	environmentBody, err := marshalAuditJSON(environmentEvidence(report))
	if err != nil {
		return nil, err
	}
	complianceBody, err := marshalAuditJSON(report.Compliance)
	if err != nil {
		return nil, err
	}
	runBody, err := marshalAuditJSON(report.Run)
	if err != nil {
		return nil, err
	}
	redactionBody, err := marshalAuditJSON(redactionEvidence(report))
	if err != nil {
		return nil, err
	}
	impactBody, err := marshalAuditJSON(auditValue(report.Audit, func(a *AuditReports) any { return a.Impact }))
	if err != nil {
		return nil, err
	}
	graphBody, err := marshalAuditJSON(auditValue(report.Audit, func(a *AuditReports) any { return a.Graph }))
	if err != nil {
		return nil, err
	}
	attackPathsBody, err := marshalAuditJSON(auditValue(report.Audit, func(a *AuditReports) any { return a.AttackPaths }))
	if err != nil {
		return nil, err
	}
	cloudContextBody, err := marshalAuditJSON(auditValue(report.Audit, func(a *AuditReports) any { return a.CloudContextSummary }))
	if err != nil {
		return nil, err
	}
	riskTestsBody, err := marshalAuditJSON(auditValue(report.Audit, func(a *AuditReports) any { return a.RiskTests }))
	if err != nil {
		return nil, err
	}
	hcpRunTaskBody, err := marshalAuditJSON(auditValue(report.Audit, func(a *AuditReports) any { return a.HCPRunTask }))
	if err != nil {
		return nil, err
	}
	importsBody, err := marshalAuditJSON(report.Imports)
	if err != nil {
		return nil, err
	}
	reproducibilityBody := []byte(renderReproducibilityMarkdown(report))
	evidenceReportBody := []byte(renderEvidenceReportHTML(report))

	policyBody := []byte(policyYAML(report))
	if len(policyBody) == 0 {
		policyBody = []byte("version: 1\n")
	}
	impactMarkdownBody := []byte(auditString(report.Audit, func(a *AuditReports) string { return a.ImpactMarkdown }))
	reviewCommentBody := []byte(auditString(report.Audit, func(a *AuditReports) string { return a.ReviewCommentMarkdown }))
	policyDigest := ""
	planDigest := ""
	if report.Run != nil {
		policyDigest = report.Run.PolicyDigest
		planDigest = report.Run.PlanDigest
	}
	files := map[string][]byte{
		"changegate-audit/baseline.json":              baselineBody,
		"changegate-audit/attack-paths.json":          attackPathsBody,
		"changegate-audit/cloud-context-summary.json": cloudContextBody,
		"changegate-audit/compliance.json":            complianceBody,
		"changegate-audit/decision.json":              decisionBody,
		"changegate-audit/environment.json":           environmentBody,
		"changegate-audit/evidence.json":              evidenceBody,
		"changegate-audit/evidence-report.html":       evidenceReportBody,
		"changegate-audit/findings.json":              findingsBody,
		"changegate-audit/graph.json":                 graphBody,
		"changegate-audit/hcp-run-task.json":          hcpRunTaskBody,
		"changegate-audit/impact.json":                impactBody,
		"changegate-audit/impact.md":                  impactMarkdownBody,
		"changegate-audit/imported-scanners.json":     importsBody,
		"changegate-audit/plan-digest.txt":            []byte(policyText(planDigest)),
		"changegate-audit/policy-digest.txt":          []byte(policyText(policyDigest)),
		"changegate-audit/policy.yaml":                policyBody,
		"changegate-audit/redaction-report.json":      redactionBody,
		"changegate-audit/reproducibility.md":         reproducibilityBody,
		"changegate-audit/review-comment.md":          reviewCommentBody,
		"changegate-audit/risk-tests.json":            riskTestsBody,
		"changegate-audit/rule-pack-versions.json":    ruleVersionsBody,
		"changegate-audit/run-metadata.json":          runBody,
		"changegate-audit/scan-report.json":           scanReportBody,
		"changegate-audit/summary.md":                 []byte(RenderMarkdown(report)),
		"changegate-audit/suppressed.json":            suppressedBody,
		"changegate-audit/waivers.json":               waiversBody,
	}
	manifestBody, err := marshalAuditJSON(auditManifest(files, report))
	if err != nil {
		return nil, err
	}
	files["changegate-audit/manifest.json"] = manifestBody
	return files, nil
}

func marshalAuditJSON(value any) ([]byte, error) {
	if value == nil {
		value = map[string]any{}
	}
	return json.MarshalIndent(value, "", "  ")
}

func auditValue(audit *AuditReports, selectValue func(*AuditReports) any) any {
	if audit == nil {
		return nil
	}
	return selectValue(audit)
}

func auditString(audit *AuditReports, selectValue func(*AuditReports) string) string {
	if audit == nil {
		return ""
	}
	return selectValue(audit)
}

type auditManifestDocument struct {
	SchemaVersion string              `json:"schema_version"`
	Root          string              `json:"root"`
	Decision      model.Decision      `json:"decision"`
	Plan          PlanSummary         `json:"plan"`
	Graph         GraphSummary        `json:"graph"`
	Artifacts     []auditManifestFile `json:"artifacts"`
	Redaction     RedactionReport     `json:"redaction"`
}

type auditManifestFile struct {
	Path        string `json:"path"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	Description string `json:"description"`
}

func auditManifest(files map[string][]byte, report Report) auditManifestDocument {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	artifacts := make([]auditManifestFile, 0, len(names))
	for _, name := range names {
		body := files[name]
		artifacts = append(artifacts, auditManifestFile{
			Path:        name,
			Bytes:       len(body),
			SHA256:      sha256String(body),
			Description: auditArtifactDescription(name),
		})
	}
	return auditManifestDocument{
		SchemaVersion: "changegate.audit.bundle.v2",
		Root:          "changegate-audit/",
		Decision:      report.Decision,
		Plan:          report.Plan,
		Graph:         report.Graph,
		Artifacts:     artifacts,
		Redaction:     redactionEvidence(report),
	}
}

func auditArtifactDescription(name string) string {
	switch name {
	case "changegate-audit/scan-report.json":
		return "Canonical ChangeGate scan report."
	case "changegate-audit/evidence-report.html":
		return "Self-contained human-readable evidence report."
	case "changegate-audit/manifest.json":
		return "Checksummed bundle manifest."
	case "changegate-audit/reproducibility.md":
		return "Commands and inputs for reproducing the scan."
	case "changegate-audit/imported-scanners.json":
		return "External scanner import summary and handling notes."
	case "changegate-audit/summary.md":
		return "Markdown summary of the deployment decision."
	case "changegate-audit/review-comment.md":
		return "PR or MR review comment body."
	case "changegate-audit/impact.md", "changegate-audit/impact.json":
		return "Security Impact Statement."
	case "changegate-audit/graph.json":
		return "Sanitized graph evidence."
	case "changegate-audit/attack-paths.json":
		return "Attack path evidence."
	case "changegate-audit/cloud-context-summary.json":
		return "Cloud context capability and collection summary."
	case "changegate-audit/policy.yaml":
		return "Policy configuration snapshot."
	case "changegate-audit/run-metadata.json":
		return "CLI version, build, digest, and redaction metadata."
	case "changegate-audit/redaction-report.json":
		return "Redaction summary."
	default:
		return "ChangeGate audit evidence artifact."
	}
}

func sha256String(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func renderReproducibilityMarkdown(report Report) string {
	var b strings.Builder
	b.WriteString("# Reproducibility\n\n")
	b.WriteString("This bundle does not include raw plan JSON or raw cloud inventory. Reproduce with the same plan, policy, cloud-context snapshot, and external scanner artifacts used by the original scan.\n\n")
	b.WriteString("## Primary command\n\n")
	b.WriteString("```bash\n")
	fmt.Fprintf(&b, "changegate scan --plan %s --format json --out changegate.json --audit-bundle changegate-audit.zip\n", shellQuote(report.Plan.Path))
	b.WriteString("```\n\n")
	if report.Run != nil {
		b.WriteString("## Digests\n\n")
		fmt.Fprintf(&b, "- Plan digest: `%s`\n", firstNonEmpty(report.Run.PlanDigest, "none"))
		fmt.Fprintf(&b, "- Policy digest: `%s`\n", firstNonEmpty(report.Run.PolicyDigest, "none"))
		fmt.Fprintf(&b, "- Config digest: `%s`\n", firstNonEmpty(report.Run.ConfigHash, "none"))
		fmt.Fprintf(&b, "- CLI version: `%s`\n", firstNonEmpty(report.Run.CLIVersion, "unknown"))
		if report.Run.CLICommit != "" {
			fmt.Fprintf(&b, "- CLI commit: `%s`\n", report.Run.CLICommit)
		}
		if report.Run.CLIDate != "" {
			fmt.Fprintf(&b, "- CLI build date: `%s`\n", report.Run.CLIDate)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Bundle entry points\n\n")
	b.WriteString("- `evidence-report.html` for a browser-readable evidence summary.\n")
	b.WriteString("- `scan-report.json` for the canonical machine-readable report.\n")
	b.WriteString("- `manifest.json` for artifact checksums.\n")
	b.WriteString("- `policy.yaml` for the policy snapshot used by the scan.\n")
	b.WriteString("- `summary.md`, `impact.md`, and `review-comment.md` for approval workflows.\n")
	return b.String()
}

func shellQuote(value string) string {
	if value == "" {
		return "tfplan.json"
	}
	if strings.ContainsAny(value, " \t\n'\"\\$`") {
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return value
}

func renderEvidenceReportHTML(report Report) string {
	clusters := clustersForReport(report)
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>ChangeGate Evidence Report</title>")
	b.WriteString("<style>body{font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;margin:0;color:#111827;background:#f8fafc}main{max-width:1120px;margin:0 auto;padding:32px}h1,h2,h3{margin:0 0 12px}.hero,.card{background:#fff;border:1px solid #dbe3ef;border-radius:8px;padding:20px;margin-bottom:18px}.decision{display:inline-block;padding:6px 10px;border-radius:6px;background:#111827;color:#fff;font-weight:700;text-transform:uppercase}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.metric{border:1px solid #dbe3ef;border-radius:8px;padding:14px;background:#f9fbff}.metric strong{display:block;font-size:28px}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #e5e7eb;padding:8px;vertical-align:top}code{background:#eef2f7;border-radius:4px;padding:1px 4px}a{color:#0f5cc0}.muted{color:#64748b}.finding{border-top:1px solid #e5e7eb;padding-top:12px;margin-top:12px}</style></head><body><main>")
	fmt.Fprintf(&b, "<section class=\"hero\"><h1>ChangeGate Evidence Report</h1><p><span class=\"decision\">%s</span></p><p class=\"muted\">Plan %s, %d resources, %d changes. Graph: %d nodes and %d edges.</p></section>", html.EscapeString(string(report.Decision)), html.EscapeString(report.Plan.Path), report.Plan.Resources, report.Plan.Changes, report.Graph.Nodes, report.Graph.Edges)
	b.WriteString("<section class=\"card\"><h2>Summary</h2><div class=\"grid\">")
	writeMetricHTML(&b, "Findings", report.RiskSummary.Total)
	writeMetricHTML(&b, "Risk clusters", len(clusters))
	writeMetricHTML(&b, "Blocking", report.RiskSummary.Blocking)
	writeMetricHTML(&b, "Warnings", report.RiskSummary.Warnings)
	writeMetricHTML(&b, "Suppressed", report.RiskSummary.Suppressed)
	writeMetricHTML(&b, "Downgraded", report.RiskSummary.Downgraded)
	b.WriteString("</div></section>")
	if report.Imports != nil {
		b.WriteString("<section class=\"card\"><h2>External Scanner Intelligence</h2><div class=\"grid\">")
		writeMetricHTML(&b, "Imported", report.Imports.Imported)
		writeMetricHTML(&b, "Retained", retainedImportCount(report.Imports))
		writeMetricHTML(&b, "Superseded", report.Imports.SupersededByNative)
		writeMetricHTML(&b, "Correlated", report.Imports.Correlated)
		writeMetricHTML(&b, "Downgraded", report.Imports.Downgraded)
		writeMetricHTML(&b, "Upgraded", report.Imports.Upgraded)
		b.WriteString("</div>")
		if len(report.Imports.Insights) > 0 {
			b.WriteString("<table><thead><tr><th>Source</th><th>Action</th><th>Resource</th><th>Reason</th></tr></thead><tbody>")
			limit := len(report.Imports.Insights)
			if limit > 10 {
				limit = 10
			}
			for _, insight := range report.Imports.Insights[:limit] {
				fmt.Fprintf(&b, "<tr><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>", html.EscapeString(insight.Source), html.EscapeString(insight.Action), html.EscapeString(insight.Resource), html.EscapeString(insight.Reason))
			}
			b.WriteString("</tbody></table>")
		}
		b.WriteString("</section>")
	}
	if len(clusters) > 0 {
		b.WriteString("<section class=\"card\"><h2>Risk Clusters</h2><table><thead><tr><th>Cluster</th><th>Decision</th><th>Severity</th><th>Confidence</th><th>Resources</th><th>Findings</th></tr></thead><tbody>")
		for _, cluster := range clusters {
			fmt.Fprintf(&b, "<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td><td>%d</td><td>%d</td></tr>", html.EscapeString(cluster.Title), html.EscapeString(string(cluster.Decision)), html.EscapeString(string(cluster.Severity)), html.EscapeString(string(cluster.Confidence)), len(cluster.AffectedResources), len(cluster.SupportingFindings))
		}
		b.WriteString("</tbody></table></section>")
	}
	b.WriteString("<section class=\"card\"><h2>Top Findings</h2>")
	if len(report.Findings) == 0 {
		b.WriteString("<p>No findings.</p>")
	} else {
		limit := len(report.Findings)
		if limit > 10 {
			limit = 10
		}
		for _, finding := range report.Findings[:limit] {
			fmt.Fprintf(&b, "<div class=\"finding\"><h3>%s</h3><p><code>%s</code> on <code>%s</code></p><p>Severity <code>%s</code>, confidence <code>%s</code></p>", html.EscapeString(finding.Title), html.EscapeString(finding.RuleID), html.EscapeString(finding.ResourceAddress), html.EscapeString(string(finding.Severity)), html.EscapeString(string(finding.Confidence)))
			if finding.Remediation.Summary != "" {
				fmt.Fprintf(&b, "<p><strong>Fix:</strong> %s</p>", html.EscapeString(finding.Remediation.Summary))
			}
			b.WriteString("</div>")
		}
	}
	b.WriteString("</section>")
	b.WriteString("<section class=\"card\"><h2>Bundle Artifacts</h2><ul>")
	for _, item := range []struct {
		href  string
		label string
	}{
		{"scan-report.json", "Canonical scan report"},
		{"summary.md", "Markdown summary"},
		{"impact.md", "Security Impact Statement"},
		{"review-comment.md", "PR/MR review comment"},
		{"graph.json", "Graph evidence"},
		{"attack-paths.json", "Attack path evidence"},
		{"imported-scanners.json", "External scanner summary"},
		{"policy.yaml", "Policy snapshot"},
		{"manifest.json", "Checksummed manifest"},
		{"reproducibility.md", "Reproducibility notes"},
	} {
		fmt.Fprintf(&b, "<li><a href=\"%s\">%s</a></li>", html.EscapeString(item.href), html.EscapeString(item.label))
	}
	b.WriteString("</ul></section></main></body></html>\n")
	return b.String()
}

func writeMetricHTML(b *strings.Builder, label string, value int) {
	fmt.Fprintf(b, "<div class=\"metric\"><strong>%d</strong><span>%s</span></div>", value, html.EscapeString(label))
}

func policyYAML(report Report) string {
	if report.Audit == nil {
		return ""
	}
	return report.Audit.PolicyYAML
}

func policyPackVersions(report Report) map[string]string {
	if report.Run == nil {
		return map[string]string{}
	}
	return report.Run.PolicyPackVersions
}

func redactionEvidence(report Report) RedactionReport {
	if report.Run != nil && report.Run.Redaction.Status != "" {
		return report.Run.Redaction
	}
	return RedactionReport{Status: "redacted"}
}

func environmentEvidence(report Report) map[string]any {
	env := map[string]any{
		"plan":             report.Plan,
		"graph":            report.Graph,
		"policy_decision":  report.Decision,
		"risk_summary":     report.RiskSummary,
		"redaction_status": redactionEvidence(report).Status,
	}
	if report.Run != nil {
		env["cli_version"] = report.Run.CLIVersion
		env["cli_commit"] = report.Run.CLICommit
		env["cli_date"] = report.Run.CLIDate
		env["cloud_context_timestamp"] = report.Run.CloudContextTimestamp
	}
	return env
}

func decisionEvidence(report Report) map[string]any {
	return map[string]any{
		"decision":     report.Decision,
		"reason_codes": report.ReasonCodes,
		"reasons":      report.Reasons,
		"risk_summary": report.RiskSummary,
	}
}

func findingEvidence(findings []model.Finding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		out = append(out, map[string]any{
			"finding_id":       finding.ID,
			"rule_id":          finding.RuleID,
			"resource":         finding.ResourceAddress,
			"evidence":         finding.Evidence,
			"decision_reasons": finding.DecisionReasons,
		})
	}
	return out
}

func suppressedFindings(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0)
	for _, finding := range findings {
		if findingSuppressed(finding) {
			out = append(out, finding)
		}
	}
	return out
}

func policyText(value string) string {
	if value == "" {
		return "none\n"
	}
	return value + "\n"
}

func remediationMarkdown(rule RuleSummary) string {
	var b strings.Builder
	if rule.Help != "" {
		b.WriteString(rule.Help)
	}
	if len(rule.Remediation) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("Remediation:\n")
		for _, step := range rule.Remediation {
			b.WriteString("- ")
			b.WriteString(step)
			b.WriteString("\n")
		}
	}
	if len(rule.References) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("References:\n")
		for _, ref := range rule.References {
			b.WriteString("- ")
			b.WriteString(ref)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func gitLabSeverity(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "major"
	case model.SeverityMedium:
		return "minor"
	default:
		return "info"
	}
}

func findingBlocks(finding model.Finding) bool {
	for _, code := range finding.DecisionReasonCodes {
		if code == model.ReasonMeetsBlockThreshold {
			return true
		}
	}
	return false
}

func findingSuppressed(finding model.Finding) bool {
	for _, code := range finding.DecisionReasonCodes {
		if code == model.ReasonSuppressed || code == model.ReasonChangedResourceOnly || code == model.ReasonExistingRisk {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
