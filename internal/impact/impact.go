// Package impact builds canonical Security Impact Statements from scan reports.
package impact

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
)

const (
	// StatementVersion is the canonical Security Impact Statement schema version.
	StatementVersion = 1

	// DefaultTopFindingsLimit controls how many findings are included by default.
	DefaultTopFindingsLimit = 10
	// DefaultTopGraphPathsLimit controls how many graph paths are included by default.
	DefaultTopGraphPathsLimit = 5
	// DefaultAttackPathsLimit controls how many attack paths are included by default.
	DefaultAttackPathsLimit = 5
)

// SectionID is a stable anchor identifier for downstream comments and renderers.
type SectionID string

const (
	SectionSummary         SectionID = "summary"
	SectionDecision        SectionID = "decision"
	SectionRiskMovement    SectionID = "risk-movement"
	SectionTopFindings     SectionID = "top-findings"
	SectionTopGraphPaths   SectionID = "top-graph-paths"
	SectionAttackPaths     SectionID = "attack-paths"
	SectionWaivers         SectionID = "waivers"
	SectionBaseline        SectionID = "baseline"
	SectionOwnership       SectionID = "ownership"
	SectionRequiredReviews SectionID = "required-reviews"
)

// Options controls impact statement construction.
type Options struct {
	GeneratedAt        time.Time
	PlansScanned       int
	TopFindingsLimit   int
	TopGraphPathsLimit int
	AttackPathsLimit   int
}

// RenderJSON renders a canonical impact statement JSON document.
func RenderJSON(statement Statement) ([]byte, error) {
	return json.MarshalIndent(statement, "", "  ")
}

// RenderMarkdown renders a human-readable Security Impact Statement.
func RenderMarkdown(statement Statement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security Impact Statement\n\n")
	fmt.Fprintf(&b, "Decision: %s\n", strings.ToUpper(string(statement.Decision)))
	if statement.ReviewRequired {
		b.WriteString("Review required: Yes\n\n")
	} else {
		b.WriteString("Review required: No\n\n")
	}

	b.WriteString("This change introduces:\n")
	fmt.Fprintf(&b, "- %d public entrypoint%s\n", statement.Summary.PublicEntrypointsAdded, plural(statement.Summary.PublicEntrypointsAdded))
	fmt.Fprintf(&b, "- %d sensitive asset%s touched\n", statement.Summary.SensitiveAssetsTouched, plural(statement.Summary.SensitiveAssetsTouched))
	fmt.Fprintf(&b, "- %d IAM permission change%s\n", statement.Summary.IAMPermissionChanges, plural(statement.Summary.IAMPermissionChanges))
	fmt.Fprintf(&b, "- %d network path change%s\n", statement.Summary.NetworkPathChanges, plural(statement.Summary.NetworkPathChanges))
	fmt.Fprintf(&b, "- %d data path change%s\n", statement.Summary.DataPathChanges, plural(statement.Summary.DataPathChanges))
	fmt.Fprintf(&b, "- %d active waiver%s\n\n", statement.Waivers.Active, plural(statement.Waivers.Active))

	if len(statement.RiskClusters) > 0 {
		fmt.Fprintf(&b, "## Risk Clusters\n\n")
		for _, cluster := range statement.RiskClusters {
			fmt.Fprintf(&b, "- `%s/%s` %s\n", cluster.Severity, cluster.Confidence, cluster.Title)
			fmt.Fprintf(&b, "  - Decision: `%s`\n", cluster.Decision)
			fmt.Fprintf(&b, "  - Affected resources: %d\n", len(cluster.AffectedResources))
			fmt.Fprintf(&b, "  - Supporting findings: %d\n", len(cluster.SupportingFindings))
			if cluster.RemediationSummary != "" {
				fmt.Fprintf(&b, "  - Primary fix: %s\n", cluster.RemediationSummary)
			}
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Risk Movement\n\n")
	fmt.Fprintf(&b, "| Metric | Count |\n| --- | ---: |\n")
	fmt.Fprintf(&b, "| New critical risks | %d |\n", statement.RiskMovement.NewCritical)
	fmt.Fprintf(&b, "| New high risks | %d |\n", statement.RiskMovement.NewHigh)
	fmt.Fprintf(&b, "| New medium risks | %d |\n", statement.RiskMovement.NewMedium)
	fmt.Fprintf(&b, "| Existing unchanged risks | %d |\n", statement.RiskMovement.ExistingUnchanged)
	fmt.Fprintf(&b, "| Existing worsened risks | %d |\n", statement.RiskMovement.ExistingWorsened)
	fmt.Fprintf(&b, "| Existing improved risks | %d |\n", statement.RiskMovement.ExistingImproved)
	fmt.Fprintf(&b, "| Resolved high risks | %d |\n\n", statement.RiskMovement.ResolvedHigh)

	if len(statement.TopGraphPaths) > 0 {
		fmt.Fprintf(&b, "## Top Graph Paths\n\n")
		for _, path := range statement.TopGraphPaths {
			fmt.Fprintf(&b, "- `%s`: %s\n", path.Resource, strings.Join(path.Path, " -> "))
		}
		b.WriteString("\n")
	}

	if len(statement.AttackPaths) > 0 {
		fmt.Fprintf(&b, "## Attack Paths\n\n")
		for _, path := range statement.AttackPaths {
			fmt.Fprintf(&b, "- `%s` `%s/%s` `%s` %s\n", path.RuleID, path.Severity, path.Confidence, path.Decision, path.Title)
			if path.Type != "" || path.Kind != "" || path.Source != "" {
				fmt.Fprintf(&b, "  - Context: type `%s`, kind `%s`, source `%s`\n", nonEmpty(path.Type, "unknown"), nonEmpty(path.Kind, "unknown"), nonEmpty(path.Source, "unknown"))
			}
			if path.ConfidenceReason != "" {
				fmt.Fprintf(&b, "  - Confidence reason: %s\n", path.ConfidenceReason)
			}
			for _, step := range path.Steps {
				fmt.Fprintf(&b, "  - %s\n", step)
			}
		}
		b.WriteString("\n")
	}

	if len(statement.TopFindings) > 0 {
		fmt.Fprintf(&b, "## Top Findings\n\n")
		for _, finding := range statement.TopFindings {
			fmt.Fprintf(&b, "- `%s` `%s/%s` %s on `%s`\n", finding.RuleID, finding.Severity, finding.Confidence, finding.Title, finding.ResourceAddress)
		}
		b.WriteString("\n")
	}

	if len(statement.RequiredReviewers) > 0 {
		fmt.Fprintf(&b, "## Required Review\n\n")
		for _, reviewer := range statement.RequiredReviewers {
			fmt.Fprintf(&b, "- `%s`: %s\n", reviewer.Reviewer, reviewer.Reason)
		}
	}

	return b.String()
}

func plural(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func nonEmpty(value string, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

// RenderAuditBundle renders a deterministic ZIP containing impact evidence.
func RenderAuditBundle(statement Statement, report output.Report) ([]byte, error) {
	statementJSON, err := RenderJSON(statement)
	if err != nil {
		return nil, err
	}
	reportJSON, err := output.RenderJSON(report)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"changegate-impact/impact-statement.json": statementJSON,
		"changegate-impact/impact-statement.md":   []byte(RenderMarkdown(statement)),
		"changegate-impact/scan-report.json":      reportJSON,
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.Modified = time.Unix(0, 0).UTC()
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Statement is the canonical Security Impact Statement model.
type Statement struct {
	Version           int                        `json:"version"`
	SectionIDs        map[string]SectionID       `json:"section_ids"`
	Decision          model.Decision             `json:"decision"`
	DecisionReasons   []model.DecisionReason     `json:"decision_reasons"`
	Summary           Summary                    `json:"summary"`
	RiskMovement      RiskMovement               `json:"risk_movement"`
	RiskClusters      []output.RiskCluster       `json:"risk_clusters,omitempty"`
	TopFindings       []model.Finding            `json:"top_findings,omitempty"`
	TopGraphPaths     []GraphPathSummary         `json:"top_graph_paths,omitempty"`
	AttackPaths       []AttackPathSummary        `json:"attack_paths,omitempty"`
	Waivers           WaiverSummary              `json:"waivers"`
	Baseline          BaselineSummary            `json:"baseline"`
	Ownership         []OwnershipHint            `json:"ownership,omitempty"`
	ReviewRequired    bool                       `json:"review_required"`
	RequiredReviewers []ReviewerRequirement      `json:"required_reviewers,omitempty"`
	GeneratedAt       time.Time                  `json:"generated_at"`
	Source            SourceSummary              `json:"source"`
	Diagnostics       []model.Diagnostic         `json:"diagnostics,omitempty"`
	ReasonCodes       []model.DecisionReasonCode `json:"reason_codes,omitempty"`
}

// SourceSummary identifies the scan report used to build a statement.
type SourceSummary struct {
	ReportSchemaVersion string              `json:"report_schema_version"`
	Plan                output.PlanSummary  `json:"plan"`
	Graph               output.GraphSummary `json:"graph"`
}

// Summary describes infrastructure change impact.
type Summary struct {
	PlansScanned           int `json:"plans_scanned"`
	ResourcesChanged       int `json:"resources_changed"`
	ResourcesCreated       int `json:"resources_created"`
	ResourcesUpdated       int `json:"resources_updated"`
	ResourcesDeleted       int `json:"resources_deleted"`
	PublicEntrypointsAdded int `json:"public_entrypoints_added"`
	SensitiveAssetsTouched int `json:"sensitive_assets_touched"`
	IAMPermissionChanges   int `json:"iam_permission_changes"`
	NetworkPathChanges     int `json:"network_path_changes"`
	DataPathChanges        int `json:"data_path_changes"`
}

// RiskMovement describes baseline and waiver movement relevant to a review.
type RiskMovement struct {
	NewCritical       int `json:"new_critical"`
	NewHigh           int `json:"new_high"`
	NewMedium         int `json:"new_medium"`
	ResolvedCritical  int `json:"resolved_critical"`
	ResolvedHigh      int `json:"resolved_high"`
	ExistingUnchanged int `json:"existing_unchanged"`
	ExistingWorsened  int `json:"existing_worsened"`
	ExistingImproved  int `json:"existing_improved"`
	WaivedActive      int `json:"waived_active"`
	WaivedExpired     int `json:"waived_expired"`
}

// GraphPathSummary captures a graph path promoted into review output.
type GraphPathSummary struct {
	ID          string           `json:"id"`
	FindingID   string           `json:"finding_id,omitempty"`
	RuleID      string           `json:"rule_id,omitempty"`
	Resource    string           `json:"resource,omitempty"`
	Title       string           `json:"title,omitempty"`
	Severity    model.Severity   `json:"severity,omitempty"`
	Confidence  model.Confidence `json:"confidence,omitempty"`
	Path        []string         `json:"path,omitempty"`
	Description string           `json:"description,omitempty"`
}

// AttackPathSummary captures an attack path promoted into review output.
type AttackPathSummary struct {
	ID               string                     `json:"id"`
	FindingID        string                     `json:"finding_id,omitempty"`
	RuleID           string                     `json:"rule_id,omitempty"`
	Resource         string                     `json:"resource,omitempty"`
	Type             string                     `json:"type,omitempty"`
	Kind             string                     `json:"kind,omitempty"`
	Title            string                     `json:"title,omitempty"`
	Severity         model.Severity             `json:"severity,omitempty"`
	Confidence       model.Confidence           `json:"confidence,omitempty"`
	Source           string                     `json:"source,omitempty"`
	ConfidenceReason string                     `json:"confidence_reason,omitempty"`
	Steps            []string                   `json:"steps,omitempty"`
	Decision         model.Decision             `json:"decision,omitempty"`
	ReasonCodes      []model.DecisionReasonCode `json:"reason_codes,omitempty"`
}

// WaiverSummary summarizes waiver state visible in the report.
type WaiverSummary struct {
	Active  int `json:"active"`
	Expired int `json:"expired"`
	Total   int `json:"total"`
}

// BaselineSummary summarizes existing-risk state visible in the report.
type BaselineSummary struct {
	ExistingFindings int `json:"existing_findings"`
	NewFindings      int `json:"new_findings"`
}

// OwnershipHint routes a finding to a probable owner.
type OwnershipHint struct {
	Owner    string `json:"owner"`
	Resource string `json:"resource,omitempty"`
	Finding  string `json:"finding_id,omitempty"`
	Source   string `json:"source"`
}

// ReviewerRequirement describes a human review requirement.
type ReviewerRequirement struct {
	Reviewer string `json:"reviewer"`
	Reason   string `json:"reason"`
	Source   string `json:"source,omitempty"`
}

// Build creates a deterministic Security Impact Statement from an output report.
func Build(report output.Report, opts Options) (Statement, error) {
	opts = normalizeOptions(opts)
	findings := sanitizedFindings(report.Findings)
	SortFindings(findings)

	statement := Statement{
		Version:         StatementVersion,
		SectionIDs:      defaultSectionIDs(),
		Decision:        report.Decision,
		DecisionReasons: sortedDecisionReasons(report.Reasons),
		Summary:         buildSummary(report, findings, opts),
		RiskMovement:    buildRiskMovement(report, findings),
		RiskClusters:    output.BuildRiskClusters(findings),
		TopFindings:     limitFindings(findings, opts.TopFindingsLimit),
		TopGraphPaths:   limitGraphPaths(buildGraphPaths(findings), opts.TopGraphPathsLimit),
		AttackPaths:     limitAttackPaths(buildAttackPaths(findings, report.Decision), opts.AttackPathsLimit),
		Waivers:         buildWaiverSummary(findings),
		Baseline:        buildBaselineSummary(findings),
		Ownership:       buildOwnership(findings),
		ReviewRequired:  reviewRequired(report.Decision, findings),
		GeneratedAt:     opts.GeneratedAt.UTC(),
		Source: SourceSummary{
			ReportSchemaVersion: report.SchemaVersion,
			Plan:                report.Plan,
			Graph:               report.Graph,
		},
		Diagnostics: sortedDiagnostics(report.Diagnostics),
		ReasonCodes: sortedReasonCodes(report.ReasonCodes),
	}
	statement.RequiredReviewers = buildReviewerRequirements(statement)
	return statement, nil
}

// SortFindings applies Review Intelligence ordering to findings.
func SortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i int, j int) bool {
		left := findings[i]
		right := findings[j]
		for _, cmp := range []int{
			compareInt(severityRank(right.Severity), severityRank(left.Severity)),
			compareInt(confidenceRank(right.Confidence), confidenceRank(left.Confidence)),
			compareInt(decisionImpactRank(right), decisionImpactRank(left)),
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

func normalizeOptions(opts Options) Options {
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	if opts.PlansScanned == 0 {
		opts.PlansScanned = 1
	}
	if opts.TopFindingsLimit == 0 {
		opts.TopFindingsLimit = DefaultTopFindingsLimit
	}
	if opts.TopGraphPathsLimit == 0 {
		opts.TopGraphPathsLimit = DefaultTopGraphPathsLimit
	}
	if opts.AttackPathsLimit == 0 {
		opts.AttackPathsLimit = DefaultAttackPathsLimit
	}
	return opts
}

func defaultSectionIDs() map[string]SectionID {
	return map[string]SectionID{
		"summary":          SectionSummary,
		"decision":         SectionDecision,
		"risk_movement":    SectionRiskMovement,
		"top_findings":     SectionTopFindings,
		"top_graph_paths":  SectionTopGraphPaths,
		"attack_paths":     SectionAttackPaths,
		"waivers":          SectionWaivers,
		"baseline":         SectionBaseline,
		"ownership":        SectionOwnership,
		"required_reviews": SectionRequiredReviews,
	}
}

func sanitizedFindings(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		current := finding
		current.Evidence = model.RedactEvidence(current.Evidence)
		out = append(out, current)
	}
	return out
}

func buildSummary(report output.Report, findings []model.Finding, opts Options) Summary {
	summary := Summary{
		PlansScanned:     opts.PlansScanned,
		ResourcesChanged: report.Plan.Changes,
	}
	summary.PublicEntrypointsAdded = countUniqueByCategory(findings, model.RiskCategoryPublicExposure)
	summary.SensitiveAssetsTouched = countUniqueByCategory(findings, model.RiskCategorySensitiveData)
	summary.IAMPermissionChanges = countIAMFindings(findings)
	summary.NetworkPathChanges = countNetworkFindings(findings)
	summary.DataPathChanges = countUniqueByCategory(findings, model.RiskCategorySensitiveData)
	return summary
}

func buildRiskMovement(report output.Report, findings []model.Finding) RiskMovement {
	if report.RiskMovement != nil {
		return RiskMovement{
			NewCritical:       report.RiskMovement.NewCritical,
			NewHigh:           report.RiskMovement.NewHigh,
			NewMedium:         report.RiskMovement.NewMedium,
			ResolvedCritical:  report.RiskMovement.ResolvedCritical,
			ResolvedHigh:      report.RiskMovement.ResolvedHigh,
			ExistingUnchanged: report.RiskMovement.ExistingUnchanged,
			ExistingWorsened:  report.RiskMovement.ExistingWorsened,
			ExistingImproved:  report.RiskMovement.ExistingImproved,
			WaivedActive:      report.RiskMovement.WaivedActive,
			WaivedExpired:     report.RiskMovement.WaivedExpired,
		}
	}
	var movement RiskMovement
	for _, finding := range findings {
		if hasActiveSuppression(finding, "waiver") {
			movement.WaivedActive++
			continue
		}
		if hasExpiredSuppression(finding, "waiver") {
			movement.WaivedExpired++
		}
		if hasReason(finding, model.ReasonExistingRisk) || hasActiveSuppression(finding, "existing_risk") || hasActiveSuppression(finding, "baseline") {
			movement.ExistingUnchanged++
			continue
		}
		switch finding.Severity {
		case model.SeverityCritical:
			movement.NewCritical++
		case model.SeverityHigh:
			movement.NewHigh++
		case model.SeverityMedium:
			movement.NewMedium++
		}
	}
	movement.WaivedActive = buildWaiverSummary(findings).Active
	movement.WaivedExpired = buildWaiverSummary(findings).Expired
	return movement
}

func buildWaiverSummary(findings []model.Finding) WaiverSummary {
	var summary WaiverSummary
	for _, finding := range findings {
		for _, suppression := range finding.Suppressions {
			if suppression.Kind != "waiver" {
				continue
			}
			summary.Total++
			if suppression.Active {
				summary.Active++
			} else {
				summary.Expired++
			}
		}
	}
	return summary
}

func buildBaselineSummary(findings []model.Finding) BaselineSummary {
	var summary BaselineSummary
	for _, finding := range findings {
		if hasReason(finding, model.ReasonExistingRisk) || hasActiveSuppression(finding, "existing_risk") || hasActiveSuppression(finding, "baseline") {
			summary.ExistingFindings++
			continue
		}
		summary.NewFindings++
	}
	return summary
}

func buildGraphPaths(findings []model.Finding) []GraphPathSummary {
	out := make([]GraphPathSummary, 0)
	for _, finding := range findings {
		for index, evidence := range finding.Evidence {
			if !isGraphEvidence(evidence) {
				continue
			}
			out = append(out, GraphPathSummary{
				ID:          stableItemID("graph-path", finding, index),
				FindingID:   finding.ID,
				RuleID:      finding.RuleID,
				Resource:    finding.ResourceAddress,
				Title:       finding.Title,
				Severity:    finding.Severity,
				Confidence:  finding.Confidence,
				Path:        graphPathFromEvidence(evidence),
				Description: evidence.Message,
			})
		}
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return compareGraphPaths(out[i], out[j]) < 0
	})
	return out
}

func buildAttackPaths(findings []model.Finding, decision model.Decision) []AttackPathSummary {
	out := make([]AttackPathSummary, 0)
	for _, finding := range findings {
		if !isAttackPathFinding(finding) && finding.Category != model.RiskCategoryPrivilegeEscalation && !containsFold(finding.RuleID, "PASSROLE") && !containsFold(finding.RuleID, "ASSUME") {
			continue
		}
		steps := make([]string, 0, len(finding.Evidence))
		for _, evidence := range finding.Evidence {
			if isAttackPathMetadataEvidence(evidence) {
				continue
			}
			if isGraphEvidence(evidence) {
				steps = append(steps, graphPathFromEvidence(evidence)...)
				continue
			}
			if evidence.Message != "" {
				steps = append(steps, evidence.Message)
			}
		}
		out = append(out, AttackPathSummary{
			ID:               stableItemID("attack-path", finding, 0),
			FindingID:        finding.ID,
			RuleID:           finding.RuleID,
			Resource:         finding.ResourceAddress,
			Type:             attackPathType(finding),
			Kind:             attackPathEvidenceValue(finding, "attack_path.kind"),
			Title:            finding.Title,
			Severity:         finding.Severity,
			Confidence:       finding.Confidence,
			Source:           attackPathEvidenceValue(finding, "attack_path.source"),
			ConfidenceReason: attackPathEvidenceValue(finding, "attack_path.confidence_reason"),
			Steps:            dedupeSorted(steps),
			Decision:         decisionForFinding(decision, finding),
			ReasonCodes:      sortedReasonCodes(finding.DecisionReasonCodes),
		})
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return compareAttackPaths(out[i], out[j]) < 0
	})
	return out
}

func isAttackPathMetadataEvidence(evidence model.Evidence) bool {
	return evidence.Type == "attack_path" && strings.HasPrefix(evidence.Path, "attack_path.")
}

func isAttackPathFinding(finding model.Finding) bool {
	if strings.Contains(strings.ToLower(finding.RuleID), "ATTACK_PATH") {
		return true
	}
	for _, evidence := range finding.Evidence {
		if strings.Contains(strings.ToLower(evidence.Type), "attack_path") {
			return true
		}
	}
	return false
}

func buildOwnership(findings []model.Finding) []OwnershipHint {
	seen := make(map[string]bool)
	out := make([]OwnershipHint, 0)
	for _, finding := range findings {
		for _, owner := range finding.Remediation.OwnerHints {
			key := owner + "\x00" + finding.ResourceAddress + "\x00" + finding.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, OwnershipHint{
				Owner:    owner,
				Resource: finding.ResourceAddress,
				Finding:  finding.ID,
				Source:   "remediation.owner_hints",
			})
		}
	}
	sort.SliceStable(out, func(i int, j int) bool {
		for _, cmp := range []int{
			strings.Compare(out[i].Owner, out[j].Owner),
			strings.Compare(out[i].Resource, out[j].Resource),
			strings.Compare(out[i].Finding, out[j].Finding),
		} {
			if cmp != 0 {
				return cmp < 0
			}
		}
		return false
	})
	return out
}

func buildReviewerRequirements(statement Statement) []ReviewerRequirement {
	if !statement.ReviewRequired {
		return nil
	}
	requirements := make([]ReviewerRequirement, 0)
	if statement.Decision == model.DecisionBlock {
		requirements = append(requirements, ReviewerRequirement{
			Reviewer: "security",
			Reason:   "deployment decision is block",
			Source:   string(SectionDecision),
		})
	}
	if statement.Summary.IAMPermissionChanges > 0 {
		requirements = append(requirements, ReviewerRequirement{
			Reviewer: "cloud-security",
			Reason:   "IAM permission change affects review impact",
			Source:   string(SectionSummary),
		})
	}
	if statement.Summary.SensitiveAssetsTouched > 0 {
		requirements = append(requirements, ReviewerRequirement{
			Reviewer: "data-owner",
			Reason:   "sensitive asset is affected",
			Source:   string(SectionSummary),
		})
	}
	return requirements
}

func reviewRequired(decision model.Decision, findings []model.Finding) bool {
	if decision == model.DecisionBlock || decision == model.DecisionError {
		return true
	}
	for _, finding := range findings {
		if finding.Severity == model.SeverityCritical || finding.Severity == model.SeverityHigh {
			return true
		}
	}
	return false
}

func limitFindings(findings []model.Finding, limit int) []model.Finding {
	if len(findings) == 0 || limit < 0 {
		return nil
	}
	if limit > len(findings) {
		limit = len(findings)
	}
	return append([]model.Finding(nil), findings[:limit]...)
}

func limitGraphPaths(paths []GraphPathSummary, limit int) []GraphPathSummary {
	if len(paths) == 0 || limit < 0 {
		return nil
	}
	if limit > len(paths) {
		limit = len(paths)
	}
	return append([]GraphPathSummary(nil), paths[:limit]...)
}

func limitAttackPaths(paths []AttackPathSummary, limit int) []AttackPathSummary {
	if len(paths) == 0 || limit < 0 {
		return nil
	}
	if limit > len(paths) {
		limit = len(paths)
	}
	return append([]AttackPathSummary(nil), paths[:limit]...)
}

func sortedDecisionReasons(reasons []model.DecisionReason) []model.DecisionReason {
	out := append([]model.DecisionReason(nil), reasons...)
	sort.SliceStable(out, func(i int, j int) bool {
		for _, cmp := range []int{
			strings.Compare(out[i].Resource, out[j].Resource),
			strings.Compare(out[i].FindingID, out[j].FindingID),
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

func sortedDiagnostics(diagnostics []model.Diagnostic) []model.Diagnostic {
	out := append([]model.Diagnostic(nil), diagnostics...)
	sort.SliceStable(out, func(i int, j int) bool {
		for _, cmp := range []int{
			strings.Compare(string(out[i].Severity), string(out[j].Severity)),
			strings.Compare(out[i].Code, out[j].Code),
			strings.Compare(out[i].Message, out[j].Message),
		} {
			if cmp != 0 {
				return cmp < 0
			}
		}
		return false
	})
	return out
}

func sortedReasonCodes(codes []model.DecisionReasonCode) []model.DecisionReasonCode {
	values := make([]string, 0, len(codes))
	for _, code := range codes {
		values = append(values, string(code))
	}
	values = dedupeSorted(values)
	out := make([]model.DecisionReasonCode, 0, len(values))
	for _, value := range values {
		out = append(out, model.DecisionReasonCode(value))
	}
	return out
}

func countUniqueByCategory(findings []model.Finding, category model.RiskCategory) int {
	seen := make(map[string]bool)
	for _, finding := range findings {
		if finding.Category == category {
			seen[finding.ResourceAddress] = true
		}
	}
	return len(seen)
}

func countIAMFindings(findings []model.Finding) int {
	seen := make(map[string]bool)
	for _, finding := range findings {
		if finding.Category == model.RiskCategoryPrivilegeEscalation || strings.HasPrefix(finding.RuleID, "AWS_IAM_") || containsFold(finding.RuleID, "PASSROLE") || containsFold(finding.RuleID, "ASSUME") {
			seen[finding.ResourceAddress] = true
		}
	}
	return len(seen)
}

func countNetworkFindings(findings []model.Finding) int {
	seen := make(map[string]bool)
	for _, finding := range findings {
		if finding.Category == model.RiskCategoryNetworkBlastRadius || finding.Category == model.RiskCategoryPublicExposure {
			seen[finding.ResourceAddress] = true
		}
	}
	return len(seen)
}

func hasReason(finding model.Finding, code model.DecisionReasonCode) bool {
	for _, reason := range finding.DecisionReasonCodes {
		if reason == code {
			return true
		}
	}
	return false
}

func hasActiveSuppression(finding model.Finding, kind string) bool {
	for _, suppression := range finding.Suppressions {
		if suppression.Kind == kind && suppression.Active {
			return true
		}
	}
	return false
}

func hasExpiredSuppression(finding model.Finding, kind string) bool {
	for _, suppression := range finding.Suppressions {
		if suppression.Kind == kind && !suppression.Active {
			return true
		}
	}
	return false
}

func decisionForFinding(decision model.Decision, finding model.Finding) model.Decision {
	if hasReason(finding, model.ReasonMeetsBlockThreshold) {
		return decision
	}
	if hasReason(finding, model.ReasonBelowBlockThreshold) {
		return model.DecisionWarn
	}
	return model.DecisionAllow
}

func isGraphEvidence(evidence model.Evidence) bool {
	lowerType := strings.ToLower(evidence.Type)
	lowerPath := strings.ToLower(evidence.Path)
	return strings.Contains(lowerType, "graph") || strings.Contains(lowerPath, "graph")
}

func graphPathFromEvidence(evidence model.Evidence) []string {
	switch value := evidence.Value.(type) {
	case []string:
		return append([]string(nil), value...)
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok && text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		if value == "" {
			return nil
		}
		if strings.Contains(value, "->") {
			parts := strings.Split(value, "->")
			out := make([]string, 0, len(parts))
			for _, part := range parts {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					out = append(out, trimmed)
				}
			}
			return out
		}
		return []string{value}
	default:
		return nil
	}
}

func stableItemID(prefix string, finding model.Finding, index int) string {
	key := finding.ID
	if key == "" {
		key = finding.Fingerprint
	}
	if key == "" {
		key = finding.RuleID + "-" + finding.ResourceAddress
	}
	key = strings.ToLower(strings.TrimPrefix(key, "CHG-"))
	key = strings.ReplaceAll(key, "_", "-")
	return prefix + "-" + key + "-" + strconv.Itoa(index+1)
}

func attackPathType(finding model.Finding) string {
	if value := attackPathEvidenceValue(finding, "attack_path.type"); value != "" {
		return value
	}
	switch {
	case containsFold(finding.RuleID, "PASSROLE"):
		return "iam_passrole_escalation"
	case containsFold(finding.RuleID, "ASSUME"):
		return "iam_assume_role_escalation"
	case finding.Category == model.RiskCategoryPrivilegeEscalation:
		return "privilege_escalation"
	default:
		return "unknown"
	}
}

func attackPathEvidenceValue(finding model.Finding, evidencePath string) string {
	for _, evidence := range finding.Evidence {
		if evidence.Path == evidencePath {
			if value, ok := evidence.Value.(string); ok && value != "" {
				return value
			}
			if evidence.Message != "" {
				return evidence.Message
			}
		}
	}
	return ""
}

func compareGraphPaths(left GraphPathSummary, right GraphPathSummary) int {
	for _, cmp := range []int{
		compareInt(severityRank(right.Severity), severityRank(left.Severity)),
		compareInt(confidenceRank(right.Confidence), confidenceRank(left.Confidence)),
		strings.Compare(left.Resource, right.Resource),
		strings.Compare(left.RuleID, right.RuleID),
		strings.Compare(left.ID, right.ID),
	} {
		if cmp != 0 {
			return cmp
		}
	}
	return 0
}

func compareAttackPaths(left AttackPathSummary, right AttackPathSummary) int {
	for _, cmp := range []int{
		compareInt(severityRank(right.Severity), severityRank(left.Severity)),
		compareInt(confidenceRank(right.Confidence), confidenceRank(left.Confidence)),
		strings.Compare(left.Resource, right.Resource),
		strings.Compare(left.RuleID, right.RuleID),
		strings.Compare(left.ID, right.ID),
	} {
		if cmp != 0 {
			return cmp
		}
	}
	return 0
}

func decisionImpactRank(finding model.Finding) int {
	switch {
	case hasReason(finding, model.ReasonMeetsBlockThreshold):
		return 3
	case hasReason(finding, model.ReasonBelowBlockThreshold):
		return 2
	case hasReason(finding, model.ReasonSuppressed), hasReason(finding, model.ReasonExistingRisk):
		return 1
	default:
		return 0
	}
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidenceRank(confidence model.Confidence) int {
	switch confidence {
	case model.ConfidenceHigh:
		return 4
	case model.ConfidenceMedium:
		return 3
	case model.ConfidenceLow:
		return 2
	case model.ConfidenceUnknown:
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

func containsFold(value string, needle string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(needle))
}

func dedupeSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	out := []string{values[0]}
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
