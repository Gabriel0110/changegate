// Package review renders Review Intelligence pull request and merge request output.
package review

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/impact"
	"github.com/Gabriel0110/changegate/internal/model"
)

const (
	// DefaultStickyCommentMarker identifies the single ChangeGate review comment.
	DefaultStickyCommentMarker = "<!-- changegate-review -->"
	// DefaultMaxCommentFindings limits top findings in review comments.
	DefaultMaxCommentFindings = 10
	// DefaultMaxGraphPaths limits graph paths in review comments.
	DefaultMaxGraphPaths = 5
	// DefaultMaxAttackPaths limits attack paths in review comments.
	DefaultMaxAttackPaths = 5
	// DefaultMaxCommentBytes leaves room below common provider comment limits.
	DefaultMaxCommentBytes = 60000
)

// ArtifactLink describes an artifact included with a review comment.
type ArtifactLink struct {
	Label string
	URL   string
}

// CommentOptions controls PR/MR comment rendering.
type CommentOptions struct {
	Marker         string
	MaxFindings    int
	MaxGraphPaths  int
	MaxAttackPaths int
	MaxBytes       int
	ArtifactLinks  []ArtifactLink
}

// RenderComment renders a deterministic GitHub/GitLab-compatible Markdown review comment.
func RenderComment(statement impact.Statement, opts CommentOptions) string {
	opts = normalizeOptions(opts)
	comment := renderFullComment(statement, opts)
	if opts.MaxBytes > 0 && len(comment) > opts.MaxBytes {
		comment = renderCompactComment(statement, opts)
	}
	if opts.MaxBytes > 0 && len(comment) > opts.MaxBytes {
		comment = truncateMarkdown(comment, opts.MaxBytes)
	}
	return normalizeFinalNewline(comment)
}

func normalizeOptions(opts CommentOptions) CommentOptions {
	if opts.Marker == "" {
		opts.Marker = DefaultStickyCommentMarker
	}
	if opts.MaxFindings < 0 {
		opts.MaxFindings = 0
	}
	if opts.MaxFindings == 0 {
		opts.MaxFindings = DefaultMaxCommentFindings
	}
	if opts.MaxGraphPaths < 0 {
		opts.MaxGraphPaths = 0
	}
	if opts.MaxGraphPaths == 0 {
		opts.MaxGraphPaths = DefaultMaxGraphPaths
	}
	if opts.MaxAttackPaths < 0 {
		opts.MaxAttackPaths = 0
	}
	if opts.MaxAttackPaths == 0 {
		opts.MaxAttackPaths = DefaultMaxAttackPaths
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = DefaultMaxCommentBytes
	}
	return opts
}

func renderFullComment(statement impact.Statement, opts CommentOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", opts.Marker)
	fmt.Fprintf(&b, "## ChangeGate Infrastructure Review: %s\n\n", strings.ToUpper(string(statement.Decision)))
	fmt.Fprintf(&b, "%s\n\n", summarySentence(statement))

	b.WriteString("### Security Impact\n\n")
	writeBullets(&b, []string{
		fmt.Sprintf("Resources changed: %d", statement.Summary.ResourcesChanged),
		fmt.Sprintf("Public entrypoints added: %d", statement.Summary.PublicEntrypointsAdded),
		fmt.Sprintf("Sensitive assets touched: %d", statement.Summary.SensitiveAssetsTouched),
		fmt.Sprintf("IAM permission changes: %d", statement.Summary.IAMPermissionChanges),
		fmt.Sprintf("Network path changes: %d", statement.Summary.NetworkPathChanges),
		fmt.Sprintf("Data path changes: %d", statement.Summary.DataPathChanges),
		fmt.Sprintf("Review required: %s", yesNo(statement.ReviewRequired)),
	})

	writeRiskMovement(&b, statement)
	writeTopFindings(&b, statement, opts)
	writeGraphPaths(&b, statement, opts)
	writeAttackPaths(&b, statement, opts)
	writeWaiverBaseline(&b, statement)
	writeOwnership(&b, statement)
	writeRequiredAction(&b, statement)
	writeArtifacts(&b, opts.ArtifactLinks)
	writeDiagnostics(&b, statement)

	return b.String()
}

func renderCompactComment(statement impact.Statement, opts CommentOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", opts.Marker)
	fmt.Fprintf(&b, "## ChangeGate Infrastructure Review: %s\n\n", strings.ToUpper(string(statement.Decision)))
	fmt.Fprintf(&b, "%s\n\n", summarySentence(statement))
	writeBullets(&b, []string{
		fmt.Sprintf("Blocking findings shown: %d of %d total top findings", min(len(statement.TopFindings), 3), len(statement.TopFindings)),
		fmt.Sprintf("New critical/high risks: %d", statement.RiskMovement.NewCritical+statement.RiskMovement.NewHigh),
		fmt.Sprintf("Existing worsened risks: %d", statement.RiskMovement.ExistingWorsened),
		fmt.Sprintf("Active waivers: %d", statement.Waivers.Active),
	})
	if len(statement.TopFindings) > 0 {
		b.WriteString("### Top Findings\n\n")
		for index, finding := range statement.TopFindings {
			if index >= 3 {
				break
			}
			fmt.Fprintf(&b, "- `%s` `%s/%s` %s on `%s`\n", finding.RuleID, finding.Severity, finding.Confidence, safeInline(finding.Title), safeInline(finding.ResourceAddress))
		}
		b.WriteString("\n")
	}
	b.WriteString("_Comment compacted because the full review exceeded the configured provider size limit._\n")
	return b.String()
}

func summarySentence(statement impact.Statement) string {
	switch statement.Decision {
	case model.DecisionAllow:
		if len(statement.TopFindings) == 0 {
			return "No blocking infrastructure risks were detected for this change."
		}
		return fmt.Sprintf("This change is allowed with %d non-blocking finding%s for reviewer awareness.", len(statement.TopFindings), plural(len(statement.TopFindings)))
	case model.DecisionWarn:
		return fmt.Sprintf("This change introduces %d warning finding%s that should be reviewed before apply.", len(statement.TopFindings), plural(len(statement.TopFindings)))
	case model.DecisionBlock:
		return fmt.Sprintf("This change introduces %d blocking infrastructure risk%s and requires remediation or an approved waiver.", countBlockingFindings(statement.TopFindings), plural(countBlockingFindings(statement.TopFindings)))
	case model.DecisionError:
		return "ChangeGate could not complete the review reliably. Treat this as a failed infrastructure review."
	default:
		return "This change requires manual infrastructure security review before apply."
	}
}

func writeRiskMovement(b *strings.Builder, statement impact.Statement) {
	b.WriteString("### Risk Movement\n\n")
	writeBullets(b, []string{
		fmt.Sprintf("New critical risks: %d", statement.RiskMovement.NewCritical),
		fmt.Sprintf("New high risks: %d", statement.RiskMovement.NewHigh),
		fmt.Sprintf("New medium risks: %d", statement.RiskMovement.NewMedium),
		fmt.Sprintf("Existing unchanged risks: %d", statement.RiskMovement.ExistingUnchanged),
		fmt.Sprintf("Existing worsened risks: %d", statement.RiskMovement.ExistingWorsened),
		fmt.Sprintf("Existing improved risks: %d", statement.RiskMovement.ExistingImproved),
		fmt.Sprintf("Resolved critical/high risks: %d", statement.RiskMovement.ResolvedCritical+statement.RiskMovement.ResolvedHigh),
	})
}

func writeTopFindings(b *strings.Builder, statement impact.Statement, opts CommentOptions) {
	if len(statement.TopFindings) == 0 {
		b.WriteString("### Top Findings\n\nNo findings.\n\n")
		return
	}
	b.WriteString("### Top Findings\n\n")
	limit := boundedLimit(len(statement.TopFindings), opts.MaxFindings)
	for index, finding := range statement.TopFindings[:limit] {
		fmt.Fprintf(b, "%d. `%s` `%s/%s` %s on `%s`\n", index+1, finding.RuleID, finding.Severity, finding.Confidence, safeInline(finding.Title), safeInline(finding.ResourceAddress))
		if finding.Remediation.Summary != "" {
			fmt.Fprintf(b, "   - Fix: %s\n", safeInline(finding.Remediation.Summary))
		}
		if len(finding.Remediation.OwnerHints) > 0 {
			fmt.Fprintf(b, "   - Owner hints: `%s`\n", strings.Join(safeInlineSlice(finding.Remediation.OwnerHints), "`, `"))
		}
	}
	if len(statement.TopFindings) > limit {
		fmt.Fprintf(b, "\n%d additional finding%s omitted from the summary.\n", len(statement.TopFindings)-limit, plural(len(statement.TopFindings)-limit))
	}
	b.WriteString("\n<details>\n<summary>Finding details</summary>\n\n")
	for _, finding := range statement.TopFindings[:limit] {
		fmt.Fprintf(b, "#### `%s` %s\n\n", finding.RuleID, safeInline(finding.Title))
		fmt.Fprintf(b, "- Resource: `%s`\n", safeInline(finding.ResourceAddress))
		fmt.Fprintf(b, "- Severity/confidence: `%s/%s`\n", finding.Severity, finding.Confidence)
		if finding.Description != "" {
			fmt.Fprintf(b, "- Why this matters: %s\n", safeInline(finding.Description))
		}
		for _, evidence := range finding.Evidence {
			if evidence.Message != "" {
				fmt.Fprintf(b, "- Evidence: %s\n", safeInline(evidence.Message))
			}
		}
		for _, step := range finding.Remediation.Steps {
			fmt.Fprintf(b, "- Remediation: %s\n", safeInline(step))
		}
		b.WriteString("\n")
	}
	b.WriteString("</details>\n\n")
}

func writeGraphPaths(b *strings.Builder, statement impact.Statement, opts CommentOptions) {
	if len(statement.TopGraphPaths) == 0 {
		return
	}
	b.WriteString("### Top Blast Radius\n\n")
	limit := boundedLimit(len(statement.TopGraphPaths), opts.MaxGraphPaths)
	for _, path := range statement.TopGraphPaths[:limit] {
		if len(path.Path) > 0 {
			fmt.Fprintf(b, "- `%s`\n", safeInline(strings.Join(path.Path, " -> ")))
		} else {
			fmt.Fprintf(b, "- `%s` %s\n", safeInline(path.Resource), safeInline(path.Title))
		}
		if path.Description != "" {
			fmt.Fprintf(b, "  - Why this matters: %s\n", safeInline(path.Description))
		}
	}
	if len(statement.TopGraphPaths) > limit {
		fmt.Fprintf(b, "- ... %d more graph path%s\n", len(statement.TopGraphPaths)-limit, plural(len(statement.TopGraphPaths)-limit))
	}
	b.WriteString("\n")
}

func writeAttackPaths(b *strings.Builder, statement impact.Statement, opts CommentOptions) {
	if len(statement.AttackPaths) == 0 {
		return
	}
	b.WriteString("### Attack Paths\n\n")
	limit := boundedLimit(len(statement.AttackPaths), opts.MaxAttackPaths)
	for _, path := range statement.AttackPaths[:limit] {
		fmt.Fprintf(b, "- `%s` `%s/%s` %s\n", path.RuleID, path.Severity, path.Confidence, safeInline(path.Title))
		if len(path.Steps) > 0 {
			fmt.Fprintf(b, "  - Path: `%s`\n", safeInline(strings.Join(path.Steps, " -> ")))
		}
	}
	if len(statement.AttackPaths) > limit {
		fmt.Fprintf(b, "- ... %d more attack path%s\n", len(statement.AttackPaths)-limit, plural(len(statement.AttackPaths)-limit))
	}
	b.WriteString("\n")
}

func writeWaiverBaseline(b *strings.Builder, statement impact.Statement) {
	b.WriteString("### Waivers and Baseline\n\n")
	writeBullets(b, []string{
		fmt.Sprintf("Active waivers: %d", statement.Waivers.Active),
		fmt.Sprintf("Expired waivers: %d", statement.Waivers.Expired),
		fmt.Sprintf("Existing baseline findings: %d", statement.Baseline.ExistingFindings),
		fmt.Sprintf("New findings: %d", statement.Baseline.NewFindings),
	})
}

func writeOwnership(b *strings.Builder, statement impact.Statement) {
	if len(statement.Ownership) == 0 {
		return
	}
	b.WriteString("### Ownership\n\n")
	for _, owner := range statement.Ownership {
		if owner.Resource == "" {
			fmt.Fprintf(b, "- `%s`\n", safeInline(owner.Owner))
			continue
		}
		fmt.Fprintf(b, "- `%s` owns `%s`\n", safeInline(owner.Owner), safeInline(owner.Resource))
	}
	b.WriteString("\n")
}

func writeRequiredAction(b *strings.Builder, statement impact.Statement) {
	b.WriteString("### Required Action\n\n")
	if len(statement.RequiredReviewers) > 0 {
		for _, requirement := range statement.RequiredReviewers {
			fmt.Fprintf(b, "- `%s`: %s\n", safeInline(requirement.Reviewer), safeInline(requirement.Reason))
		}
	}
	if len(statement.TopFindings) == 0 {
		b.WriteString("- No remediation required by ChangeGate.\n\n")
		return
	}
	seen := make(map[string]bool)
	for _, finding := range statement.TopFindings {
		if finding.Remediation.Summary == "" || seen[finding.Remediation.Summary] {
			continue
		}
		seen[finding.Remediation.Summary] = true
		fmt.Fprintf(b, "- %s\n", safeInline(finding.Remediation.Summary))
	}
	if len(seen) == 0 && len(statement.RequiredReviewers) == 0 {
		b.WriteString("- Review the top findings and attach remediation evidence before apply.\n")
	}
	b.WriteString("\n")
}

func writeArtifacts(b *strings.Builder, links []ArtifactLink) {
	clean := make([]ArtifactLink, 0, len(links))
	for _, link := range links {
		if link.Label == "" || link.URL == "" {
			continue
		}
		clean = append(clean, link)
	}
	if len(clean) == 0 {
		return
	}
	sort.SliceStable(clean, func(i int, j int) bool {
		return clean[i].Label < clean[j].Label
	})
	b.WriteString("### Artifacts\n\n")
	for _, link := range clean {
		fmt.Fprintf(b, "- [%s](%s)\n", safeInline(link.Label), safeURL(link.URL))
	}
	b.WriteString("\n")
}

func writeDiagnostics(b *strings.Builder, statement impact.Statement) {
	if len(statement.Diagnostics) == 0 {
		return
	}
	b.WriteString("<details>\n<summary>Diagnostics</summary>\n\n")
	for _, diagnostic := range statement.Diagnostics {
		fmt.Fprintf(b, "- `%s` `%s`: %s\n", diagnostic.Severity, diagnostic.Code, safeInline(diagnostic.Message))
	}
	b.WriteString("\n</details>\n")
}

func writeBullets(b *strings.Builder, values []string) {
	for _, value := range values {
		fmt.Fprintf(b, "- %s\n", safeInline(value))
	}
	b.WriteString("\n")
}

func countBlockingFindings(findings []model.Finding) int {
	count := 0
	for _, finding := range findings {
		for _, code := range finding.DecisionReasonCodes {
			if code == model.ReasonMeetsBlockThreshold {
				count++
				break
			}
		}
	}
	if count == 0 {
		return len(findings)
	}
	return count
}

func boundedLimit(length int, limit int) int {
	if limit < 0 {
		return 0
	}
	if limit > length {
		return length
	}
	return limit
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func plural(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func safeInline(value string) string {
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "<!--", "&lt;!--")
	value = strings.ReplaceAll(value, "-->", "--&gt;")
	value = strings.ReplaceAll(value, "<script", "&lt;script")
	value = strings.ReplaceAll(value, "</script", "&lt;/script")
	return strings.TrimSpace(value)
}

func safeInlineSlice(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, safeInline(value))
	}
	return out
}

func safeURL(value string) string {
	value = safeInline(value)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return value
	}
	return "#"
}

func truncateMarkdown(value string, maxBytes int) string {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	suffix := "\n\n_Comment truncated because it exceeded the configured provider size limit._\n"
	limit := maxBytes - len(suffix)
	if limit <= 0 {
		return suffix[:maxBytes]
	}
	var b strings.Builder
	for _, r := range value {
		next := string(r)
		if b.Len()+len(next) > limit {
			break
		}
		b.WriteString(next)
	}
	b.WriteString(suffix)
	return b.String()
}

func normalizeFinalNewline(value string) string {
	return strings.TrimRight(value, "\n") + "\n"
}
