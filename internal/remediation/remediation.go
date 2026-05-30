// Package remediation enriches findings with concrete developer fix guidance.
package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
)

// Options controls remediation enrichment.
type Options struct {
	DocsLinks map[string]string
}

// RuleExplanation is the developer-facing explanation for a rule or finding.
type RuleExplanation struct {
	RuleID        string             `json:"rule_id"`
	Title         string             `json:"title"`
	WhatHappened  string             `json:"what_happened"`
	WhyItMatters  string             `json:"why_it_matters"`
	Recommended   model.Remediation  `json:"recommended_fix"`
	Severity      model.Severity     `json:"severity"`
	Confidence    model.Confidence   `json:"confidence"`
	Category      model.RiskCategory `json:"category"`
	Provider      string             `json:"provider,omitempty"`
	References    []string           `json:"references,omitempty"`
	TemplateFound bool               `json:"template_found"`
}

// EnrichFindings adds remediation templates, snippets, next steps, and ownership hints.
func EnrichFindings(findings []model.Finding, resourceTags map[string]map[string]string, options Options) []model.Finding {
	out := make([]model.Finding, len(findings))
	for index, finding := range findings {
		out[index] = EnrichFinding(finding, resourceTags[finding.ResourceAddress], options)
	}
	return out
}

// EnrichFinding adds remediation details to one finding while preserving rule-provided guidance.
func EnrichFinding(finding model.Finding, tags map[string]string, options Options) model.Finding {
	template := TemplateFor(finding.RuleID, finding.Category)
	if finding.Remediation.Summary == "" {
		finding.Remediation.Summary = template.Summary
	}
	finding.Remediation.Steps = mergeStrings(finding.Remediation.Steps, template.Steps...)
	finding.Remediation.References = mergeStrings(finding.Remediation.References, template.References...)
	if finding.Remediation.WhyThisWorks == "" {
		finding.Remediation.WhyThisWorks = template.WhyThisWorks
	}
	if finding.Remediation.FixConfidence == "" {
		finding.Remediation.FixConfidence = template.FixConfidence
	}
	finding.Remediation.AutoFixAvailable = false
	finding.Remediation.Patches = mergePatches(finding.Remediation.Patches, template.Patches)
	finding.Remediation.NextSteps = mergeStrings(finding.Remediation.NextSteps, severityNextSteps(finding.Severity, finding.Confidence)...)
	finding.Remediation.OwnerHints = mergeStrings(finding.Remediation.OwnerHints, ownerHints(tags)...)
	finding.Remediation.Docs = mergeStrings(finding.Remediation.Docs, docsForFinding(finding, options.DocsLinks)...)
	return finding
}

// ExplainRule returns a developer explanation for a rule ID and optional finding context.
func ExplainRule(ruleID string, title string, description string, category model.RiskCategory, severity model.Severity, confidence model.Confidence, finding *model.Finding, options Options) RuleExplanation {
	template := TemplateFor(ruleID, category)
	remediation := template.Remediation()
	if finding != nil {
		enriched := EnrichFinding(*finding, nil, options)
		remediation = enriched.Remediation
	}
	what := firstNonEmpty(template.WhatHappened, description, title)
	if finding != nil {
		what = fmt.Sprintf("%s Resource: %s.", what, finding.ResourceAddress)
	}
	return RuleExplanation{
		RuleID:        ruleID,
		Title:         title,
		WhatHappened:  what,
		WhyItMatters:  firstNonEmpty(template.WhyItMatters, categoryWhy(category)),
		Recommended:   remediation,
		Severity:      severity,
		Confidence:    confidence,
		Category:      category,
		Provider:      providerForRule(ruleID),
		References:    remediation.References,
		TemplateFound: template.ID != "",
	}
}

// Template describes reusable remediation guidance.
type Template struct {
	ID            string
	Summary       string
	Steps         []string
	References    []string
	WhyThisWorks  string
	FixConfidence model.Confidence
	Patches       []model.PatchSuggestion
	WhatHappened  string
	WhyItMatters  string
}

// Remediation converts a template into the model remediation object.
func (t Template) Remediation() model.Remediation {
	return model.Remediation{
		Summary:          t.Summary,
		Steps:            append([]string(nil), t.Steps...),
		References:       append([]string(nil), t.References...),
		WhyThisWorks:     t.WhyThisWorks,
		FixConfidence:    t.FixConfidence,
		AutoFixAvailable: false,
		Patches:          append([]model.PatchSuggestion(nil), t.Patches...),
	}
}

// TemplateFor returns the most specific remediation template available.
func TemplateFor(ruleID string, category model.RiskCategory) Template {
	if template, ok := ruleTemplates[ruleID]; ok {
		return template
	}
	if template, ok := categoryTemplates[category]; ok {
		return template
	}
	return categoryTemplates[model.RiskCategoryUnknown]
}

var ruleTemplates = map[string]Template{
	"AWS_PUBLIC_ADMIN_SERVICE": {
		ID:            "AWS_PUBLIC_ADMIN_SERVICE",
		Summary:       "Use an internal load balancer, restrict ingress to trusted networks, or place the admin service behind an authenticated proxy.",
		Steps:         []string{"Set the ALB `internal` argument to `true` for private admin services.", "If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.", "Confirm downstream services are not tagged as admin or production unless the exposure is intentional."},
		WhyThisWorks:  "Removing direct public routing to admin workloads prevents unauthenticated internet clients from reaching privileged control surfaces.",
		FixConfidence: model.ConfidenceHigh,
		WhatHappened:  "The plan exposes a load balancer path that can route to an admin service.",
		WhyItMatters:  "Admin services should not be directly reachable from the public internet because they often provide privileged operational access.",
		Patches: []model.PatchSuggestion{terraformSnippet("Prefer internal ALB for admin services", "aws_lb", `resource "aws_lb" "admin" {
  internal = true

  # Keep admin listeners reachable only from private subnets or a trusted proxy.
}`)},
	},
	"AWS_SG_WORLD_OPEN_ADMIN_PORT": {
		ID:            "AWS_SG_WORLD_OPEN_ADMIN_PORT",
		Summary:       "Replace world-open admin ingress with VPN, SSM Session Manager, or a narrow trusted CIDR.",
		Steps:         []string{"Remove `0.0.0.0/0` and `::/0` from admin-port ingress rules.", "Use SSM Session Manager for instance access where possible.", "If network access is required, restrict `cidr_blocks` to a reviewed VPN or bastion CIDR."},
		WhyThisWorks:  "Narrowing admin ingress removes broad internet reachability while preserving controlled operator access.",
		FixConfidence: model.ConfidenceHigh,
		WhatHappened:  "The plan opens an administrative port to the public internet.",
		WhyItMatters:  "Public admin ports are high-value targets and are often exploited before application controls can help.",
		Patches: []model.PatchSuggestion{terraformSnippet("Restrict security group ingress", "aws_security_group", `ingress {
  description = "Admin access from VPN only"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = [var.vpn_cidr]
}`)},
	},
	"AWS_SG_WORLD_OPEN_DB_PORT": {
		ID:            "AWS_SG_WORLD_OPEN_DB_PORT",
		Summary:       "Remove public database ingress and allow only application security groups or private network CIDRs.",
		Steps:         []string{"Delete public CIDR ingress on database ports.", "Use `source_security_group_id` for application-to-database access.", "Keep database resources in private subnets."},
		WhyThisWorks:  "Database access is constrained to known workloads instead of arbitrary internet clients.",
		FixConfidence: model.ConfidenceHigh,
		Patches: []model.PatchSuggestion{terraformSnippet("Use security-group-to-security-group access", "aws_security_group_rule", `resource "aws_security_group_rule" "db_from_app" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.db.id
  source_security_group_id = aws_security_group.app.id
}`)},
	},
	"AWS_PUBLIC_RDS_INSTANCE": {
		ID:            "AWS_PUBLIC_RDS_INSTANCE",
		Summary:       "Disable public accessibility and place the database in private subnets.",
		Steps:         []string{"Set `publicly_accessible = false`.", "Use private DB subnet groups.", "Restrict security groups to application sources only."},
		WhyThisWorks:  "The database no longer receives public network exposure and is reachable only through private routing.",
		FixConfidence: model.ConfidenceHigh,
		Patches: []model.PatchSuggestion{terraformSnippet("Disable public RDS accessibility", "aws_db_instance", `resource "aws_db_instance" "customer" {
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name
}`)},
	},
	"AWS_STATEFUL_REPLACEMENT": {
		ID:            "AWS_STATEFUL_REPLACEMENT",
		Summary:       "Review the replacement plan, create a backup or snapshot, and require explicit approval before apply.",
		Steps:         []string{"Check the replacement path and confirm it is intended.", "Create a current backup or snapshot before apply.", "Plan a rollback or restore path before approving the change."},
		WhyThisWorks:  "Stateful replacements can destroy data or cause downtime; backup and approval reduce irreversible impact.",
		FixConfidence: model.ConfidenceMedium,
		Patches:       []model.PatchSuggestion{advisorySnippet("No automatic patch for stateful replacement", "Replacement semantics depend on the resource and data lifecycle. ChangeGate intentionally does not generate an automatic patch for destructive changes.")},
	},
	"AWS_RDS_REPLACEMENT_PROD": {
		ID:            "AWS_RDS_REPLACEMENT_PROD",
		Summary:       "Avoid replacing production databases unless a migration, snapshot, and restore plan are approved.",
		Steps:         []string{"Prefer in-place supported changes where possible.", "Snapshot the database immediately before apply.", "Schedule maintenance and document rollback."},
		WhyThisWorks:  "Production database replacement is treated as a data availability event, not a routine infrastructure edit.",
		FixConfidence: model.ConfidenceMedium,
		Patches:       []model.PatchSuggestion{advisorySnippet("No automatic patch for production database replacement", "The safe fix depends on engine version, migration strategy, and recovery objectives.")},
	},
}

var categoryTemplates = map[model.RiskCategory]Template{
	model.RiskCategoryPublicExposure: {
		Summary:       "Constrain public exposure to the smallest reviewed entry point.",
		Steps:         []string{"Remove public CIDRs unless internet access is required.", "Prefer private subnets, internal load balancers, or authenticated edge controls.", "Document any intentional public exposure in policy or a time-bounded waiver."},
		WhyThisWorks:  "Reducing public reachability lowers exploitability and leaves fewer assets directly reachable from the internet.",
		FixConfidence: model.ConfidenceMedium,
		Patches:       []model.PatchSuggestion{advisorySnippet("Public exposure requires review", "ChangeGate does not auto-apply exposure changes because safe CIDRs, proxy placement, and business intent are environment-specific.")},
	},
	model.RiskCategoryPrivilegeEscalation: {
		Summary:       "Reduce the permission scope to exact principals, actions, and resources required by the workload.",
		Steps:         []string{"Replace wildcard actions and resources with least-privilege statements.", "Constrain trust policies to expected principals and conditions.", "Separate deploy-time permissions from runtime permissions."},
		WhyThisWorks:  "Least privilege limits blast radius if a principal or workload is compromised.",
		FixConfidence: model.ConfidenceMedium,
		Patches: []model.PatchSuggestion{terraformSnippet("Scope IAM policy resources", "aws_iam_policy_document", `statement {
  actions   = ["s3:GetObject"]
  resources = ["${aws_s3_bucket.logs.arn}/*"]
}`)},
	},
	model.RiskCategorySensitiveData: {
		Summary:       "Protect sensitive data with private access paths, encryption, and audit logging.",
		Steps:         []string{"Enable encryption with managed or customer-managed keys.", "Enable access logging or equivalent audit telemetry.", "Restrict access to the workloads that need the data."},
		WhyThisWorks:  "Encryption, logging, and scoped access preserve confidentiality and provide evidence during incident review.",
		FixConfidence: model.ConfidenceMedium,
		Patches: []model.PatchSuggestion{terraformSnippet("Enable S3 bucket encryption", "aws_s3_bucket_server_side_encryption_configuration", `resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}`)},
	},
	model.RiskCategoryAvailability: {
		Summary:       "Add explicit backup, deletion-protection, and rollout controls before applying availability-impacting changes.",
		Steps:         []string{"Confirm the planned delete or replacement is intentional.", "Enable deletion protection where supported.", "Take a backup or snapshot and document rollback."},
		WhyThisWorks:  "Availability controls reduce the chance that a routine apply becomes an outage or data-loss event.",
		FixConfidence: model.ConfidenceMedium,
		Patches:       []model.PatchSuggestion{advisorySnippet("Availability changes require review", "ChangeGate does not auto-patch destructive or downtime-prone changes because the safe path depends on service ownership and recovery requirements.")},
	},
	model.RiskCategoryNetworkBlastRadius: {
		Summary:       "Constrain route and egress changes to the minimum networks and destinations required.",
		Steps:         []string{"Avoid broad `0.0.0.0/0` routes from sensitive networks.", "Use explicit route tables for public and private tiers.", "Review transitive connectivity through peering and transit gateways."},
		WhyThisWorks:  "Explicit routing limits unintended lateral movement and data path expansion.",
		FixConfidence: model.ConfidenceMedium,
		Patches:       []model.PatchSuggestion{advisorySnippet("Network routing requires topology review", "ChangeGate provides guidance but does not auto-patch routes because topology and ownership are environment-specific.")},
	},
	model.RiskCategoryCompliance: {
		Summary:       "Review the control-specific requirement and update the Terraform/OpenTofu resource or policy exception.",
		Steps:         []string{"Confirm whether the control applies to this environment.", "Update the resource configuration or add a time-bounded waiver with owner approval.", "Attach evidence to the pull request."},
		WhyThisWorks:  "Control-specific review keeps policy exceptions intentional and auditable.",
		FixConfidence: model.ConfidenceMedium,
		Patches:       []model.PatchSuggestion{advisorySnippet("Compliance fix depends on the control", "ChangeGate does not auto-patch generic compliance findings without a specific resource-safe template.")},
	},
	model.RiskCategoryUnknown: {
		Summary:       "Review the finding evidence and choose a resource-specific mitigation.",
		Steps:         []string{"Inspect the finding evidence.", "Identify the owning team.", "Add a targeted fix or a time-bounded waiver if the risk is accepted."},
		WhyThisWorks:  "Unknown-risk findings require human review because the risk class is not specific enough for a safe patch.",
		FixConfidence: model.ConfidenceLow,
		Patches:       []model.PatchSuggestion{advisorySnippet("No automatic patch for unknown risk", "The risk category is too broad to generate a safe Terraform/OpenTofu patch.")},
	},
}

func terraformSnippet(title string, appliesTo string, snippet string) model.PatchSuggestion {
	return model.PatchSuggestion{
		Title:        title,
		Format:       "terraform-snippet",
		Language:     "hcl",
		Snippet:      snippet,
		AppliesTo:    []string{appliesTo},
		SafeToApply:  false,
		Rationale:    "Snippet is advisory because variable names, module boundaries, and environment intent must be reviewed before use.",
		ReviewNeeded: true,
	}
}

func advisorySnippet(title string, rationale string) model.PatchSuggestion {
	return model.PatchSuggestion{
		Title:        title,
		Format:       "advisory",
		Snippet:      "",
		SafeToApply:  false,
		Rationale:    rationale,
		ReviewNeeded: true,
	}
}

func severityNextSteps(severity model.Severity, confidence model.Confidence) []string {
	if severity == model.SeverityCritical || severity == model.SeverityHigh {
		if confidence == model.ConfidenceHigh {
			return []string{"Treat as release-blocking unless a reviewer approves a time-bounded waiver.", "Attach evidence of the selected mitigation before apply."}
		}
		return []string{"Request owner review before apply.", "Validate whether missing context changes the risk."}
	}
	if severity == model.SeverityMedium {
		return []string{"Fix before merge when practical, or track with an owner and due date."}
	}
	return []string{"Review during normal infrastructure hygiene work."}
}

func ownerHints(tags map[string]string) []string {
	if len(tags) == 0 {
		return nil
	}
	keys := []string{"owner", "team", "service", "application", "app"}
	out := make([]string, 0)
	for _, key := range keys {
		if value := strings.TrimSpace(tags[key]); value != "" {
			out = append(out, key+"="+value)
		}
	}
	return out
}

func docsForFinding(finding model.Finding, links map[string]string) []string {
	if len(links) == 0 {
		return nil
	}
	var out []string
	for _, key := range []string{finding.RuleID, string(finding.Category), providerForRule(finding.RuleID), "default"} {
		if link := links[key]; link != "" {
			out = append(out, link)
		}
	}
	return out
}

func providerForRule(ruleID string) string {
	if strings.HasPrefix(ruleID, "AWS_") {
		return "aws"
	}
	if strings.HasPrefix(ruleID, "EXT_") {
		return "external"
	}
	return ""
}

func categoryWhy(category model.RiskCategory) string {
	switch category {
	case model.RiskCategoryPublicExposure:
		return "Public exposure increases the chance that a misconfiguration can be exploited directly from the internet."
	case model.RiskCategoryPrivilegeEscalation:
		return "Broad permissions or trust relationships can turn a small compromise into wider account control."
	case model.RiskCategorySensitiveData:
		return "Sensitive data needs scoped access, auditability, and encryption to reduce confidentiality and incident impact."
	case model.RiskCategoryAvailability:
		return "Availability-impacting changes can create outages or data loss if they are applied without recovery controls."
	case model.RiskCategoryNetworkBlastRadius:
		return "Network expansion can create unexpected paths between public, private, and sensitive systems."
	default:
		return "The finding requires review before deployment because ChangeGate could not prove it is safe."
	}
}

func mergeStrings(existing []string, incoming ...string) []string {
	seen := make(map[string]bool, len(existing)+len(incoming))
	out := make([]string, 0, len(existing)+len(incoming))
	for _, value := range append(existing, incoming...) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func mergePatches(existing []model.PatchSuggestion, incoming []model.PatchSuggestion) []model.PatchSuggestion {
	out := append([]model.PatchSuggestion(nil), existing...)
	seen := make(map[string]bool, len(existing)+len(incoming))
	for _, patch := range existing {
		seen[patch.Title+"|"+patch.Format] = true
	}
	for _, patch := range incoming {
		key := patch.Title + "|" + patch.Format
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, patch)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].Title < out[j].Title
	})
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
