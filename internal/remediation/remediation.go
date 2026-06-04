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
	template = mergeTemplateDefaults(template, categoryOperationalDefaults(finding.Category))
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
	if finding.Remediation.Effort == "" {
		finding.Remediation.Effort = template.Effort
	}
	if finding.Remediation.DowntimeRisk == "" {
		finding.Remediation.DowntimeRisk = template.DowntimeRisk
	}
	if !finding.Remediation.Destructive {
		finding.Remediation.Destructive = template.Destructive
	}
	finding.Remediation.AutoFixAvailable = false
	finding.Remediation.FixOptions = mergeFixOptions(finding.Remediation.FixOptions, template.FixOptions)
	finding.Remediation.TerraformHints = mergeTerraformHints(finding.Remediation.TerraformHints, template.TerraformHints)
	finding.Remediation.Patches = mergePatches(finding.Remediation.Patches, template.Patches)
	finding.Remediation.NextSteps = mergeStrings(finding.Remediation.NextSteps, severityNextSteps(finding.Severity, finding.Confidence)...)
	finding.Remediation.OwnerHints = mergeStrings(finding.Remediation.OwnerHints, ownerHints(tags)...)
	finding.Remediation.Docs = mergeStrings(finding.Remediation.Docs, docsForFinding(finding, options.DocsLinks)...)
	return finding
}

// ExplainRule returns a developer explanation for a rule ID and optional finding context.
func ExplainRule(ruleID string, title string, description string, category model.RiskCategory, severity model.Severity, confidence model.Confidence, finding *model.Finding, options Options) RuleExplanation {
	template := TemplateFor(ruleID, category)
	template = mergeTemplateDefaults(template, categoryOperationalDefaults(category))
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
	ID             string
	Summary        string
	Steps          []string
	References     []string
	WhyThisWorks   string
	FixConfidence  model.Confidence
	Effort         string
	DowntimeRisk   string
	Destructive    bool
	FixOptions     []model.FixOption
	TerraformHints []model.TerraformHint
	Patches        []model.PatchSuggestion
	WhatHappened   string
	WhyItMatters   string
}

// Remediation converts a template into the model remediation object.
func (t Template) Remediation() model.Remediation {
	return model.Remediation{
		Summary:          t.Summary,
		Steps:            append([]string(nil), t.Steps...),
		References:       append([]string(nil), t.References...),
		WhyThisWorks:     t.WhyThisWorks,
		FixConfidence:    t.FixConfidence,
		Effort:           t.Effort,
		DowntimeRisk:     t.DowntimeRisk,
		Destructive:      t.Destructive,
		AutoFixAvailable: false,
		FixOptions:       append([]model.FixOption(nil), t.FixOptions...),
		TerraformHints:   append([]model.TerraformHint(nil), t.TerraformHints...),
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
	"AWS_PUBLIC_TO_SENSITIVE_DATA_PATH": {
		ID:            "AWS_PUBLIC_TO_SENSITIVE_DATA_PATH",
		Summary:       "Break the public-to-sensitive path by removing public exposure, narrowing routing, or segmenting sensitive data access.",
		Steps:         []string{"Restrict the public entrypoint to approved CIDRs or authenticated edge controls.", "Remove direct routing from public workloads to sensitive datastores or secrets.", "Allow sensitive assets only from reviewed workload security groups and roles."},
		References:    []string{"docs/attack-paths.md"},
		WhyThisWorks:  "The attack path requires each graph edge to remain reachable; removing any required edge prevents public traffic from reaching sensitive data.",
		FixConfidence: model.ConfidenceMedium,
		WhatHappened:  "The plan creates or preserves a graph path from a public entrypoint to a sensitive datastore or secret.",
		WhyItMatters:  "A public-to-data path is higher confidence than a single misconfiguration because it shows how exposure can reach an asset that matters.",
		Patches:       []model.PatchSuggestion{advisorySnippet("Attack path requires topology review", "ChangeGate does not auto-patch multi-resource attack paths because the correct fix depends on service ownership, routing intent, and approved access patterns.")},
	},
	"AWS_PUBLIC_TO_SENSITIVE_DATASTORE": {
		ID:            "AWS_PUBLIC_TO_SENSITIVE_DATASTORE",
		Summary:       "Break the public-to-datastore path by removing public exposure, narrowing routing, or segmenting datastore access.",
		Steps:         []string{"Restrict the public entrypoint to approved CIDRs or authenticated edge controls.", "Remove direct routing from public workloads to sensitive datastores.", "Allow datastore access only from reviewed private workload security groups."},
		References:    []string{"docs/graph.md", "docs/attack-paths.md"},
		WhyThisWorks:  "The datastore is reachable only while each graph edge remains in place; removing public exposure, routing, or datastore access breaks the path.",
		FixConfidence: model.ConfidenceMedium,
		WhatHappened:  "The plan creates or preserves a graph path from a public resource to a sensitive datastore.",
		WhyItMatters:  "This is topology risk, not a missing storage control: a public-facing resource can reach a data asset that should be isolated.",
		Patches:       []model.PatchSuggestion{advisorySnippet("Datastore reachability requires topology review", "ChangeGate does not auto-patch public-to-datastore paths because the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.")},
	},
	"AWS_PUBLIC_ADMIN_SERVICE_PATH": {
		ID:            "AWS_PUBLIC_ADMIN_SERVICE_PATH",
		Summary:       "Remove public reachability to the admin workload or put it behind a reviewed private or authenticated access path.",
		Steps:         []string{"Make the load balancer internal when the service is administrative.", "Restrict ingress to VPN, zero-trust proxy, or approved operator CIDRs.", "Confirm service tags and ownership metadata reflect the intended exposure."},
		References:    []string{"docs/attack-paths.md"},
		WhyThisWorks:  "Admin workloads should require controlled operator access instead of direct internet reachability.",
		FixConfidence: model.ConfidenceMedium,
		WhatHappened:  "The plan creates or preserves a public path to an admin-like workload.",
		WhyItMatters:  "Admin surfaces often provide privileged operations, so public reachability materially increases exploitability.",
		Patches:       []model.PatchSuggestion{advisorySnippet("Admin exposure requires review", "ChangeGate does not auto-patch admin-service exposure because the safe access pattern depends on the team's operator model.")},
	},
	"AWS_IAM_PASSROLE_FUNCTION_ESCALATION": {
		ID:            "AWS_IAM_PASSROLE_FUNCTION_ESCALATION",
		Summary:       "Separate compute mutation from role passing, or scope iam:PassRole to only the exact execution roles this principal must use.",
		Steps:         []string{"Remove wildcard `iam:PassRole` grants.", "Restrict function or service mutation actions to explicitly owned resources.", "Use conditions such as `iam:PassedToService` where appropriate."},
		References:    []string{"docs/attack-paths.md"},
		WhyThisWorks:  "Privilege escalation requires both the ability to change executable compute and the ability to attach or pass a more privileged role.",
		FixConfidence: model.ConfidenceMedium,
		WhatHappened:  "The plan grants a principal both role-passing capability and compute mutation capability.",
		WhyItMatters:  "That combination can let a lower-privileged principal run code with a stronger execution role.",
		Patches:       []model.PatchSuggestion{advisorySnippet("IAM escalation requires least-privilege review", "ChangeGate does not rewrite IAM policies automatically because safe permissions depend on the deployment workflow and resource ownership.")},
	},
	"AWS_IAM_ASSUME_ADMIN_PATH": {
		ID:            "AWS_IAM_ASSUME_ADMIN_PATH",
		Summary:       "Constrain sts:AssumeRole trust and permissions so the source principal cannot assume admin or sensitive roles.",
		Steps:         []string{"Restrict trust policies to exact principals and expected conditions.", "Avoid administrator policy attachment on roles that are assumable from deploy or external identities.", "Add explicit boundaries where role assumption is required."},
		References:    []string{"docs/attack-paths.md"},
		WhyThisWorks:  "Removing the trust edge or admin destination breaks the role-assumption path before the principal can escalate.",
		FixConfidence: model.ConfidenceMedium,
		WhatHappened:  "The plan creates or preserves a path from a principal to an admin or sensitive role through sts:AssumeRole.",
		WhyItMatters:  "Assumable admin roles are a direct escalation target for CI, deploy, and federated identities.",
		Patches:       []model.PatchSuggestion{advisorySnippet("Assume-role path requires trust review", "ChangeGate does not auto-patch trust policies because the required principals and conditions are organization-specific.")},
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

func categoryOperationalDefaults(category model.RiskCategory) Template {
	switch category {
	case model.RiskCategoryPublicExposure:
		return Template{
			Effort:       "medium",
			DowntimeRisk: "medium",
			FixOptions: []model.FixOption{
				{Title: "Make the endpoint private", Description: "Move the exposed resource behind private networking or an internal load balancer.", Effort: "medium", DowntimeRisk: "medium", Preferred: true},
				{Title: "Restrict ingress", Description: "Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.", Effort: "low", DowntimeRisk: "low"},
			},
			TerraformHints: []model.TerraformHint{
				{ResourceType: "aws_security_group_rule", Attribute: "cidr_blocks", Preferred: "trusted CIDRs only", Notes: "Avoid 0.0.0.0/0 and ::/0 for administrative or data paths."},
				{ResourceType: "aws_lb", Attribute: "internal", Preferred: "true", Notes: "Admin and private services should use internal load balancers."},
			},
		}
	case model.RiskCategoryPrivilegeEscalation:
		return Template{
			Effort:       "medium",
			DowntimeRisk: "low",
			FixOptions: []model.FixOption{
				{Title: "Scope privileged actions", Description: "Replace wildcard IAM actions and resources with exact deployment permissions.", Effort: "medium", DowntimeRisk: "low", Preferred: true},
				{Title: "Split duties", Description: "Separate role-passing, trust-management, and compute-mutation permissions across different principals.", Effort: "high", DowntimeRisk: "low"},
			},
			TerraformHints: []model.TerraformHint{
				{ResourceType: "aws_iam_policy_document", Attribute: "statement.actions", Preferred: "least-privilege action list", Notes: "Review iam:PassRole, sts:AssumeRole, and compute update permissions together."},
				{ResourceType: "aws_iam_policy_document", Attribute: "statement.resources", Preferred: "specific ARNs", Notes: "Avoid '*' for privileged actions."},
			},
		}
	case model.RiskCategorySensitiveData:
		return Template{
			Effort:       "medium",
			DowntimeRisk: "low",
			FixOptions: []model.FixOption{
				{Title: "Enable protection controls", Description: "Turn on encryption, public-access blocks, and logging where supported.", Effort: "low", DowntimeRisk: "low", Preferred: true},
				{Title: "Segment access", Description: "Limit sensitive asset access to the workloads and roles that require it.", Effort: "medium", DowntimeRisk: "medium"},
			},
			TerraformHints: []model.TerraformHint{
				{ResourceType: "aws_s3_bucket_public_access_block", Attribute: "block_public_acls", Preferred: "true", Notes: "Set all S3 public access block booleans to true unless explicitly justified."},
				{ResourceType: "aws_db_instance", Attribute: "storage_encrypted", Preferred: "true", Notes: "Use KMS-backed encryption for database storage."},
			},
		}
	case model.RiskCategoryAvailability:
		return Template{
			Effort:       "medium",
			DowntimeRisk: "high",
			Destructive:  true,
			FixOptions: []model.FixOption{
				{Title: "Avoid replacement", Description: "Prefer an in-place supported change or staged migration instead of replacing stateful infrastructure.", Effort: "medium", DowntimeRisk: "medium", Preferred: true},
				{Title: "Approve replacement with recovery plan", Description: "If replacement is intentional, require a snapshot, rollback plan, and maintenance window.", Effort: "medium", DowntimeRisk: "high"},
			},
			TerraformHints: []model.TerraformHint{
				{ResourceType: "aws_db_instance", Attribute: "deletion_protection", Preferred: "true", Notes: "Use deletion protection for production stateful resources."},
				{ResourceType: "lifecycle", Attribute: "prevent_destroy", Preferred: "true", Notes: "Use when accidental replacement would be unacceptable."},
			},
		}
	default:
		return Template{
			Effort:       "unknown",
			DowntimeRisk: "unknown",
			FixOptions: []model.FixOption{
				{Title: "Review evidence", Description: "Use the finding evidence and owning team context to select a resource-specific mitigation.", Effort: "unknown", DowntimeRisk: "unknown", Preferred: true},
			},
		}
	}
}

func mergeTemplateDefaults(template Template, defaults Template) Template {
	if template.Effort == "" {
		template.Effort = defaults.Effort
	}
	if template.DowntimeRisk == "" {
		template.DowntimeRisk = defaults.DowntimeRisk
	}
	if !template.Destructive {
		template.Destructive = defaults.Destructive
	}
	template.FixOptions = mergeFixOptions(template.FixOptions, defaults.FixOptions)
	template.TerraformHints = mergeTerraformHints(template.TerraformHints, defaults.TerraformHints)
	return template
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

func mergeFixOptions(existing []model.FixOption, incoming []model.FixOption) []model.FixOption {
	out := append([]model.FixOption(nil), existing...)
	seen := make(map[string]bool, len(existing)+len(incoming))
	for _, option := range existing {
		seen[option.Title+"|"+option.Description] = true
	}
	for _, option := range incoming {
		key := option.Title + "|" + option.Description
		if strings.TrimSpace(option.Title) == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, option)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		if out[i].Preferred != out[j].Preferred {
			return out[i].Preferred
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func mergeTerraformHints(existing []model.TerraformHint, incoming []model.TerraformHint) []model.TerraformHint {
	out := append([]model.TerraformHint(nil), existing...)
	seen := make(map[string]bool, len(existing)+len(incoming))
	for _, hint := range existing {
		seen[hint.ResourceType+"|"+hint.Attribute] = true
	}
	for _, hint := range incoming {
		key := hint.ResourceType + "|" + hint.Attribute
		if key == "|" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, hint)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		return out[i].ResourceType+"|"+out[i].Attribute < out[j].ResourceType+"|"+out[j].Attribute
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
