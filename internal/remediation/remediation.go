// Package remediation enriches findings with concrete developer fix guidance.
package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
)

const (
	attackPathsDocsURL = "https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md"
	graphDocsURL       = "https://github.com/Gabriel0110/changegate/blob/main/docs/graph.md"
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
	if externalVulnerabilityFinding(finding) {
		template = externalVulnerabilityTemplate(finding)
	} else {
		template = mergeTemplateDefaults(template, categoryOperationalDefaults(finding.Category))
	}
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

func externalVulnerabilityFinding(finding model.Finding) bool {
	if finding.Provider != "external" {
		return false
	}
	for _, evidence := range finding.Evidence {
		if evidence.Type == "external_vulnerability" {
			return true
		}
	}
	return false
}

func externalVulnerabilityTemplate(finding model.Finding) Template {
	references := append([]string(nil), finding.Remediation.References...)
	return Template{
		ID:              finding.RuleID,
		Summary:         firstNonEmpty(finding.Remediation.Summary, "Upgrade or replace the affected package version, or document an accepted vulnerability exception with an owner and expiration."),
		Steps:           []string{"Upgrade the affected package to a fixed version when one is available.", "Rebuild and rescan the artifact that produced the imported vulnerability finding.", "Use a time-bounded waiver only when the vulnerability is not exploitable in the deployed context."},
		References:      references,
		WhyThisWorks:    "Package vulnerability findings are resolved by removing the vulnerable version or documenting a reviewed, time-bounded risk acceptance.",
		FixConfidence:   model.ConfidenceMedium,
		Effort:          "medium",
		DowntimeRisk:    "low",
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Upgrade package", Description: "Move the affected dependency or OS package to a fixed version and regenerate the scanner output.", Effort: "medium", DowntimeRisk: "low", Preferred: true},
			{Title: "Accept with expiration", Description: "Use a waiver only when compensating controls or non-exploitability are documented.", Effort: "low", DowntimeRisk: "low"},
		},
		Patches: []model.PatchSuggestion{advisorySnippet("Package vulnerability requires dependency update", "ChangeGate does not auto-patch imported package vulnerabilities because the safe update path depends on the package manager, base image, and compatibility requirements.")},
	}
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
	ID              string
	Summary         string
	Steps           []string
	References      []string
	WhyThisWorks    string
	FixConfidence   model.Confidence
	Effort          string
	DowntimeRisk    string
	Destructive     bool
	ReplaceDefaults bool
	FixOptions      []model.FixOption
	TerraformHints  []model.TerraformHint
	Patches         []model.PatchSuggestion
	WhatHappened    string
	WhyItMatters    string
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
	"AWS_LAMBDA_PUBLIC_FUNCTION_URL": {
		ID:              "AWS_LAMBDA_PUBLIC_FUNCTION_URL",
		Summary:         "Use AWS_IAM authorization or move the function behind an authenticated API layer.",
		Steps:           []string{"Set the Lambda function URL `authorization_type` to `AWS_IAM` when callers can sign requests.", "If anonymous access is required, put the function behind API Gateway, CloudFront, WAF, or another reviewed edge control.", "Document any intentionally public function URL with owner approval and monitoring coverage."},
		WhyThisWorks:    "Authenticated entry points prevent arbitrary internet clients from invoking the function directly.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Require IAM authorization", Description: "Set the function URL authorization type to AWS_IAM for signed callers.", Effort: "low", DowntimeRisk: "low", Preferred: true},
			{Title: "Move behind a reviewed edge layer", Description: "Use API Gateway, CloudFront, WAF, or an application gateway when anonymous internet access is intentional.", Effort: "medium", DowntimeRisk: "medium"},
		},
		WhatHappened: "The plan exposes a Lambda function URL without authentication.",
		WhyItMatters: "Unauthenticated function URLs are direct public entry points; risk increases when the function can reach secrets, data stores, or privileged APIs.",
		Patches: []model.PatchSuggestion{terraformSnippet("Require IAM authorization for Lambda Function URL", "aws_lambda_function_url", `resource "aws_lambda_function_url" "public_handler" {
  authorization_type = "AWS_IAM"
}`)},
	},
	"AWS_S3_BUCKET_PUBLIC_POLICY": {
		ID:              "AWS_S3_BUCKET_PUBLIC_POLICY",
		Summary:         "Remove public principals from the bucket policy or scope access through CloudFront origin access control.",
		Steps:           []string{"Remove `Principal: \"*\"` statements that grant S3 read or write access.", "Use CloudFront origin access control, a specific AWS principal, or an application role instead of public bucket policy access.", "Keep public access block enabled unless the bucket is intentionally public and reviewed."},
		WhyThisWorks:    "Removing public principals prevents direct anonymous S3 access while still allowing reviewed service-to-bucket access paths.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Remove public bucket policy grants", Description: "Delete or narrow public principals and wildcard S3 actions from the bucket policy.", Effort: "low", DowntimeRisk: "low", Preferred: true},
			{Title: "Use CloudFront origin access control", Description: "Serve content through CloudFront while keeping the bucket private.", Effort: "medium", DowntimeRisk: "medium"},
		},
		WhatHappened: "The bucket policy grants public read or write access.",
		WhyItMatters: "Public S3 policies can expose data directly, bypassing intended application, CloudFront, or identity controls.",
	},
	"AWS_S3_BUCKET_PUBLIC_ACL": {
		ID:              "AWS_S3_BUCKET_PUBLIC_ACL",
		Summary:         "Replace public ACLs with private ACLs and policy-scoped access.",
		Steps:           []string{"Set the bucket ACL to `private`.", "Remove grants to AllUsers or AuthenticatedUsers.", "Prefer bucket policies scoped to exact service principals over ACL-based public access."},
		WhyThisWorks:    "Private ACLs remove legacy anonymous access grants from the bucket.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Make ACL private", Description: "Set the ACL to `private` and remove public grants.", Effort: "low", DowntimeRisk: "low", Preferred: true},
		},
	},
	"AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD": {
		ID:              "AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD",
		Summary:         "Enable all S3 public access block controls for production buckets.",
		Steps:           []string{"Set `block_public_acls`, `block_public_policy`, `ignore_public_acls`, and `restrict_public_buckets` to `true`.", "Review any intentionally public production bucket through a policy exception or waiver.", "Confirm dependent CloudFront or application access uses private origin or scoped IAM access."},
		WhyThisWorks:    "S3 public access block prevents accidental public ACLs and policies from exposing production bucket contents.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Enable public access block", Description: "Turn on all public access block settings for the bucket.", Effort: "low", DowntimeRisk: "low", Preferred: true},
		},
	},
	"AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA": {
		ID:              "AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA",
		Summary:         "Require authentication on the Lambda function URL or remove the function's downstream sensitive-data access.",
		Steps:           []string{"Set the function URL `authorization_type` to `AWS_IAM` or place it behind an authenticated edge layer.", "Remove secret, KMS, datastore, or bucket access that is not required by this public handler.", "If the function must stay public, split sensitive operations into a private worker role or separate function."},
		References:      []string{attackPathsDocsURL},
		WhyThisWorks:    "The path requires both public invocation and downstream sensitive-data access; removing either step breaks the exposure path.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Authenticate the public entrypoint", Description: "Require IAM-signed requests or put the Lambda behind an authenticated API/edge layer.", Effort: "low", DowntimeRisk: "low", Preferred: true},
			{Title: "Split public and private work", Description: "Keep public request handling separate from the role or function that can read sensitive data.", Effort: "medium", DowntimeRisk: "medium"},
		},
		WhatHappened: "The plan exposes a Lambda function URL that invokes code with graph-backed access to sensitive data.",
		WhyItMatters: "This is stronger evidence than a standalone public endpoint finding because ChangeGate can trace the path from internet access to the sensitive asset.",
		Patches: []model.PatchSuggestion{terraformSnippet("Require IAM authorization for Lambda Function URL", "aws_lambda_function_url", `resource "aws_lambda_function_url" "public_handler" {
  authorization_type = "AWS_IAM"
}`)},
	},
	"AWS_PUBLIC_WORKLOAD_READS_SECRET": {
		ID:              "AWS_PUBLIC_WORKLOAD_READS_SECRET",
		Summary:         "Remove public reachability from the workload or move secret access to a private execution path.",
		Steps:           []string{"Remove unauthenticated public entry points that invoke the workload.", "Scope `secretsmanager:GetSecretValue` to only the secret and role that require it.", "Split public request handling from private secret access when the endpoint must remain internet-facing."},
		References:      []string{attackPathsDocsURL},
		WhyThisWorks:    "The secret is reachable only while the workload is publicly invokable and allowed to read the secret; removing either condition breaks the path.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Break public invocation", Description: "Remove anonymous/public routes to the workload or require authenticated ingress.", Effort: "low", DowntimeRisk: "low", Preferred: true},
			{Title: "Move secret access private", Description: "Use a private worker or narrower role for the code path that reads the secret.", Effort: "medium", DowntimeRisk: "medium"},
		},
		WhatHappened: "The plan creates or preserves a graph path from an internet-exposed workload to a Secrets Manager secret.",
		WhyItMatters: "Public workloads with secret access can turn a request-handling flaw into credential or data exposure.",
		Patches:      []model.PatchSuggestion{advisorySnippet("Secret-access path requires workload review", "ChangeGate does not auto-patch secret access paths because the safe fix depends on caller authentication, role boundaries, and workload ownership.")},
	},
	"AWS_PUBLIC_API_GATEWAY_TO_SENSITIVE_DATA": {
		ID:              "AWS_PUBLIC_API_GATEWAY_TO_SENSITIVE_DATA",
		Summary:         "Require authorization on the API route or remove the downstream sensitive-data access.",
		Steps:           []string{"Set API Gateway route authorization to IAM, JWT, Cognito, or a reviewed custom authorizer.", "Confirm only authenticated routes can invoke workloads that read secrets, KMS keys, buckets, or datastores.", "Split public request handling from sensitive operations when the route must remain internet-facing."},
		References:      []string{attackPathsDocsURL},
		WhyThisWorks:    "The path requires both unauthenticated API reachability and downstream sensitive-data access; removing either condition breaks the exposure path.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Require route authorization", Description: "Use IAM, JWT, Cognito, or a reviewed authorizer for the public API route.", Effort: "low", DowntimeRisk: "low", Preferred: true},
			{Title: "Move sensitive access private", Description: "Keep public API handlers separate from workers or roles that can reach sensitive data.", Effort: "medium", DowntimeRisk: "medium"},
		},
		WhatHappened: "The graph shows an unauthenticated public API route invoking a workload that can reach sensitive data.",
		WhyItMatters: "This is a concrete public-to-sensitive path, not just a public endpoint setting.",
	},
	"AWS_PUBLIC_WORKLOAD_KMS_KEY_ACCESS": {
		ID:              "AWS_PUBLIC_WORKLOAD_KMS_KEY_ACCESS",
		Summary:         "Remove public reachability from the workload or scope KMS decrypt access to a private execution path.",
		Steps:           []string{"Restrict the public entrypoint with authentication or approved CIDRs.", "Scope `kms:Decrypt` to the exact key and private workload role that requires it.", "Separate public request handling from code paths that decrypt sensitive data."},
		References:      []string{attackPathsDocsURL},
		WhyThisWorks:    "The key is at risk only while the workload is publicly reachable and has decrypt capability; removing either condition breaks the path.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Constrain KMS decrypt access", Description: "Limit decrypt permission to the smallest private workload role and exact key.", Effort: "medium", DowntimeRisk: "low", Preferred: true},
			{Title: "Break public invocation", Description: "Require authenticated ingress or move decrypt operations behind a private worker.", Effort: "medium", DowntimeRisk: "medium"},
		},
		WhatHappened: "The graph shows an internet-exposed workload with access to a sensitive KMS key.",
		WhyItMatters: "Publicly reachable code with decrypt access can become a data exposure path if the workload is compromised.",
	},
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
		ID:              "AWS_PUBLIC_TO_SENSITIVE_DATA_PATH",
		Summary:         "Break the public-to-sensitive path by removing public exposure, narrowing routing, or segmenting sensitive data access.",
		Steps:           []string{"Restrict the public entrypoint to approved CIDRs or authenticated edge controls.", "Remove direct routing from public workloads to sensitive datastores or secrets.", "Allow sensitive assets only from reviewed workload security groups and roles."},
		References:      []string{attackPathsDocsURL},
		WhyThisWorks:    "The attack path requires each graph edge to remain reachable; removing any required edge prevents public traffic from reaching sensitive data.",
		FixConfidence:   model.ConfidenceMedium,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Break the reachable path", Description: "Remove one required edge between the public entrypoint, workload, and sensitive asset.", Effort: "medium", DowntimeRisk: "medium", Preferred: true},
			{Title: "Constrain sensitive access", Description: "Allow the sensitive asset only from reviewed private workload identities or security groups.", Effort: "medium", DowntimeRisk: "low"},
		},
		WhatHappened: "The plan creates or preserves a graph path from a public entrypoint to a sensitive datastore or secret.",
		WhyItMatters: "A public-to-data path is higher confidence than a single misconfiguration because it shows how exposure can reach an asset that matters.",
		Patches:      []model.PatchSuggestion{advisorySnippet("Attack path requires topology review", "ChangeGate does not auto-patch multi-resource attack paths because the correct fix depends on service ownership, routing intent, and approved access patterns.")},
	},
	"AWS_PUBLIC_TO_SENSITIVE_DATASTORE": {
		ID:              "AWS_PUBLIC_TO_SENSITIVE_DATASTORE",
		Summary:         "Break the public-to-datastore path by removing public exposure, narrowing routing, or segmenting datastore access.",
		Steps:           []string{"Restrict the public entrypoint to approved CIDRs or authenticated edge controls.", "Remove direct routing from public workloads to sensitive datastores.", "Allow datastore access only from reviewed private workload security groups."},
		References:      []string{graphDocsURL, attackPathsDocsURL},
		WhyThisWorks:    "The datastore is reachable only while each graph edge remains in place; removing public exposure, routing, or datastore access breaks the path.",
		FixConfidence:   model.ConfidenceMedium,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Remove datastore reachability", Description: "Eliminate the route, security-group edge, or identity edge that lets the public path reach the datastore.", Effort: "medium", DowntimeRisk: "medium", Preferred: true},
			{Title: "Allow only private workload access", Description: "Restrict datastore access to reviewed private workload security groups or roles.", Effort: "medium", DowntimeRisk: "low"},
		},
		WhatHappened: "The plan creates or preserves a graph path from a public resource to a sensitive datastore.",
		WhyItMatters: "This is topology risk, not a missing storage control: a public-facing resource can reach a data asset that should be isolated.",
		Patches:      []model.PatchSuggestion{advisorySnippet("Datastore reachability requires topology review", "ChangeGate does not auto-patch public-to-datastore paths because the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.")},
	},
	"AWS_PUBLIC_ADMIN_SERVICE_PATH": {
		ID:            "AWS_PUBLIC_ADMIN_SERVICE_PATH",
		Summary:       "Remove public reachability to the admin workload or put it behind a reviewed private or authenticated access path.",
		Steps:         []string{"Make the load balancer internal when the service is administrative.", "Restrict ingress to VPN, zero-trust proxy, or approved operator CIDRs.", "Confirm service tags and ownership metadata reflect the intended exposure."},
		References:    []string{attackPathsDocsURL},
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
		References:    []string{attackPathsDocsURL},
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
		References:    []string{attackPathsDocsURL},
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
	"AWS_RDS_BACKUP_RETENTION_DISABLED_PROD": {
		ID:              "AWS_RDS_BACKUP_RETENTION_DISABLED_PROD",
		Summary:         "Set backup retention to a non-zero period aligned with recovery requirements.",
		Steps:           []string{"Set `backup_retention_period` to the required production value.", "Confirm backup windows and retention meet the service recovery objective.", "Apply through the normal database change process."},
		WhyThisWorks:    "A non-zero retention period preserves restorable backups for production recovery.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Enable production backup retention", Description: "Set `backup_retention_period` to an approved non-zero value for the database or cluster.", Effort: "low", DowntimeRisk: "low", Preferred: true},
		},
	},
	"AWS_RDS_BACKUP_RETENTION_REDUCED_PROD": {
		ID:              "AWS_RDS_BACKUP_RETENTION_REDUCED_PROD",
		Summary:         "Keep production backup retention at or above the approved recovery window.",
		Steps:           []string{"Restore `backup_retention_period` to the previous or approved value.", "Confirm the reduction does not violate recovery requirements.", "Document any intentional retention reduction with approval."},
		WhyThisWorks:    "Maintaining the approved retention window keeps restore coverage intact after deployment.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Restore approved retention", Description: "Keep backup retention at the previous or policy-approved value.", Effort: "low", DowntimeRisk: "low", Preferred: true},
		},
	},
	"AWS_RDS_DELETION_PROTECTION_DISABLED_PROD": {
		ID:              "AWS_RDS_DELETION_PROTECTION_DISABLED_PROD",
		Summary:         "Enable deletion protection for production databases.",
		Steps:           []string{"Set `deletion_protection = true` for production databases and clusters.", "Only disable deletion protection in a reviewed teardown or migration plan.", "Keep stateful deletion controls separate from routine configuration changes."},
		WhyThisWorks:    "Deletion protection prevents accidental destructive applies from deleting production data stores.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Enable deletion protection", Description: "Set `deletion_protection = true` before apply.", Effort: "low", DowntimeRisk: "low", Preferred: true},
		},
	},
	"AWS_RDS_FINAL_SNAPSHOT_DISABLED_PROD": {
		ID:              "AWS_RDS_FINAL_SNAPSHOT_DISABLED_PROD",
		Summary:         "Keep final snapshots enabled for production database deletion or replacement.",
		Steps:           []string{"Set `skip_final_snapshot = false` for production deletion or replacement.", "Provide a reviewed `final_snapshot_identifier` where required.", "Confirm the snapshot retention and restore plan before approving the change."},
		WhyThisWorks:    "A final snapshot preserves a restore point before destructive database changes complete.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Require final snapshot", Description: "Disable `skip_final_snapshot` and configure a final snapshot identifier if Terraform requires one.", Effort: "low", DowntimeRisk: "low", Preferred: true},
		},
	},
	"AWS_DYNAMODB_PITR_DISABLED_PROD": {
		ID:              "AWS_DYNAMODB_PITR_DISABLED_PROD",
		Summary:         "Enable point-in-time recovery for production DynamoDB tables.",
		Steps:           []string{"Set `point_in_time_recovery.enabled` to `true` for production tables.", "Confirm recovery-period requirements with the owning service before disabling PITR.", "Use a waiver only for intentionally ephemeral production tables with documented recovery alternatives."},
		WhyThisWorks:    "PITR preserves the ability to restore production table data to a recent point after accidental writes, deletes, or bad deploys.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Enable DynamoDB PITR", Description: "Turn on point-in-time recovery for the production table.", Effort: "low", DowntimeRisk: "low", Preferred: true},
		},
		WhatHappened: "The plan disables or omits point-in-time recovery for a production DynamoDB table.",
		WhyItMatters: "Without PITR, accidental data corruption or deletion can become a longer outage or data-loss event.",
	},
	"AWS_ECR_REPOSITORY_MUTABLE_OR_SCAN_DISABLED_PROD": {
		ID:              "AWS_ECR_REPOSITORY_MUTABLE_OR_SCAN_DISABLED_PROD",
		Summary:         "Use immutable image tags and enable image scanning for production ECR repositories.",
		Steps:           []string{"Set `image_tag_mutability` to `IMMUTABLE` for production repositories.", "Enable `image_scanning_configuration.scan_on_push` or an equivalent registry scanning workflow.", "Use explicit release tags or digests for production deployment references."},
		WhyThisWorks:    "Immutable tags preserve artifact provenance, and scan-on-push catches known vulnerable images before deployment.",
		FixConfidence:   model.ConfidenceHigh,
		ReplaceDefaults: true,
		FixOptions: []model.FixOption{
			{Title: "Harden ECR repository settings", Description: "Enable immutable tags and scan-on-push for production repositories.", Effort: "low", DowntimeRisk: "low", Preferred: true},
		},
		WhatHappened: "The plan allows mutable production image tags or disables image scanning.",
		WhyItMatters: "Mutable production tags weaken release provenance, and disabled scanning reduces visibility into vulnerable images.",
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
		Steps:         []string{"Inspect the finding evidence.", "Identify the resource owner.", "Add a targeted fix or a time-bounded waiver if the risk is accepted."},
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
				{Title: "Review evidence", Description: "Use the finding evidence and resource-owner context to select a resource-specific mitigation.", Effort: "unknown", DowntimeRisk: "unknown", Preferred: true},
			},
		}
	}
}

func mergeTemplateDefaults(template Template, defaults Template) Template {
	if template.ReplaceDefaults {
		if template.Effort == "" {
			template.Effort = defaults.Effort
		}
		if template.DowntimeRisk == "" {
			template.DowntimeRisk = defaults.DowntimeRisk
		}
		return template
	}
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
