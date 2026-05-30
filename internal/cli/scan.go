package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/adapters"
	"github.com/Gabriel0110/changegate/internal/baseline"
	"github.com/Gabriel0110/changegate/internal/buildinfo"
	"github.com/Gabriel0110/changegate/internal/cloudcontext"
	"github.com/Gabriel0110/changegate/internal/compliance"
	"github.com/Gabriel0110/changegate/internal/custompolicy"
	graphpkg "github.com/Gabriel0110/changegate/internal/graph"
	tfjson "github.com/Gabriel0110/changegate/internal/input/terraform"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
	"github.com/Gabriel0110/changegate/internal/policy"
	"github.com/Gabriel0110/changegate/internal/remediation"
	"github.com/Gabriel0110/changegate/internal/rules"
	"github.com/Gabriel0110/changegate/internal/waiver"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	planPaths      []string
	debugPlanModel bool
	debugGraph     bool
	branch         string
	baselinePath   string
	newOnly        bool
	cloudContext   string
	contextFile    string
	importSARIF    []string
	importJSON     []string
	importCheckov  []string
	importTrivy    []string
	importKICS     []string
	importGrype    []string
	failImport     bool
	auditBundle    string
	timeout        string
	maxFindings    int
	changedOnly    bool
}

func newScanCommand() *cobra.Command {
	scanOpts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan --plan tfplan.json",
		Short: "Analyze Terraform/OpenTofu plan JSON before apply",
		Long: `Analyze Terraform/OpenTofu plan JSON before apply and return one deployment decision.

Fastest path:
  terraform plan -out=tfplan
  terraform show -json tfplan > tfplan.json
  changegate scan --plan tfplan.json

Scan builds a changing-resource graph, evaluates built-in AWS risk rules,
applies policy thresholds, and emits terminal or CI-friendly output.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}

			if len(scanOpts.planPaths) == 0 {
				return usageError("missing required --plan path", "Generate plan JSON with terraform show -json tfplan > tfplan.json, then run changegate scan --plan tfplan.json.")
			}
			if err := prepareCache(state.opts.cacheDir); err != nil {
				return err
			}
			if scanOpts.debugPlanModel || scanOpts.debugGraph {
				if len(scanOpts.planPaths) != 1 {
					return usageError("--debug-plan-model and --debug-graph require exactly one --plan", "Run debug output against one plan at a time.")
				}
				plan, err := loadPlan(cmd.Context(), state.stdin, scanOpts.planPaths[0])
				if err != nil {
					return mapPlanLoadError(err)
				}
				if scanOpts.debugPlanModel {
					return writeJSON(state.renderer.out, plan)
				}
				return writeJSON(state.renderer.out, graphpkg.Build(plan))
			}

			policyConfig, selection, registry, err := loadPolicyForScan(state.opts)
			if err != nil {
				return err
			}
			if err := applyBaselineOptions(&policyConfig, scanOpts.baselinePath, scanOpts.newOnly); err != nil {
				return err
			}
			if scanOpts.changedOnly {
				policyConfig.ChangedResourcesOnly = true
			}
			scanCtx, cancel, err := scanContext(cmd.Context(), scanOpts.timeout)
			if err != nil {
				return err
			}
			defer cancel()
			contextSnapshot, contextDiagnostics, err := loadCloudContext(state.opts.cacheDir, scanOpts.cloudContext, scanOpts.contextFile)
			if err != nil {
				return err
			}
			imports := scanImportRequests(scanOpts)
			report, err := scanPlans(scanCtx, state.stdin, scanOpts.planPaths, scanOpts.branch, state.opts, registry, selection, policyConfig, contextSnapshot, imports, scanOpts.failImport)
			if err != nil {
				return err
			}
			if err := scanCtx.Err(); err != nil && scanOpts.timeout != "" {
				return inputError(fmt.Sprintf("scan timed out after %s", scanOpts.timeout), "Increase --timeout or reduce scan scope.")
			}
			report.Diagnostics = append(report.Diagnostics, contextDiagnostics...)
			if err := limitReportFindings(&report, scanOpts.maxFindings); err != nil {
				return err
			}
			if err := attachAuditEvidence(&report, scanOpts, state.opts, contextSnapshot); err != nil {
				return err
			}
			if report.Decision == model.DecisionBlock {
				state.opts.exitCode = exitBlocked
			}

			if scanOpts.auditBundle != "" {
				if err := writeAuditBundle(scanOpts.auditBundle, report); err != nil {
					return err
				}
			}
			return writeScanReport(state, report)
		},
	}

	cmd.Flags().StringArrayVar(&scanOpts.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON produced by show -json; repeat for multiple plans")
	cmd.Flags().BoolVar(&scanOpts.debugPlanModel, "debug-plan-model", false, "dump the redacted normalized plan model as JSON")
	cmd.Flags().BoolVar(&scanOpts.debugGraph, "debug-graph", false, "dump the inferred resource relationship graph as JSON")
	cmd.Flags().StringVar(&scanOpts.branch, "branch", "", "branch name for branch-specific policy thresholds")
	cmd.Flags().StringVar(&scanOpts.baselinePath, "baseline", "", "baseline file used to suppress existing findings")
	cmd.Flags().BoolVar(&scanOpts.newOnly, "new-only", false, "only enforce findings not present in the baseline")
	cmd.Flags().StringVar(&scanOpts.cloudContext, "cloud-context", "", "optional cloud context provider: aws")
	cmd.Flags().StringVar(&scanOpts.contextFile, "context-file", "", "offline cloud context snapshot file")
	cmd.Flags().StringArrayVar(&scanOpts.importSARIF, "import-sarif", nil, "import SARIF 2.1.0 findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&scanOpts.importJSON, "import-json", nil, "import generic ChangeGate JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&scanOpts.importCheckov, "import-checkov", nil, "import Checkov JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&scanOpts.importTrivy, "import-trivy", nil, "import Trivy JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&scanOpts.importKICS, "import-kics", nil, "import KICS JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&scanOpts.importGrype, "import-grype", nil, "import Grype JSON findings as external evidence; repeatable")
	cmd.Flags().BoolVar(&scanOpts.failImport, "fail-on-import-error", false, "fail the scan when an external scanner output cannot be imported")
	cmd.Flags().StringVar(&scanOpts.auditBundle, "audit-bundle", "", "write a deterministic audit evidence bundle zip to this path")
	cmd.Flags().StringVar(&scanOpts.timeout, "timeout", "", "overall scan timeout such as 30s, 2m, or 5m")
	cmd.Flags().IntVar(&scanOpts.maxFindings, "max-findings", 0, "maximum findings to include in output; 0 includes all findings")
	cmd.Flags().BoolVar(&scanOpts.changedOnly, "changed-only", false, "only enforce findings on resources changed by the plan")
	return cmd
}

func scanImportRequests(opts *scanOptions) []adapters.ImportRequest {
	if opts == nil {
		return nil
	}
	var requests []adapters.ImportRequest
	requests = appendImportRequests(requests, adapters.SourceSARIF, opts.importSARIF)
	requests = appendImportRequests(requests, adapters.SourceGeneric, opts.importJSON)
	requests = appendImportRequests(requests, adapters.SourceCheckov, opts.importCheckov)
	requests = appendImportRequests(requests, adapters.SourceTrivy, opts.importTrivy)
	requests = appendImportRequests(requests, adapters.SourceKICS, opts.importKICS)
	requests = appendImportRequests(requests, adapters.SourceGrype, opts.importGrype)
	return requests
}

func appendImportRequests(requests []adapters.ImportRequest, source adapters.Source, paths []string) []adapters.ImportRequest {
	for _, path := range paths {
		requests = append(requests, adapters.ImportRequest{Source: source, Path: path})
	}
	return requests
}

func loadPolicyForScan(opts *options) (model.PolicyConfig, rules.Selection, *rules.Registry, error) {
	defaultRegistry, err := rules.DefaultRegistry()
	if err != nil {
		return model.PolicyConfig{}, rules.Selection{}, nil, internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	if opts.policy == "" {
		return model.DefaultPolicyConfig(), rules.Selection{}, defaultRegistry, nil
	}

	config, err := policy.LoadFile(opts.policy)
	if err != nil {
		return model.PolicyConfig{}, rules.Selection{}, nil, usageError(err.Error(), "Check the policy path and YAML syntax.")
	}
	registry, customDiagnostics, err := registryForPolicy(opts.policy, config)
	if err != nil {
		return model.PolicyConfig{}, rules.Selection{}, nil, err
	}
	validation := policy.Validate(config, registry, rules.DefaultPolicyPacks())
	validation.Diagnostics = append(validation.Diagnostics, customDiagnostics...)
	if len(customDiagnostics) > 0 {
		validation.Valid = false
	}
	if !validation.Valid {
		return model.PolicyConfig{}, rules.Selection{}, nil, usageError(validation.Diagnostics[0].Message, "Run changegate policy validate "+opts.policy+" for details.")
	}
	modelConfig := policy.ModelConfig(config, "default")
	if config.Baseline.File != "" {
		file, err := baseline.LoadFile(config.Baseline.File)
		if err != nil {
			return model.PolicyConfig{}, rules.Selection{}, nil, policyError(err.Error(), "Check baseline.file in the policy or recreate the baseline.")
		}
		if err := enforceBaselinePolicy(file, config.Baseline.RequireExpiration); err != nil {
			return model.PolicyConfig{}, rules.Selection{}, nil, err
		}
		modelConfig.ExistingFingerprints = mergeExistingFingerprints(modelConfig.ExistingFingerprints, baseline.Fingerprints(file))
		modelConfig.BaselineWarnings = append(modelConfig.BaselineWarnings, baseline.Diagnostics(file, time.Now().UTC(), config.Baseline.MaxAgeDays, config.Baseline.RequireExpiration)...)
	}
	if config.Waivers.File != "" {
		file, err := waiver.LoadFile(config.Waivers.File)
		if err != nil {
			return model.PolicyConfig{}, rules.Selection{}, nil, policyError(err.Error(), "Check waivers.file in the policy or recreate the waiver file.")
		}
		validation := waiver.Validate(file, waiver.ValidationOptions{
			RequireExpiration: true,
			MaxDurationDays:   config.Waivers.MaxDurationDays,
			Now:               time.Now().UTC(),
		})
		if !validation.Valid {
			return model.PolicyConfig{}, rules.Selection{}, nil, policyError(validation.Diagnostics[0].Message, "Fix the waiver file and rerun validation.")
		}
		if config.Waivers.FailExpired && validation.Summary.Expired > 0 {
			return model.PolicyConfig{}, rules.Selection{}, nil, policyError("waiver file contains expired waivers", "Run changegate waiver prune or renew expired waivers.")
		}
		modelConfig.WaiverFile = config.Waivers.File
		modelConfig.FailExpiredWaivers = config.Waivers.FailExpired
	}
	return modelConfig, policy.RuleSelection(config, rules.DefaultPolicyPacks()), registry, nil
}

func registryForPolicy(policyPath string, config policy.Config) (*rules.Registry, []model.Diagnostic, error) {
	registry, err := rules.DefaultRegistry()
	if err != nil {
		return nil, nil, internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	var diagnostics []model.Diagnostic
	customRules, customDiagnostics := custompolicy.LoadYAMLRules(policyPath, config.CustomRules.Files, config.CustomRules.MaxFileSize)
	diagnostics = append(diagnostics, customModelDiagnostics(customDiagnostics, model.DiagnosticError)...)
	for _, rule := range customRules {
		if err := registry.Register(rule); err != nil {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.DiagnosticError, Code: "CUSTOM_RULE_REGISTER_FAILED", Message: err.Error()})
		}
	}
	timeout, err := parseRegoTimeout(config.Rego.Timeout)
	if err != nil {
		diagnostics = append(diagnostics, model.Diagnostic{Severity: model.DiagnosticError, Code: "REGO_TIMEOUT_INVALID", Message: err.Error()})
	}
	regoRule, regoDiagnostics := custompolicy.LoadRegoRule(custompolicy.RegoOptions{
		PolicyPath:    policyPath,
		Files:         config.Rego.Files,
		Query:         config.Rego.Query,
		Timeout:       timeout,
		MaxInputBytes: config.Rego.MaxInputBytes,
	})
	diagnostics = append(diagnostics, customModelDiagnostics(regoDiagnostics, model.DiagnosticError)...)
	if regoRule != nil {
		if err := registry.Register(regoRule); err != nil {
			diagnostics = append(diagnostics, model.Diagnostic{Severity: model.DiagnosticError, Code: "REGO_RULE_REGISTER_FAILED", Message: err.Error()})
		}
	}
	return registry, diagnostics, nil
}

func customModelDiagnostics(values []custompolicy.Diagnostic, severity model.DiagnosticSeverity) []model.Diagnostic {
	out := make([]model.Diagnostic, 0, len(values))
	for _, value := range values {
		out = append(out, model.Diagnostic{Severity: severity, Code: value.Code, Message: value.Message})
	}
	return out
}

func parseRegoTimeout(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	timeout, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("rego.timeout must be a duration such as 250ms: %w", err)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("rego.timeout must be positive")
	}
	if timeout > 5*time.Second {
		return 0, fmt.Errorf("rego.timeout must be 5s or less")
	}
	return timeout, nil
}

func enforceBaselinePolicy(file baseline.File, requireExpiration bool) error {
	if !requireExpiration {
		return nil
	}
	if file.ExpiresAt == "" {
		return policyError("baseline policy requires expires_at", "Recreate the baseline with --expires-at or --expires-in-days.")
	}
	expiresAt, err := time.Parse(time.RFC3339, file.ExpiresAt)
	if err != nil {
		return policyError("baseline expires_at must be RFC3339", "Recreate the baseline with a valid --expires-at timestamp.")
	}
	if !time.Now().UTC().Before(expiresAt.UTC()) {
		return policyError("baseline has expired", "Refresh or remove stale baseline entries before enforcing.")
	}
	return nil
}

func applyBaselineOptions(config *model.PolicyConfig, baselinePath string, newOnly bool) error {
	if baselinePath == "" {
		if newOnly {
			return usageError("--new-only requires --baseline", "Create a baseline with changegate baseline create --plan tfplan.json --out .changegate/baseline.json.")
		}
		return nil
	}
	file, err := baseline.LoadFile(baselinePath)
	if err != nil {
		return inputError(err.Error(), "Check the baseline path or recreate it with changegate baseline create.")
	}
	config.ExistingFingerprints = mergeExistingFingerprints(config.ExistingFingerprints, baseline.Fingerprints(file))
	if newOnly {
		config.NewRiskOnly = true
	}
	config.BaselineWarnings = append(config.BaselineWarnings, baseline.Diagnostics(file, time.Now().UTC(), 0, false)...)
	return nil
}

func scanContext(parent context.Context, timeoutValue string) (context.Context, context.CancelFunc, error) {
	if timeoutValue == "" {
		return parent, func() {}, nil
	}
	timeout, err := time.ParseDuration(timeoutValue)
	if err != nil {
		return nil, nil, usageError("--timeout must be a duration such as 30s, 2m, or 5m", "Pass a valid Go duration or omit --timeout.")
	}
	if timeout <= 0 {
		return nil, nil, usageError("--timeout must be positive", "Pass a timeout greater than zero or omit --timeout.")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	return ctx, cancel, nil
}

func limitReportFindings(report *output.Report, maxFindings int) error {
	if maxFindings < 0 {
		return usageError("--max-findings must be zero or greater", "Use 0 to include all findings, or pass a positive cap.")
	}
	if maxFindings == 0 || len(report.Findings) <= maxFindings {
		return nil
	}
	omitted := len(report.Findings) - maxFindings
	report.Findings = append([]model.Finding{}, report.Findings[:maxFindings]...)
	report.Diagnostics = append(report.Diagnostics, model.Diagnostic{
		Severity: model.DiagnosticInfo,
		Code:     "MAX_FINDINGS_TRUNCATED",
		Message:  fmt.Sprintf("output limited to %d findings; %d findings omitted from serialized output", maxFindings, omitted),
	})
	return nil
}

func mergeExistingFingerprints(existing map[string]bool, incoming map[string]bool) map[string]bool {
	if existing == nil {
		existing = make(map[string]bool, len(incoming))
	}
	for fingerprint := range incoming {
		existing[fingerprint] = true
	}
	return existing
}

func scanPlans(ctx context.Context, stdin io.Reader, planPaths []string, branch string, opts *options, registry *rules.Registry, selection rules.Selection, basePolicy model.PolicyConfig, contextSnapshot *cloudcontext.Snapshot, imports []adapters.ImportRequest, failImport bool) (output.Report, error) {
	if len(planPaths) == 1 {
		return scanOnePlan(ctx, stdin, planPaths[0], branch, opts, registry, selection, basePolicy, contextSnapshot, imports, failImport)
	}
	if len(imports) > 0 {
		return output.Report{}, usageError("external scanner imports require exactly one --plan", "Run ChangeGate once per plan when using --import-sarif, --import-json, --import-checkov, --import-trivy, --import-kics, or --import-grype.")
	}
	for _, planPath := range planPaths {
		if planPath == "-" {
			return output.Report{}, usageError("--plan - cannot be combined with additional --plan values", "Write each plan JSON to a file when scanning multiple plans.")
		}
	}

	combinedOutcome := model.PolicyOutcome{
		Decision: model.DecisionAllow,
		Summary: model.RiskSummary{
			BySeverity:         make(map[model.Severity]int),
			ByCategory:         make(map[model.RiskCategory]int),
			SuppressedByReason: make(map[string]int),
		},
	}
	var diagnostics []model.Diagnostic
	var resourceCount int
	var changeCount int
	var graphNodes int
	var graphEdges int
	var tool model.Tool
	var formatVersion string

	for _, planPath := range planPaths {
		report, err := scanOnePlan(ctx, stdin, planPath, branch, opts, registry, selection, basePolicy, contextSnapshot, nil, false)
		if err != nil {
			return output.Report{}, err
		}
		if tool == "" {
			tool = report.Plan.Tool
		} else if tool != report.Plan.Tool {
			tool = model.ToolUnknown
		}
		if formatVersion == "" {
			formatVersion = report.Plan.FormatVersion
		}
		resourceCount += report.Plan.Resources
		changeCount += report.Plan.Changes
		graphNodes += report.Graph.Nodes
		graphEdges += report.Graph.Edges
		diagnostics = append(diagnostics, report.Diagnostics...)
		combinedOutcome.Findings = append(combinedOutcome.Findings, report.Findings...)
		combinedOutcome.Reasons = append(combinedOutcome.Reasons, report.Reasons...)
		combinedOutcome.ReasonCodes = appendDecisionReasonCodes(combinedOutcome.ReasonCodes, report.ReasonCodes...)
		mergeRiskSummary(&combinedOutcome.Summary, report.RiskSummary)
		combinedOutcome.Decision = strongestDecision(combinedOutcome.Decision, report.Decision)
	}

	return output.Report{
		SchemaVersion: output.ReportSchemaVersion,
		Decision:      combinedOutcome.Decision,
		Plan: output.PlanSummary{
			Path:          "multiple",
			Tool:          tool,
			FormatVersion: formatVersion,
			Resources:     resourceCount,
			Changes:       changeCount,
		},
		Graph:       output.GraphSummary{Nodes: graphNodes, Edges: graphEdges},
		RiskSummary: combinedOutcome.Summary,
		ReasonCodes: combinedOutcome.ReasonCodes,
		Reasons:     combinedOutcome.Reasons,
		Findings:    combinedOutcome.Findings,
		Diagnostics: diagnostics,
		Rules:       ruleSummaries(registry),
		Message:     fmt.Sprintf("%d plans parsed, graphs built, and policies evaluated", len(planPaths)),
	}, nil
}

func scanOnePlan(ctx context.Context, stdin io.Reader, planPath string, branch string, opts *options, registry *rules.Registry, selection rules.Selection, basePolicy model.PolicyConfig, contextSnapshot *cloudcontext.Snapshot, imports []adapters.ImportRequest, failImport bool) (output.Report, error) {
	plan, err := loadPlan(ctx, stdin, planPath)
	if err != nil {
		return output.Report{}, mapPlanLoadError(err)
	}

	resourceGraph := graphpkg.Build(plan)

	ruleResult := rules.NewRunner(registry).Evaluate(ctx, rules.RuleInput{
		Plan:        plan,
		Graph:       resourceGraph,
		Environment: "default",
	}, selection)
	plan.Diagnostics = append(plan.Diagnostics, ruleResult.Diagnostics...)
	findings := ruleResult.Findings
	if contextSnapshot != nil {
		enriched, diagnostics := cloudcontext.EnrichFindings(findings, *contextSnapshot)
		findings = enriched
		plan.Diagnostics = append(plan.Diagnostics, diagnostics...)
	}
	importSummary, importDiagnostics, err := importExternalFindings(imports, findings, resourceGraph, failImport)
	if err != nil {
		return output.Report{}, err
	}
	plan.Diagnostics = append(plan.Diagnostics, importDiagnostics...)
	if importSummary != nil {
		findings = importSummary.findings
	}
	findings = remediation.EnrichFindings(findings, resourceTags(plan), remediation.Options{DocsLinks: basePolicy.DocumentationLinks})
	if basePolicy.WaiverFile != "" {
		waiverFile, err := waiver.LoadFile(basePolicy.WaiverFile)
		if err != nil {
			return output.Report{}, inputError(err.Error(), "Check the waiver file path.")
		}
		applied, review := waiver.Apply(waiverFile, findings, time.Now().UTC(), basePolicy.FailExpiredWaivers)
		findings = applied
		plan.Diagnostics = append(plan.Diagnostics, review.Diagnostics...)
		if basePolicy.FailExpiredWaivers && len(review.Diagnostics) > 0 {
			return output.Report{}, policyError(review.Diagnostics[0].Message, "Prune or renew expired waivers.")
		}
	}

	policyConfig := basePolicy
	policyConfig.Mode = policyMode(opts.mode)
	policyConfig.Branch = branch
	policyConfig.ChangedResources = changedResources(plan)
	outcome := model.EvaluatePolicy(findings, policyConfig)
	for _, warning := range policyConfig.BaselineWarnings {
		plan.Diagnostics = append(plan.Diagnostics, model.Diagnostic{
			Severity: model.DiagnosticWarning,
			Code:     "BASELINE_WARNING",
			Message:  warning,
		})
	}

	report := output.NewReport(
		planPath,
		plan,
		len(resourceGraph.Nodes),
		len(resourceGraph.Edges),
		outcome,
		ruleSummaries(registry),
		"plan parsed, graph built, and policy evaluated",
	)
	if importSummary != nil {
		report.Imports = importSummary.summary
	}
	return report, nil
}

type scanImportSummary struct {
	findings []model.Finding
	summary  *output.ImportSummary
}

func importExternalFindings(requests []adapters.ImportRequest, nativeFindings []model.Finding, resourceGraph *graphpkg.Graph, failImport bool) (*scanImportSummary, []model.Diagnostic, error) {
	if len(requests) == 0 {
		return nil, nil, nil
	}
	imported := make([]model.Finding, 0)
	var diagnostics []model.Diagnostic
	for _, request := range requests {
		result := adapters.ImportFile(request)
		imported = append(imported, result.Findings...)
		diagnostics = append(diagnostics, result.Diagnostics...)
		if failImport && len(result.Diagnostics) > 0 {
			return nil, diagnostics, inputError(result.Diagnostics[0].Message, "Fix the scanner output path or omit --fail-on-import-error.")
		}
	}
	merged, summary := adapters.Merge(nativeFindings, imported, resourceGraph)
	return &scanImportSummary{
		findings: merged,
		summary:  importSummaryFromAdapter(summary),
	}, diagnostics, nil
}

func importSummaryFromAdapter(summary adapters.Summary) *output.ImportSummary {
	if summary.Imported == 0 && summary.Deduplicated == 0 && summary.Correlated == 0 && summary.Downgraded == 0 && summary.Upgraded == 0 {
		return nil
	}
	bySource := make(map[string]int, len(summary.BySource))
	for source, count := range summary.BySource {
		bySource[string(source)] = count
	}
	return &output.ImportSummary{
		Imported:     summary.Imported,
		Deduplicated: summary.Deduplicated,
		Correlated:   summary.Correlated,
		Downgraded:   summary.Downgraded,
		Upgraded:     summary.Upgraded,
		BySource:     bySource,
	}
}

func loadCloudContext(cacheDir string, provider string, contextFile string) (*cloudcontext.Snapshot, []model.Diagnostic, error) {
	if provider == "" && contextFile == "" {
		return nil, nil, nil
	}
	if provider != "" && provider != cloudcontext.ProviderAWS {
		return nil, nil, usageError("--cloud-context must be aws", "Use --cloud-context aws or omit the flag for no cloud context.")
	}
	if contextFile != "" {
		snapshot, err := cloudcontext.LoadFile(contextFile)
		if err != nil {
			return nil, nil, inputError(err.Error(), "Check --context-file or recreate it with changegate context aws snapshot.")
		}
		diagnostics := cloudcontext.ValidatePermissions(snapshot)
		return &snapshot, diagnostics, nil
	}
	if provider == cloudcontext.ProviderAWS {
		if cacheDir != "" {
			cached := filepath.Join(cacheDir, "cloud-context", "aws-context.json")
			if snapshot, err := cloudcontext.LoadFile(cached); err == nil {
				diagnostics := cloudcontext.ValidatePermissions(snapshot)
				return &snapshot, diagnostics, nil
			}
		}
		return nil, []model.Diagnostic{{
			Severity: model.DiagnosticWarning,
			Code:     "CLOUD_CONTEXT_UNAVAILABLE",
			Message:  "AWS cloud context requested but no context file or cache snapshot was available; defaulting to plan-only analysis without network calls",
		}}, nil
	}
	return nil, nil, nil
}

func policyMode(mode string) model.PolicyMode {
	switch mode {
	case "warn":
		return model.PolicyModeWarn
	case "audit":
		return model.PolicyModeAudit
	default:
		return model.PolicyModeBlock
	}
}

func loadPlan(ctx context.Context, stdin io.Reader, planPath string) (*model.Plan, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("scan cancelled before reading plan: %w", ctx.Err())
	default:
	}

	if planPath == "-" {
		return tfjson.Load(stdin)
	}

	file, err := os.Open(planPath)
	if err != nil {
		return nil, fmt.Errorf("open plan %q: %w", planPath, err)
	}
	defer closeReader(file)

	return tfjson.Load(file)
}

func mapPlanLoadError(err error) error {
	var parseErr *tfjson.ParseError
	if errors.As(err, &parseErr) {
		switch parseErr.Kind {
		case "unsupported_format_version", "missing_format_version":
			return unsupportedError(parseErr.Error(), "Use Terraform/OpenTofu show -json output with supported plan format version 1.x.")
		default:
			return inputError(parseErr.Error(), "Verify the file was generated with terraform show -json or tofu show -json.")
		}
	}

	if errors.Is(err, os.ErrNotExist) {
		return inputError(err.Error(), "Check the --plan path or pass --plan - to read JSON from stdin.")
	}

	return inputError(err.Error(), "Check the --plan path or pass --plan - to read JSON from stdin.")
}

func changedResources(plan *model.Plan) map[string]bool {
	out := make(map[string]bool)
	if plan == nil {
		return out
	}
	for _, change := range plan.Changes {
		out[change.Address] = true
	}
	return out
}

func resourceTags(plan *model.Plan) map[string]map[string]string {
	out := make(map[string]map[string]string)
	if plan == nil {
		return out
	}
	for _, resource := range plan.Resources {
		if len(resource.Tags) > 0 {
			out[resource.Address] = resource.Tags
		}
	}
	for _, change := range plan.Changes {
		if len(change.Tags) > 0 {
			out[change.Address] = change.Tags
		}
	}
	return out
}

func prepareCache(cacheDir string) error {
	if cacheDir == "" {
		return nil
	}
	for _, dir := range []string{
		filepath.Join(cacheDir, "policy-packs"),
		filepath.Join(cacheDir, "cloud-context"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return inputError(fmt.Sprintf("create cache directory %q: %v", dir, err), "Check --cache-dir permissions or choose a writable cache path.")
		}
	}
	return nil
}

func appendDecisionReasonCodes(existing []model.DecisionReasonCode, values ...model.DecisionReasonCode) []model.DecisionReasonCode {
	seen := make(map[model.DecisionReasonCode]bool, len(existing)+len(values))
	for _, code := range existing {
		seen[code] = true
	}
	for _, code := range values {
		if seen[code] {
			continue
		}
		existing = append(existing, code)
		seen[code] = true
	}
	return existing
}

func mergeRiskSummary(target *model.RiskSummary, source model.RiskSummary) {
	target.Total += source.Total
	target.Blocking += source.Blocking
	target.Warnings += source.Warnings
	target.Informational += source.Informational
	target.Suppressed += source.Suppressed
	target.Downgraded += source.Downgraded
	target.Upgraded += source.Upgraded
	if target.BySeverity == nil {
		target.BySeverity = make(map[model.Severity]int)
	}
	for severity, count := range source.BySeverity {
		target.BySeverity[severity] += count
	}
	if target.ByCategory == nil {
		target.ByCategory = make(map[model.RiskCategory]int)
	}
	for category, count := range source.ByCategory {
		target.ByCategory[category] += count
	}
	if target.SuppressedByReason == nil {
		target.SuppressedByReason = make(map[string]int)
	}
	for reason, count := range source.SuppressedByReason {
		target.SuppressedByReason[reason] += count
	}
}

func strongestDecision(a model.Decision, b model.Decision) model.Decision {
	if decisionRank(b) > decisionRank(a) {
		return b
	}
	return a
}

func decisionRank(decision model.Decision) int {
	switch decision {
	case model.DecisionBlock:
		return 3
	case model.DecisionWarn:
		return 2
	case model.DecisionAllow:
		return 1
	default:
		return 0
	}
}

func closeReader(file *os.File) {
	if err := file.Close(); err != nil {
		return
	}
}

func ruleSummaries(registry *rules.Registry) map[string]output.RuleSummary {
	out := make(map[string]output.RuleSummary)
	for _, rule := range registry.Rules() {
		meta := rule.Metadata()
		out[meta.ID] = output.RuleSummary{
			ID:          meta.ID,
			Name:        meta.Title,
			Description: meta.Description,
			Category:    meta.Category,
			Severity:    meta.Severity,
			Confidence:  meta.Confidence,
			Help:        meta.Documentation.Rationale,
			Remediation: meta.Documentation.Remediation,
			References:  meta.Documentation.References,
		}
	}
	return out
}

func attachAuditEvidence(report *output.Report, scanOpts *scanOptions, opts *options, contextSnapshot *cloudcontext.Snapshot) error {
	info := buildinfo.Current()
	policyBody, policyDigest, err := policyEvidence(opts.policy, opts.mode)
	if err != nil {
		return inputError(err.Error(), "Check --policy or rerun without an audit bundle.")
	}
	planDigest, err := planEvidence(scanOpts.planPaths, *report)
	if err != nil {
		return inputError(err.Error(), "Check --plan paths and permissions.")
	}
	configHash := policyDigest
	if opts.policy == "" {
		configHash = ""
	}
	report.Run = &output.RunMetadata{
		SchemaVersion:      "changegate.audit.run.v1",
		CLIVersion:         info.Version,
		CLICommit:          info.Commit,
		CLIDate:            info.Date,
		PlanHash:           planDigest,
		ConfigHash:         configHash,
		PolicyDigest:       policyDigest,
		PlanDigest:         planDigest,
		PolicyPackVersions: packVersionMap(rules.DefaultPolicyPacks()),
		Redaction:          redactionReport(report.Findings),
	}
	if contextSnapshot != nil {
		report.Run.CloudContextTimestamp = contextSnapshot.GeneratedAt
	}
	report.Audit = &output.AuditReports{
		PolicyYAML: string(policyBody),
	}
	if opts.policy != "" {
		config, err := policy.LoadFile(opts.policy)
		if err != nil {
			return inputError(err.Error(), "Check --policy and rerun the scan.")
		}
		if config.Waivers.File != "" {
			waiverReport, err := waiverReport(config.Waivers.File, report.Findings, config.Waivers.FailExpired)
			if err != nil {
				return inputError(err.Error(), "Check waivers.file in the policy.")
			}
			report.Audit.Waivers = waiverReport
		}
		if config.Baseline.File != "" {
			baselineReport, err := baselineReport(config.Baseline.File, report.Findings, config.Baseline.MaxAgeDays, config.Baseline.RequireExpiration)
			if err != nil {
				return inputError(err.Error(), "Check baseline.file in the policy.")
			}
			report.Audit.Baseline = baselineReport
		}
	}
	if scanOpts.baselinePath != "" {
		baselineReport, err := baselineReport(scanOpts.baselinePath, report.Findings, 0, false)
		if err != nil {
			return inputError(err.Error(), "Check --baseline or recreate the baseline.")
		}
		report.Audit.Baseline = baselineReport
	}
	complianceReport := compliance.BuildReport(report.Findings)
	report.Compliance = &complianceReport
	return nil
}

func policyEvidence(policyPath string, mode string) ([]byte, string, error) {
	if policyPath == "" {
		if mode == "" {
			mode = "block"
		}
		body := []byte(fmt.Sprintf("version: 1\nmode: %s\n", mode))
		return body, sha256Hex(body), nil
	}
	body, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, "", fmt.Errorf("read policy %q: %w", policyPath, err)
	}
	return body, sha256Hex(body), nil
}

func planEvidence(planPaths []string, report output.Report) (string, error) {
	if len(planPaths) == 0 {
		body, err := json.Marshal(report.Plan)
		if err != nil {
			return "", fmt.Errorf("marshal plan summary: %w", err)
		}
		return sha256Hex(body), nil
	}
	if len(planPaths) == 1 {
		if planPaths[0] == "-" {
			body, err := json.Marshal(report.Plan)
			if err != nil {
				return "", fmt.Errorf("marshal stdin plan summary: %w", err)
			}
			return sha256Hex(body), nil
		}
		body, err := os.ReadFile(planPaths[0])
		if err != nil {
			return "", fmt.Errorf("read plan %q: %w", planPaths[0], err)
		}
		return sha256Hex(body), nil
	}
	entries := make([]string, 0, len(planPaths))
	for _, planPath := range planPaths {
		body, err := os.ReadFile(planPath)
		if err != nil {
			return "", fmt.Errorf("read plan %q: %w", planPath, err)
		}
		entries = append(entries, planPath+":"+sha256Hex(body))
	}
	sort.Strings(entries)
	return sha256Hex([]byte(strings.Join(entries, "\n"))), nil
}

func waiverReport(path string, findings []model.Finding, failExpired bool) (waiver.ReviewReport, error) {
	file, err := waiver.LoadFile(path)
	if err != nil {
		return waiver.ReviewReport{}, err
	}
	_, report := waiver.Apply(file, findings, time.Now().UTC(), failExpired)
	return report, nil
}

func baselineReport(path string, findings []model.Finding, maxAgeDays int, requireExpiration bool) (baseline.DiffResult, error) {
	file, err := baseline.LoadFile(path)
	if err != nil {
		return baseline.DiffResult{}, err
	}
	report := baseline.Diff(file, findings, time.Now().UTC(), maxAgeDays, requireExpiration)
	report.BaselinePath = path
	return report, nil
}

func packVersionMap(packs []rules.PolicyPack) map[string]string {
	out := make(map[string]string, len(packs))
	for _, pack := range packs {
		out[pack.ID] = pack.Version
	}
	return out
}

func redactionReport(findings []model.Finding) output.RedactionReport {
	report := output.RedactionReport{Status: "redacted"}
	for _, finding := range findings {
		for _, evidence := range finding.Evidence {
			if evidence.Sensitive {
				report.SensitiveEvidence++
			}
			if evidence.Value != nil && evidence.Sensitive {
				report.RedactedValues++
			}
		}
	}
	return report
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func writeAuditBundle(path string, report output.Report) error {
	body, err := output.RenderAuditBundle(report)
	if err != nil {
		return internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create audit bundle %q: %w", path, err)
	}
	if _, err := file.Write(body); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("close audit bundle %q after write error: %w", path, closeErr)
		}
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close audit bundle %q: %w", path, err)
	}
	return nil
}

func writeScanReport(state *appState, report output.Report) error {
	body, _, err := output.Render(report, state.opts.format)
	if err != nil {
		return internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	if state.opts.outPath != "" {
		file, err := os.Create(state.opts.outPath)
		if err != nil {
			return fmt.Errorf("create output file %q: %w", state.opts.outPath, err)
		}
		if _, err := file.Write(body); err != nil {
			if closeErr := file.Close(); closeErr != nil {
				return fmt.Errorf("close output file %q after write error: %w", state.opts.outPath, closeErr)
			}
			return err
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close output file %q: %w", state.opts.outPath, err)
		}
		return nil
	}
	if _, err := state.renderer.out.Write(body); err != nil {
		return err
	}
	if len(body) > 0 && body[len(body)-1] != '\n' && state.opts.format != "audit-bundle" {
		_, err := fmt.Fprintln(state.renderer.out)
		return err
	}
	return nil
}
