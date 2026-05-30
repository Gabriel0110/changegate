package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
	"github.com/Gabriel0110/changegate/internal/policy"
	"github.com/Gabriel0110/changegate/internal/remediation"
	"github.com/Gabriel0110/changegate/internal/rules"
	"github.com/spf13/cobra"
)

type explainOptions struct {
	reportPath string
	json       bool
}

type explainResult struct {
	Explanation remediation.RuleExplanation `json:"explanation"`
	Finding     *model.Finding              `json:"finding,omitempty"`
	Evidence    []string                    `json:"evidence,omitempty"`
}

func newExplainCommand() *cobra.Command {
	opts := &explainOptions{}
	cmd := &cobra.Command{
		Use:   "explain <rule-or-finding-id>",
		Short: "Explain a rule or finding with remediation guidance",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError("explain requires one rule ID or finding ID", "Run changegate rules list or pass --report changegate.json to explain a finding from a scan.")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			result, err := buildExplanation(args[0], opts.reportPath, state.opts.policy)
			if err != nil {
				return err
			}
			if opts.json || state.opts.format == "json" {
				return writeJSON(state.renderer.out, result)
			}
			return writeCommandOutput(state, "explain", result, func(r renderer) {
				renderExplanation(r, result)
			})
		},
	}
	cmd.Flags().StringVar(&opts.reportPath, "report", "", "ChangeGate JSON report used to explain a concrete finding")
	cmd.Flags().BoolVar(&opts.json, "json", false, "emit explanation as JSON")
	return cmd
}

func buildExplanation(id string, reportPath string, policyPath string) (explainResult, error) {
	options := remediation.Options{DocsLinks: documentationLinks(policyPath)}
	if reportPath != "" {
		report, err := loadReport(reportPath)
		if err != nil {
			return explainResult{}, inputError(err.Error(), "Pass a JSON report produced by changegate scan --format json.")
		}
		if finding, ok := findReportFinding(report, id); ok {
			enriched := remediation.EnrichFinding(finding, nil, options)
			explanation := remediation.ExplainRule(enriched.RuleID, enriched.Title, enriched.Description, enriched.Category, enriched.Severity, enriched.Confidence, &enriched, options)
			return explainResult{Explanation: explanation, Finding: &enriched, Evidence: model.RenderEvidence(enriched.Evidence)}, nil
		}
	}
	registry, err := rules.DefaultRegistry()
	if err != nil {
		return explainResult{}, internalError(err.Error(), "Report this as a ChangeGate bug.")
	}
	rule, ok := registry.Get(id)
	if !ok {
		return explainResult{}, usageError("unknown rule or finding "+id, "Run changegate rules list, or use --report with a scan JSON report and a finding ID.")
	}
	meta := rule.Metadata()
	explanation := remediation.ExplainRule(meta.ID, meta.Title, meta.Description, meta.Category, meta.Severity, meta.Confidence, nil, options)
	return explainResult{Explanation: explanation}, nil
}

func loadReport(path string) (output.Report, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return output.Report{}, fmt.Errorf("read report %q: %w", path, err)
	}
	var report output.Report
	if err := json.Unmarshal(body, &report); err != nil {
		return output.Report{}, fmt.Errorf("decode report %q: %w", path, err)
	}
	return report, nil
}

func findReportFinding(report output.Report, id string) (model.Finding, bool) {
	for _, finding := range report.Findings {
		if finding.ID == id || finding.RuleID == id || finding.Fingerprint == id {
			return finding, true
		}
	}
	return model.Finding{}, false
}

func documentationLinks(policyPath string) map[string]string {
	if policyPath == "" {
		return nil
	}
	config, err := policy.LoadFile(policyPath)
	if err != nil {
		return nil
	}
	return config.Docs.Links
}

func renderExplanation(r renderer, result explainResult) {
	explanation := result.Explanation
	r.printf("%s\n\n", explanation.RuleID)
	r.printf("What happened:\n  %s\n\n", explanation.WhatHappened)
	r.printf("Why it matters:\n  %s\n\n", explanation.WhyItMatters)
	if len(result.Evidence) > 0 {
		r.printf("Evidence:\n")
		for _, evidence := range result.Evidence {
			r.printf("  - %s\n", evidence)
		}
		r.printf("\n")
	}
	r.printf("Recommended fix:\n  %s\n", explanation.Recommended.Summary)
	for _, step := range explanation.Recommended.Steps {
		r.printf("  - %s\n", step)
	}
	if explanation.Recommended.WhyThisWorks != "" {
		r.printf("\nWhy this fix works:\n  %s\n", explanation.Recommended.WhyThisWorks)
	}
	if explanation.Recommended.FixConfidence != "" {
		r.printf("\nFix confidence: %s\n", explanation.Recommended.FixConfidence)
	}
	r.printf("Automatic patch: not generated\n")
	for _, patch := range explanation.Recommended.Patches {
		if patch.Format == "advisory" {
			r.printf("Patch note: %s - %s\n", patch.Title, patch.Rationale)
			continue
		}
		r.printf("\nPatch suggestion (%s, review required):\n%s\n", patch.Format, strings.TrimSpace(patch.Snippet))
	}
	if len(explanation.Recommended.OwnerHints) > 0 {
		r.printf("\nOwner hints: %s\n", strings.Join(explanation.Recommended.OwnerHints, ", "))
	}
	if len(explanation.Recommended.NextSteps) > 0 {
		r.printf("\nNext steps:\n")
		for _, step := range explanation.Recommended.NextSteps {
			r.printf("  - %s\n", step)
		}
	}
	if len(explanation.Recommended.Docs) > 0 {
		r.printf("\nDocs:\n")
		for _, doc := range explanation.Recommended.Docs {
			r.printf("  - %s\n", doc)
		}
	}
}
