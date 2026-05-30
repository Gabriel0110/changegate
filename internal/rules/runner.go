package rules

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"

	"github.com/Gabriel0110/changegate/internal/model"
)

// Selection controls which rules run and how their findings are post-processed.
type Selection struct {
	EnabledRules  map[string]bool
	DisabledRules map[string]bool
	Overrides     map[string]model.Override
}

// Result captures rule execution output and diagnostics.
type Result struct {
	Findings    []model.Finding    `json:"findings"`
	Diagnostics []model.Diagnostic `json:"diagnostics,omitempty"`
}

// Runner evaluates selected rules from a registry.
type Runner struct {
	registry    *Registry
	parallelism int
}

// RunnerOption configures a rule runner.
type RunnerOption func(*Runner)

// WithParallelism sets the maximum number of rules evaluated concurrently.
func WithParallelism(parallelism int) RunnerOption {
	return func(r *Runner) {
		if parallelism > 0 {
			r.parallelism = parallelism
		}
	}
}

// NewRunner returns a rule runner.
func NewRunner(registry *Registry, options ...RunnerOption) *Runner {
	runner := &Runner{
		registry:    registry,
		parallelism: runtime.GOMAXPROCS(0),
	}
	if runner.parallelism < 1 {
		runner.parallelism = 1
	}
	for _, option := range options {
		option(runner)
	}
	return runner
}

// Evaluate runs selected rules deterministically.
func (r *Runner) Evaluate(ctx context.Context, input RuleInput, selection Selection) Result {
	rules := r.selectedRules(selection)
	if len(rules) == 0 {
		return Result{}
	}
	if r.parallelism <= 1 || len(rules) == 1 {
		return r.evaluateSequential(ctx, rules, input, selection)
	}
	return r.evaluateParallel(ctx, rules, input, selection)
}

func (r *Runner) evaluateSequential(ctx context.Context, rules []Rule, input RuleInput, selection Selection) Result {
	results := make([]ruleResult, 0, len(rules))
	for index, rule := range rules {
		results = append(results, r.evaluateOne(ctx, index, rule, input, selection))
	}
	return mergeRuleResults(results)
}

func (r *Runner) evaluateParallel(ctx context.Context, rules []Rule, input RuleInput, selection Selection) Result {
	workers := r.parallelism
	if workers > len(rules) {
		workers = len(rules)
	}
	jobs := make(chan ruleJob)
	results := make(chan ruleResult, len(rules))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results <- r.evaluateOne(ctx, job.index, job.rule, input, selection)
			}
		}()
	}
sendJobs:
	for index, rule := range rules {
		select {
		case <-ctx.Done():
			break sendJobs
		case jobs <- ruleJob{index: index, rule: rule}:
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	collected := make([]ruleResult, 0, len(rules))
	for result := range results {
		collected = append(collected, result)
	}
	return mergeRuleResults(collected)
}

type ruleJob struct {
	index int
	rule  Rule
}

type ruleResult struct {
	index       int
	ruleID      string
	findings    []model.Finding
	diagnostics []model.Diagnostic
}

func (r *Runner) evaluateOne(ctx context.Context, index int, rule Rule, input RuleInput, selection Selection) ruleResult {
	meta := rule.Metadata()
	result := ruleResult{index: index, ruleID: meta.ID}
	if err := ctx.Err(); err != nil {
		result.diagnostics = append(result.diagnostics, model.Diagnostic{
			Severity: model.DiagnosticWarning,
			Code:     "RULE_EVALUATION_CANCELLED",
			Message:  fmt.Sprintf("%s: %v", meta.ID, err),
		})
		return result
	}
	ruleFindings, err := evaluateSafely(ctx, rule, input)
	if err != nil {
		result.diagnostics = append(result.diagnostics, model.Diagnostic{
			Severity: model.DiagnosticWarning,
			Code:     "RULE_EVALUATION_FAILED",
			Message:  fmt.Sprintf("%s: %v", meta.ID, err),
		})
		return result
	}
	for _, finding := range ruleFindings {
		finding = applyMetadataDefaults(finding, meta)
		if override, ok := selection.Overrides[meta.ID]; ok {
			finding = model.ApplyOverride(finding, override)
		} else {
			finding = model.NormalizeFinding(finding)
		}
		result.findings = append(result.findings, finding)
	}
	return result
}

func mergeRuleResults(results []ruleResult) Result {
	sort.SliceStable(results, func(i int, j int) bool {
		if results[i].index != results[j].index {
			return results[i].index < results[j].index
		}
		return results[i].ruleID < results[j].ruleID
	})
	findings := make([]model.Finding, 0)
	diagnostics := make([]model.Diagnostic, 0)
	for _, result := range results {
		findings = append(findings, result.findings...)
		diagnostics = append(diagnostics, result.diagnostics...)
	}
	model.SortFindings(findings)
	return Result{Findings: findings, Diagnostics: diagnostics}
}

func (r *Runner) selectedRules(selection Selection) []Rule {
	all := r.registry.Rules()
	selected := make([]Rule, 0, len(all))
	for _, rule := range all {
		meta := rule.Metadata()
		if selection.DisabledRules[meta.ID] {
			continue
		}
		if len(selection.EnabledRules) > 0 && !selection.EnabledRules[meta.ID] {
			continue
		}
		if meta.Status == StatusDeprecated && !selection.EnabledRules[meta.ID] {
			continue
		}
		selected = append(selected, rule)
	}
	sort.SliceStable(selected, func(i int, j int) bool {
		return selected[i].Metadata().ID < selected[j].Metadata().ID
	})
	return selected
}

func evaluateSafely(ctx context.Context, rule Rule, input RuleInput) (findings []model.Finding, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("rule panic: %v", recovered)
		}
	}()
	return rule.Evaluate(ctx, input)
}

func applyMetadataDefaults(finding model.Finding, meta Metadata) model.Finding {
	if finding.RuleID == "" {
		finding.RuleID = meta.ID
	}
	if finding.RuleName == "" {
		finding.RuleName = meta.Title
	}
	if finding.PolicyPack == "" {
		finding.PolicyPack = meta.PolicyPack
	}
	if finding.PolicyPackVersion == "" {
		finding.PolicyPackVersion = meta.Version
	}
	if finding.Title == "" {
		finding.Title = meta.Title
	}
	if finding.Description == "" {
		finding.Description = meta.Description
	}
	if finding.Category == "" {
		finding.Category = meta.Category
	}
	if finding.Severity == "" {
		finding.Severity = meta.Severity
	}
	if finding.Confidence == "" {
		finding.Confidence = meta.Confidence
	}
	if meta.Status == StatusExperimental {
		finding.Suppressions = append(finding.Suppressions, model.Suppression{
			Kind:   "rule_status",
			Reason: "experimental rules do not block by default",
			Active: true,
		})
	}
	return finding
}
