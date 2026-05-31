package risktest

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Gabriel0110/changegate/internal/output"
)

// ExecutionRequest is passed to the ChangeGate scan executor for one risk test.
type ExecutionRequest struct {
	ManifestPath string
	TestName     string
	PlanPath     string
	ConfigPath   string
	Case         TestCase
}

// Executor runs ChangeGate for one risk test case.
type Executor interface {
	Execute(ctx context.Context, request ExecutionRequest) (output.Report, error)
}

// Result captures one complete risk test run.
type Result struct {
	Passed    bool          `json:"passed"`
	Manifests []ManifestRun `json:"manifests"`
	Summary   Summary       `json:"summary"`
}

// ManifestRun captures all case results from one manifest.
type ManifestRun struct {
	Path  string    `json:"path"`
	Tests []CaseRun `json:"tests"`
	Error string    `json:"error,omitempty"`
}

// CaseRun captures one risk test execution.
type CaseRun struct {
	Name     string    `json:"name"`
	PlanPath string    `json:"plan_path"`
	Config   string    `json:"config,omitempty"`
	Passed   bool      `json:"passed"`
	Failures []Failure `json:"failures,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Summary captures aggregate risk test counts.
type Summary struct {
	Manifests int `json:"manifests"`
	Tests     int `json:"tests"`
	Passed    int `json:"passed"`
	Failed    int `json:"failed"`
	Errors    int `json:"errors"`
}

// Runner executes manifests using an injected scan executor.
type Runner struct {
	Executor        Executor
	UpdateSnapshots bool
}

// RunPath discovers manifests under path and executes them.
func (r Runner) RunPath(ctx context.Context, path string) (Result, error) {
	manifests, err := Discover(path)
	if err != nil {
		return Result{}, err
	}
	return r.RunFiles(ctx, manifests)
}

// RunFiles executes explicit manifest paths.
func (r Runner) RunFiles(ctx context.Context, manifests []string) (Result, error) {
	if r.Executor == nil {
		return Result{}, fmt.Errorf("risk test executor is required")
	}
	result := Result{Passed: true, Manifests: make([]ManifestRun, 0, len(manifests))}
	for _, manifestPath := range manifests {
		run := r.runManifest(ctx, manifestPath)
		result.Manifests = append(result.Manifests, run)
		result.Summary.Manifests++
		result.Summary.Tests += len(run.Tests)
		for _, test := range run.Tests {
			switch {
			case test.Error != "":
				result.Summary.Errors++
				result.Passed = false
			case test.Passed:
				result.Summary.Passed++
			default:
				result.Summary.Failed++
				result.Passed = false
			}
		}
		if run.Error != "" {
			result.Summary.Errors++
			result.Passed = false
		}
	}
	return result, nil
}

func (r Runner) runManifest(ctx context.Context, manifestPath string) ManifestRun {
	manifest, err := LoadFile(manifestPath)
	if err != nil {
		return ManifestRun{Path: manifestPath, Error: err.Error()}
	}
	baseDir := filepath.Dir(manifestPath)
	run := ManifestRun{Path: manifestPath, Tests: make([]CaseRun, 0, len(manifest.Tests))}
	for _, test := range manifest.Tests {
		run.Tests = append(run.Tests, r.runCase(ctx, manifestPath, baseDir, test))
	}
	return run
}

func (r Runner) runCase(ctx context.Context, manifestPath string, baseDir string, test TestCase) CaseRun {
	caseRun := CaseRun{
		Name:     test.Name,
		PlanPath: resolveRelative(baseDir, test.Plan),
		Config:   resolveOptional(baseDir, test.Config),
	}
	report, err := r.Executor.Execute(ctx, ExecutionRequest{
		ManifestPath: manifestPath,
		TestName:     test.Name,
		PlanPath:     caseRun.PlanPath,
		ConfigPath:   caseRun.Config,
		Case:         test,
	})
	if err != nil {
		caseRun.Error = err.Error()
		return caseRun
	}
	caseRun.Failures = Assert(test.Name, report, test.Expect, baseDir, r.UpdateSnapshots)
	caseRun.Passed = len(caseRun.Failures) == 0
	return caseRun
}

func resolveOptional(baseDir string, path string) string {
	if path == "" {
		return ""
	}
	return resolveRelative(baseDir, path)
}

func resolveRelative(baseDir string, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}
