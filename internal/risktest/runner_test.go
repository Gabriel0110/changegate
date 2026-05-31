package risktest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
)

func TestDiscoverFindsManifestFileAndDirectory(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	rootManifest := filepath.Join(tempDir, "changegate-test.yaml")
	nestedDir := filepath.Join(tempDir, "modules", "api")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	nestedManifest := filepath.Join(nestedDir, "api.changegate-test.yaml")
	for _, path := range []string{rootManifest, nestedManifest, filepath.Join(tempDir, ".git", "changegate-test.yaml")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte("version: 1\ntests:\n  - name: x\n    plan: plan.json\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	paths, err := Discover(rootManifest)
	if err != nil {
		t.Fatalf("Discover file returned error: %v", err)
	}
	if len(paths) != 1 || paths[0] != rootManifest {
		t.Fatalf("file discovery = %#v", paths)
	}

	paths, err = Discover(tempDir)
	if err != nil {
		t.Fatalf("Discover dir returned error: %v", err)
	}
	want := []string{rootManifest, nestedManifest}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("directory discovery = %#v, want %#v", paths, want)
	}
}

func TestRunnerExecutesManifestsWithResolvedPaths(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "changegate-test.yaml")
	manifest := `
version: 1
tests:
  - name: passes
    plan: fixtures/pass.json
    config: fixtures/changegate.yaml
    expect:
      decision: allow
  - name: fails
    plan: fixtures/fail.json
    expect:
      decision: block
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	executor := &fakeExecutor{reports: map[string]output.Report{
		"passes": {Decision: model.DecisionAllow},
		"fails":  {Decision: model.DecisionAllow},
	}}

	result, err := Runner{Executor: executor}.RunPath(context.Background(), manifestPath)
	if err != nil {
		t.Fatalf("RunPath returned error: %v", err)
	}
	if result.Passed {
		t.Fatalf("result unexpectedly passed: %#v", result)
	}
	if result.Summary.Tests != 2 || result.Summary.Passed != 1 || result.Summary.Failed != 1 {
		t.Fatalf("summary = %#v", result.Summary)
	}
	if len(executor.requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(executor.requests))
	}
	first := executor.requests[0]
	if first.PlanPath != filepath.Join(tempDir, "fixtures", "pass.json") || first.ConfigPath != filepath.Join(tempDir, "fixtures", "changegate.yaml") {
		t.Fatalf("paths not resolved: %#v", first)
	}
}

func TestRunnerRecordsExecutionErrors(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "changegate-test.yaml")
	if err := os.WriteFile(manifestPath, []byte("version: 1\ntests:\n  - name: boom\n    plan: plan.json\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	result, err := Runner{Executor: &fakeExecutor{err: fmt.Errorf("scan failed")}}.RunPath(context.Background(), manifestPath)
	if err != nil {
		t.Fatalf("RunPath returned error: %v", err)
	}
	if result.Passed || result.Summary.Errors != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Manifests[0].Tests[0].Error != "scan failed" {
		t.Fatalf("case error = %q", result.Manifests[0].Tests[0].Error)
	}
}

type fakeExecutor struct {
	reports  map[string]output.Report
	requests []ExecutionRequest
	err      error
}

func (f *fakeExecutor) Execute(_ context.Context, request ExecutionRequest) (output.Report, error) {
	f.requests = append(f.requests, request)
	if f.err != nil {
		return output.Report{}, f.err
	}
	report, ok := f.reports[request.TestName]
	if !ok {
		return output.Report{}, fmt.Errorf("missing fake report for %s", request.TestName)
	}
	return report, nil
}
