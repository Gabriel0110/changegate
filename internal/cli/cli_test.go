package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestGoldenOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		golden   string
		wantCode int
		stream   string
	}{
		{
			name:     "version plain",
			args:     []string{"--no-color", "version"},
			golden:   "version.txt",
			wantCode: exitAllowed,
			stream:   "stdout",
		},
		{
			name:     "doctor plain",
			args:     []string{"--no-color", "doctor"},
			golden:   "doctor.txt",
			wantCode: exitAllowed,
			stream:   "stdout",
		},
		{
			name:     "scan help",
			args:     []string{"scan", "--help"},
			golden:   "scan-help.txt",
			wantCode: exitAllowed,
			stream:   "stdout",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stdout, stderr, code := runCLI(tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout, stderr)
			}

			got := stdout
			if tt.stream == "stderr" {
				got = stderr
			}
			if tt.golden == "doctor.txt" {
				got = normalizeDoctorPlatform(got)
			}

			assertGolden(t, tt.golden, got)
		})
	}
}

func normalizeDoctorPlatform(output string) string {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "Platform: ") {
			lines[i] = "Platform: <runtime>"
		}
	}
	return strings.Join(lines, "\n")
}

func TestErrorSnapshots(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		golden   string
		wantCode int
	}{
		{
			name:     "missing plan plain",
			args:     []string{"--no-color", "scan"},
			golden:   "missing-plan.txt",
			wantCode: exitUsage,
		},
		{
			name:     "missing plan json",
			args:     []string{"--format", "json", "scan"},
			golden:   "missing-plan.json",
			wantCode: exitUsage,
		},
		{
			name:     "invalid format",
			args:     []string{"--format", "xml", "doctor"},
			golden:   "invalid-format.txt",
			wantCode: exitUsage,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stdout, stderr, code := runCLI(tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout, stderr)
			}

			got := stderr
			if filepath.Ext(tt.golden) == ".json" {
				got = stderr
				assertValidJSON(t, got)
			}

			assertGolden(t, tt.golden, got)
		})
	}
}

func TestJSONSuccessOutputIsValid(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("--format", "json", "doctor")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertValidJSON(t, stdout)
}

func TestScanParsesPlanFile(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("--no-color", "scan", "--plan", "../input/testdata/terraform-plan.json")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	for _, want := range []string{
		"Decision: BLOCK",
		"Tool: terraform",
		"Format: 1.0",
		"Resources: 2",
		"Changes: 4",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestScanReadsPlanFromStdin(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("../input/testdata/opentofu-plan.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	stdout, stderr, code := runCLIWithStdin(string(body), "--format", "json", "scan", "--plan", "-")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertValidJSON(t, stdout)
	if !strings.Contains(stdout, `"tool": "opentofu"`) {
		t.Fatalf("stdout missing OpenTofu tool detection:\n%s", stdout)
	}
}

func TestScanWritesRequestedOutputFormat(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "changegate.sarif")
	stdout, stderr, code := runCLI("--format", "sarif", "--out", outPath, "scan", "--plan", "../input/testdata/terraform-plan.json")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if stdout != "" || stderr != "" {
		t.Fatalf("stdout/stderr = %q/%q, want empty", stdout, stderr)
	}
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read SARIF output: %v", err)
	}
	assertValidJSON(t, string(body))
	if !strings.Contains(string(body), `"version": "2.1.0"`) {
		t.Fatalf("SARIF output missing version:\n%s", string(body))
	}
}

func TestScanWritesAuditBundleArtifact(t *testing.T) {
	t.Parallel()

	bundlePath := filepath.Join(t.TempDir(), "changegate-audit.zip")
	stdout, stderr, code := runCLI("--format", "json", "scan", "--plan", "../input/testdata/terraform-plan.json", "--audit-bundle", bundlePath)
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertValidJSON(t, stdout)
	if !strings.Contains(stdout, `"run":`) || !strings.Contains(stdout, `"compliance":`) {
		t.Fatalf("JSON output missing audit metadata:\n%s", stdout)
	}
	body, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read audit bundle: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open audit bundle: %v", err)
	}
	names := make([]string, 0, len(reader.File))
	for _, file := range reader.File {
		names = append(names, file.Name)
	}
	sort.Strings(names)
	for _, want := range []string{
		"changegate-audit/decision.json",
		"changegate-audit/evidence.json",
		"changegate-audit/plan-digest.txt",
		"changegate-audit/run-metadata.json",
		"changegate-audit/summary.md",
	} {
		if !containsString(names, want) {
			t.Fatalf("audit bundle missing %s in %+v", want, names)
		}
	}
}

func TestScanPerformanceControls(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	importPath := filepath.Join(tempDir, "findings.json")
	body := `{
  "findings": [
    {"rule_id": "CUSTOM_ONE", "title": "one", "resource_address": "aws_s3_bucket.one", "category": "sensitive", "severity": "high", "confidence": "medium"},
    {"rule_id": "CUSTOM_TWO", "title": "two", "resource_address": "aws_s3_bucket.two", "category": "sensitive", "severity": "high", "confidence": "medium"}
  ]
}`
	if err := os.WriteFile(importPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	stdout, stderr, code := runCLI("--format", "json", "scan", "--plan", "../input/testdata/terraform-plan.json", "--import-json", importPath, "--max-findings", "1", "--changed-only", "--timeout", "5s")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	var report struct {
		Findings    []any `json:"findings"`
		Diagnostics []struct {
			Code string `json:"code"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want capped to 1\n%s", len(report.Findings), stdout)
	}
	if !diagnosticCodePresent(report.Diagnostics, "MAX_FINDINGS_TRUNCATED") {
		t.Fatalf("missing max findings diagnostic:\n%s", stdout)
	}
}

func TestScanImportsExternalFindings(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	importPath := filepath.Join(tempDir, "findings.json")
	body := `{
  "findings": [
    {
      "rule_id": "CUSTOM_PUBLIC_BUCKET",
      "title": "duplicate public bucket",
      "resource_address": "aws_s3_bucket.logs",
      "category": "sensitive",
      "severity": "high",
      "confidence": "medium"
    },
    {
      "rule_id": "CUSTOM_DB_CONTEXT",
      "title": "context-backed database finding",
      "resource_address": "module.database.aws_db_instance.customer",
      "category": "public",
      "severity": "medium",
      "confidence": "medium"
    }
  ]
}`
	if err := os.WriteFile(importPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write import fixture: %v", err)
	}

	stdout, stderr, code := runCLI("--format", "json", "scan", "--plan", "../input/testdata/terraform-plan.json", "--import-json", importPath)
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertValidJSON(t, stdout)
	for _, want := range []string{
		`"imports": {`,
		`"imported": 2`,
		`"deduplicated": 1`,
		`"correlated": 1`,
		`"policy_pack": "external:generic-json"`,
		`"type": "external_scanner"`,
		`"type": "external_correlation"`,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("scan output missing %q:\n%s", want, stdout)
		}
	}
}

func TestScanImportFailureIsOptional(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.sarif")
	stdout, stderr, code := runCLI("--format", "json", "scan", "--plan", "../input/testdata/terraform-plan.json", "--import-sarif", missing)
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if !strings.Contains(stdout, "ADAPTER_IMPORT_FAILED") {
		t.Fatalf("non-fatal import failure missing diagnostic:\n%s", stdout)
	}

	stdout, stderr, code = runCLI("--format", "json", "scan", "--plan", "../input/testdata/terraform-plan.json", "--import-sarif", missing, "--fail-on-import-error")
	if code != exitInputParsing {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitInputParsing, stdout, stderr)
	}
	if !strings.Contains(stderr, "ADAPTER_IMPORT_FAILED") && !strings.Contains(stderr, "no such file") {
		t.Fatalf("fatal import failure missing reason:\n%s", stderr)
	}
}

func TestImportedFindingCanBeWaived(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	importPath := filepath.Join(tempDir, "findings.json")
	body := `{"findings":[{"rule_id":"CUSTOM_QUEUE_PUBLIC","title":"queue is public","resource_address":"aws_sqs_queue.jobs","category":"public","severity":"high","confidence":"high"}]}`
	if err := os.WriteFile(importPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write import fixture: %v", err)
	}

	stdout, stderr, code := runCLI("--format", "json", "scan", "--plan", "../input/testdata/opentofu-plan.json", "--import-json", importPath)
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	var report struct {
		Findings []struct {
			RuleID          string `json:"rule_id"`
			ResourceAddress string `json:"resource_address"`
			Fingerprint     string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal scan report: %v", err)
	}
	if len(report.Findings) != 1 || !strings.HasPrefix(report.Findings[0].RuleID, "EXT_GENERIC_JSON_") {
		t.Fatalf("unexpected imported findings: %#v", report.Findings)
	}

	waiverPath := filepath.Join(tempDir, "waivers.yaml")
	stdout, stderr, code = runCLI(
		"waiver", "add",
		"--file", waiverPath,
		"--rule", report.Findings[0].RuleID,
		"--resource", report.Findings[0].ResourceAddress,
		"--fingerprint", report.Findings[0].Fingerprint,
		"--owner", "platform@example.com",
		"--reason", "External scanner finding accepted temporarily.",
		"--expires-at", "2026-08-01",
		"--evidence-fingerprint", report.Findings[0].Fingerprint,
	)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}

	policyPath := filepath.Join(tempDir, "policy.yaml")
	policyBody := "version: 1\nwaivers:\n  file: " + waiverPath + "\n"
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	stdout, stderr, code = runCLI("--format", "json", "--policy", policyPath, "scan", "--plan", "../input/testdata/opentofu-plan.json", "--import-json", importPath)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, `"suppressed": 1`) || !strings.Contains(stdout, `"policy_pack": "external:generic-json"`) {
		t.Fatalf("waived external finding missing suppression evidence:\n%s", stdout)
	}
}

func TestScanSupportsMultiplePlansAndCacheDir(t *testing.T) {
	t.Parallel()

	cacheDir := filepath.Join(t.TempDir(), "cache")
	stdout, stderr, code := runCLI(
		"--format", "json",
		"--cache-dir", cacheDir,
		"scan",
		"--plan", "../input/testdata/terraform-plan.json",
		"--plan", "../input/testdata/opentofu-plan.json",
	)
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertValidJSON(t, stdout)
	for _, want := range []string{`"path": "multiple"`, `"tool": "unknown"`, `"message": "2 plans parsed, graphs built, and policies evaluated"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("multi-plan output missing %q:\n%s", want, stdout)
		}
	}
	for _, dir := range []string{"policy-packs", "cloud-context"} {
		if _, err := os.Stat(filepath.Join(cacheDir, dir)); err != nil {
			t.Fatalf("cache dir %s missing: %v", dir, err)
		}
	}
}

func TestCICommands(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("ci", "github", "--working-directory", "infra/prod", "--audit-first")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	for _, want := range []string{"infrastructure-risk", "working-directory: infra/prod", "--mode audit"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("GitHub snippet missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, code = runCLI("ci", "gitlab", "--working-directory", "infra/prod")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	for _, want := range []string{"gl-code-quality-report.json", "changegate.junit.xml"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("GitLab snippet missing %q:\n%s", want, stdout)
		}
	}
}

func TestCIInstallGitHub(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "changegate.yml")
	stdout, stderr, code := runCLI("ci", "install", "github", "--path", path, "--working-directory", "infra/prod")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Installed GitHub Actions workflow") {
		t.Fatalf("stdout missing install confirmation:\n%s", stdout)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read installed workflow: %v", err)
	}
	if !strings.Contains(string(body), "working-directory: infra/prod") {
		t.Fatalf("installed workflow missing working directory:\n%s", string(body))
	}
}

func TestBaselineCreateDiffAndNewOnlyScan(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "baseline.json")
	stdout, stderr, code := runCLI(
		"baseline", "create",
		"--plan", "../input/testdata/terraform-plan.json",
		"--out", path,
		"--expires-at", "2026-08-01T00:00:00Z",
	)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Findings: 2") {
		t.Fatalf("baseline create output missing finding count:\n%s", stdout)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	assertValidJSON(t, string(body))
	for _, forbidden := range []string{"super-secret", "old-secret", "new-secret"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("baseline leaked %q:\n%s", forbidden, string(body))
		}
	}

	stdout, stderr, code = runCLI("--no-color", "scan", "--plan", "../input/testdata/terraform-plan.json", "--baseline", path, "--new-only")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Suppressed or downgraded: 2") {
		t.Fatalf("new-only scan did not suppress baseline findings:\n%s", stdout)
	}

	stdout, stderr, code = runCLI("--format", "json", "baseline", "diff", "--baseline", path, "--plan", "../input/testdata/terraform-plan.json")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	assertValidJSON(t, stdout)
	for _, want := range []string{`"new": 0`, `"unchanged": 2`, `"stale": 0`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("baseline diff missing %q:\n%s", want, stdout)
		}
	}
}

func TestBaselineNewFindingsStillBlockAndPolicyRequiresExpiration(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	emptyBaseline := filepath.Join(tempDir, "empty-baseline.json")
	stdout, stderr, code := runCLI(
		"baseline", "create",
		"--plan", "../input/testdata/opentofu-plan.json",
		"--out", emptyBaseline,
	)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}

	stdout, stderr, code = runCLI("--no-color", "scan", "--plan", "../input/testdata/terraform-plan.json", "--baseline", emptyBaseline, "--new-only")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if !strings.Contains(stdout, "Decision: BLOCK") {
		t.Fatalf("new finding scan did not block:\n%s", stdout)
	}

	policyPath := filepath.Join(tempDir, "policy.yaml")
	policyBody := "version: 1\nbaseline:\n  file: " + emptyBaseline + "\n  mode: new-risk-only\n  require_expiration: true\n"
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	stdout, stderr, code = runCLI("--policy", policyPath, "scan", "--plan", "../input/testdata/terraform-plan.json")
	if code != exitPolicyConfiguration {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitPolicyConfiguration, stdout, stderr)
	}
	if !strings.Contains(stderr, "baseline policy requires expires_at") {
		t.Fatalf("policy error missing baseline expiration reason:\n%s", stderr)
	}
}

func TestWaiverCommandsAndScanSuppression(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("--format", "json", "scan", "--plan", "../input/testdata/terraform-plan.json")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	var report struct {
		Findings []struct {
			RuleID          string `json:"rule_id"`
			ResourceAddress string `json:"resource_address"`
			Fingerprint     string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal scan report: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}

	tempDir := t.TempDir()
	waiverPath := filepath.Join(tempDir, "waivers.yaml")
	for _, finding := range report.Findings {
		stdout, stderr, code = runCLI(
			"waiver", "add",
			"--file", waiverPath,
			"--rule", finding.RuleID,
			"--resource", finding.ResourceAddress,
			"--fingerprint", finding.Fingerprint,
			"--owner", "platform@example.com",
			"--reason", "Temporary migration exception.",
			"--expires-at", "2026-08-01",
			"--evidence-fingerprint", finding.Fingerprint,
		)
		if code != exitAllowed {
			t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
		}
	}

	stdout, stderr, code = runCLI("waiver", "validate", "--file", waiverPath)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Waivers: valid") {
		t.Fatalf("validate output missing success:\n%s", stdout)
	}

	stdout, stderr, code = runCLI("waiver", "report", "--file", waiverPath, "--plan", "../input/testdata/terraform-plan.json")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Applied: 2") {
		t.Fatalf("report output missing applied waivers:\n%s", stdout)
	}

	policyPath := filepath.Join(tempDir, "policy.yaml")
	policyBody := "version: 1\nwaivers:\n  file: " + waiverPath + "\n  require_expiration: true\n"
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	stdout, stderr, code = runCLI("--no-color", "--policy", policyPath, "scan", "--plan", "../input/testdata/terraform-plan.json")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Suppressed or downgraded: 2") {
		t.Fatalf("scan did not suppress waived findings:\n%s", stdout)
	}
}

func TestWaiverValidationAndPruneExpired(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	waiverPath := filepath.Join(tempDir, "waivers.yaml")
	body := []byte(`version: 1
waivers:
  - id: WVR-001
    rule_id: AWS_STATEFUL_REPLACEMENT
    resource: module.database.aws_db_instance.customer
    owner: platform@example.com
    reason: Temporary.
    created_at: 2026-01-01
    expires_at: 2026-01-31
`)
	if err := os.WriteFile(waiverPath, body, 0o644); err != nil {
		t.Fatalf("write waiver: %v", err)
	}

	stdout, stderr, code := runCLI("waiver", "validate", "--file", waiverPath)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Warning: waiver WVR-001 has expired") {
		t.Fatalf("validate output missing expired warning:\n%s", stdout)
	}

	stdout, stderr, code = runCLI("waiver", "prune", "--file", waiverPath)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Pruned: 1") {
		t.Fatalf("prune output missing count:\n%s", stdout)
	}
	next, err := os.ReadFile(waiverPath)
	if err != nil {
		t.Fatalf("read pruned waiver: %v", err)
	}
	if strings.Contains(string(next), "WVR-001") {
		t.Fatalf("expired waiver was not pruned:\n%s", string(next))
	}
}

func TestPolicyCanFailOnExpiredWaivers(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	waiverPath := filepath.Join(tempDir, "waivers.yaml")
	body := []byte(`version: 1
waivers:
  - id: WVR-001
    rule_id: AWS_STATEFUL_REPLACEMENT
    resource: module.database.aws_db_instance.customer
    owner: platform@example.com
    reason: Temporary.
    created_at: 2026-01-01
    expires_at: 2026-01-31
`)
	if err := os.WriteFile(waiverPath, body, 0o644); err != nil {
		t.Fatalf("write waiver: %v", err)
	}
	policyPath := filepath.Join(tempDir, "policy.yaml")
	policyBody := "version: 1\nwaivers:\n  file: " + waiverPath + "\n  fail_expired: true\n"
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	stdout, stderr, code := runCLI("--policy", policyPath, "scan", "--plan", "../input/testdata/terraform-plan.json")
	if code != exitPolicyConfiguration {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitPolicyConfiguration, stdout, stderr)
	}
	if !strings.Contains(stderr, "waiver file contains expired waivers") {
		t.Fatalf("stderr missing expired waiver policy failure:\n%s", stderr)
	}
}

func TestPolicyValidateFailsMalformedConfiguredWaivers(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	waiverPath := filepath.Join(tempDir, "waivers.yaml")
	body := []byte(`version: 1
waivers:
  - id: WVR-001
    rule_id: AWS_STATEFUL_REPLACEMENT
    reason: Missing owner.
    created_at: 2026-05-01
    expires_at: 2026-08-01
`)
	if err := os.WriteFile(waiverPath, body, 0o644); err != nil {
		t.Fatalf("write waiver: %v", err)
	}
	policyPath := filepath.Join(tempDir, "policy.yaml")
	policyBody := "version: 1\nwaivers:\n  file: " + waiverPath + "\n"
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	stdout, stderr, code := runCLI("policy", "validate", policyPath)
	if code != exitPolicyConfiguration {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitPolicyConfiguration, stdout, stderr)
	}
	if !strings.Contains(stderr, "requires owner") {
		t.Fatalf("stderr missing waiver validation reason:\n%s", stderr)
	}
}

func TestCloudContextCommandsAndScanEnrichment(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	contextPath := filepath.Join(tempDir, "aws-context.json")
	stdout, stderr, code := runCLI("context", "aws", "snapshot", "--out", contextPath)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Network calls: none") {
		t.Fatalf("snapshot output missing no-network guarantee:\n%s", stdout)
	}
	body := `{
  "version": 1,
  "provider": "aws",
  "generated_at": "2026-05-29T00:00:00Z",
  "account": {"id": "123456789012"},
  "capabilities": {
    "identity": true,
    "network": true,
    "security_groups": true,
    "iam": true,
    "s3": true,
    "rds": true,
    "kms": true,
    "secrets_manager": true,
    "eks": true
  },
  "resources": {
    "aws_s3_bucket.logs": {
      "address": "aws_s3_bucket.logs",
      "region": "us-east-1",
      "related_sensitive_data": ["aws_db_instance.customer"],
      "drift": {"logging": "actual disabled"}
    }
  }
}`
	if err := os.WriteFile(contextPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write context: %v", err)
	}

	stdout, stderr, code = runCLI("--format", "json", "scan", "--plan", "../input/testdata/terraform-plan.json", "--context-file", contextPath)
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	assertValidJSON(t, stdout)
	if !strings.Contains(stdout, `"severity": "critical"`) || !strings.Contains(stdout, "cloud context found sensitive data relationship") {
		t.Fatalf("scan output missing cloud context enrichment:\n%s", stdout)
	}
	if strings.Contains(stdout, "secret-value") {
		t.Fatalf("scan output leaked sensitive context:\n%s", stdout)
	}

	stdout, stderr, code = runCLI("context", "aws", "validate-permissions", "--context-file", contextPath)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Permissions: complete") {
		t.Fatalf("permissions output missing complete state:\n%s", stdout)
	}
}

func TestCloudContextCacheAndDisabledNoNetwork(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("--format", "json", "scan", "--plan", "../input/testdata/terraform-plan.json")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if strings.Contains(stdout, "CLOUD_CONTEXT") {
		t.Fatalf("default scan unexpectedly used cloud context:\n%s", stdout)
	}

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cloud-context", "aws-context.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}
	if err := os.WriteFile(cachePath, []byte(`{"version":1,"provider":"aws","generated_at":"2026-05-29T00:00:00Z","account":{"id":"123"},"resources":{}}`), 0o644); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	stdout, stderr, code = runCLI("--format", "json", "--cache-dir", cacheDir, "scan", "--plan", "../input/testdata/terraform-plan.json", "--cloud-context", "aws")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if !strings.Contains(stdout, "CLOUD_CONTEXT_PERMISSION_MISSING") {
		t.Fatalf("cache-backed context did not emit permission diagnostics:\n%s", stdout)
	}
}

func TestScanDebugPlanModelRedactsSensitiveValues(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("scan", "--plan", "../input/testdata/terraform-plan.json", "--debug-plan-model")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	assertValidJSON(t, stdout)
	for _, forbidden := range []string{"super-secret", "old-secret", "new-secret"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("debug model leaked %q:\n%s", forbidden, stdout)
		}
	}
	if !strings.Contains(stdout, "(sensitive)") {
		t.Fatalf("debug model missing redaction marker:\n%s", stdout)
	}
}

func TestScanDebugGraph(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("scan", "--plan", "../input/testdata/terraform-plan.json", "--debug-graph")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertValidJSON(t, stdout)
	if !strings.Contains(stdout, `"nodes"`) || !strings.Contains(stdout, `"edges"`) {
		t.Fatalf("debug graph missing nodes/edges:\n%s", stdout)
	}
}

func TestScanInvalidJSONError(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLIWithStdin("{", "--format", "json", "scan", "--plan", "-")
	if code != exitInputParsing {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitInputParsing, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertValidJSON(t, stderr)
	if !strings.Contains(stderr, `"type": "input"`) {
		t.Fatalf("stderr missing input type:\n%s", stderr)
	}
}

func TestScanUnsupportedFormatError(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLIWithStdin(`{"format_version":"2.0"}`, "--format", "json", "scan", "--plan", "-")
	if code != exitUnsupported {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitUnsupported, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	assertValidJSON(t, stderr)
	if !strings.Contains(stderr, `"type": "unsupported"`) {
		t.Fatalf("stderr missing unsupported type:\n%s", stderr)
	}
}

func TestCompletionUnsupportedShell(t *testing.T) {
	t.Parallel()

	_, stderr, code := runCLI("completion", "powershell")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitUsage, stderr)
	}
}

func TestRulesCommands(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("--no-color", "rules", "list")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	for _, want := range []string{
		"AWS_SG_WORLD_OPEN_ADMIN_PORT  stable  enabled",
		"AWS_PUBLIC_ADMIN_SERVICE  stable  enabled",
		"AWS_IAM_ADMIN_POLICY_ATTACHMENT  stable  enabled",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("rules list missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, code = runCLI("--no-color", "rules", "describe", "AWS_SG_WORLD_OPEN_ADMIN_PORT")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Security group opens admin port to the world") {
		t.Fatalf("describe output missing title:\n%s", stdout)
	}
}

func TestExplainCommand(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("--no-color", "explain", "AWS_PUBLIC_ADMIN_SERVICE")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	for _, want := range []string{"What happened:", "Why it matters:", "Recommended fix:", "Fix confidence:", "Automatic patch: not generated"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("explain output missing %q:\n%s", want, stdout)
		}
	}

	tempDir := t.TempDir()
	reportPath := filepath.Join(tempDir, "report.json")
	stdout, stderr, code = runCLI("--format", "json", "--out", reportPath, "scan", "--plan", "../input/testdata/terraform-plan.json")
	if code != exitBlocked {
		t.Fatalf("scan exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	stdout, stderr, code = runCLI("--no-color", "explain", "AWS_S3_SENSITIVE_BUCKET_LOGGING_DISABLED", "--report", reportPath)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Evidence:") || !strings.Contains(stdout, "aws_s3_bucket.logs") {
		t.Fatalf("report-backed explain missing evidence:\n%s", stdout)
	}

	stdout, stderr, code = runCLI("explain", "AWS_PUBLIC_ADMIN_SERVICE", "--json")
	if code != exitAllowed {
		t.Fatalf("json explain exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	assertValidJSON(t, stdout)
	if !strings.Contains(stdout, `"safe_to_apply": false`) {
		t.Fatalf("json explain missing advisory patch safety signal:\n%s", stdout)
	}
}

func TestPolicyCommands(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("--no-color", "policy", "validate", "testdata/policy-valid.yaml")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Policy: valid") {
		t.Fatalf("validate output missing success:\n%s", stdout)
	}

	stdout, stderr, code = runCLI("--format", "json", "policy", "test", "testdata/policy-valid.yaml")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	assertValidJSON(t, stdout)
	if !strings.Contains(stdout, `"enabled_rules": 16`) {
		t.Fatalf("policy test output missing enabled count:\n%s", stdout)
	}
}

func TestCustomPolicyRulesScanAndValidate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	rulePath := filepath.Join(tempDir, "rules.yaml")
	ruleBody := `id: ORG_QUEUE_REVIEW
title: SQS queue requires review
category: compliance
severity: high
confidence: high
select:
  type: aws_sqs_queue
where:
  all:
    - field: name
      equals: jobs
remediation: Review queue access policy.
`
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	policyPath := filepath.Join(tempDir, ".changegate.yaml")
	policyBody := "version: 1\ncustom_rules:\n  files:\n    - rules.yaml\n"
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	stdout, stderr, code := runCLI("--no-color", "--policy", policyPath, "policy", "validate", policyPath)
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if !strings.Contains(stdout, "Policy: valid") {
		t.Fatalf("validate output missing success:\n%s", stdout)
	}

	stdout, stderr, code = runCLI("--format", "json", "--policy", policyPath, "scan", "--plan", "../input/testdata/opentofu-plan.json")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	for _, want := range []string{
		`"rule_id": "ORG_QUEUE_REVIEW"`,
		`"policy_pack": "custom-yaml"`,
		`"type": "custom_rule"`,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("custom rule scan missing %q:\n%s", want, stdout)
		}
	}

	badRulePath := filepath.Join(tempDir, "bad.yaml")
	if err := os.WriteFile(badRulePath, []byte("id: BAD\nunknown: value\n"), 0o644); err != nil {
		t.Fatalf("write bad rule: %v", err)
	}
	badPolicyPath := filepath.Join(tempDir, "bad-policy.yaml")
	if err := os.WriteFile(badPolicyPath, []byte("version: 1\ncustom_rules:\n  files:\n    - bad.yaml\n"), 0o644); err != nil {
		t.Fatalf("write bad policy: %v", err)
	}
	stdout, stderr, code = runCLI("--policy", badPolicyPath, "policy", "validate", badPolicyPath)
	if code != exitPolicyConfiguration {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitPolicyConfiguration, stdout, stderr)
	}
	if !strings.Contains(stderr, "CUSTOM_RULE_FILE_INVALID") && !strings.Contains(stderr, "field unknown not found") {
		t.Fatalf("bad custom rule did not fail validation clearly:\n%s", stderr)
	}
}

func TestRegoPolicyScan(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	regoPath := filepath.Join(tempDir, "queue.rego")
	regoBody := `package changegate

findings[f] {
	change := input.changes[_]
	change.type == "aws_sqs_queue"
	f := {
		"rule_id": "ORG_REGO_QUEUE",
		"title": "Rego queue review",
		"resource_address": change.address,
		"category": "compliance",
		"severity": "high",
		"confidence": "high"
	}
}
`
	if err := os.WriteFile(regoPath, []byte(regoBody), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	policyPath := filepath.Join(tempDir, ".changegate.yaml")
	policyBody := `version: 1
rego:
  files:
    - queue.rego
  query: data.changegate.findings
  timeout: 1s
`
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	stdout, stderr, code := runCLI("--format", "json", "--policy", policyPath, "scan", "--plan", "../input/testdata/opentofu-plan.json")
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitBlocked, stdout, stderr)
	}
	if !strings.Contains(stdout, `"rule_id": "ORG_REGO_QUEUE"`) || !strings.Contains(stdout, `"policy_pack": "custom-rego"`) {
		t.Fatalf("rego scan missing custom finding:\n%s", stdout)
	}
}

func TestScanWarnAndAuditModesDoNotReturnBlockCode(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"warn", "audit"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runCLI("--no-color", "--mode", mode, "scan", "--plan", "../input/testdata/terraform-plan.json")
			if code != exitAllowed {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
			}
			if !strings.Contains(stdout, "Decision: WARN") {
				t.Fatalf("stdout missing warning decision:\n%s", stdout)
			}
		})
	}
}

func TestPolicyContextValidation(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runCLI("--format", "json", "policy", "validate", "testdata/policy-context.yaml")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	assertValidJSON(t, stdout)
}

func runCLI(args ...string) (string, string, int) {
	return runCLIWithStdin("", args...)
}

func runCLIWithStdin(stdin string, args ...string) (string, string, int) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(context.Background(), args, strings.NewReader(stdin), &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func assertGolden(t *testing.T, name string, got string) {
	t.Helper()

	path := filepath.Join("testdata", "golden", name)
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}

	if got != string(wantBytes) {
		t.Fatalf("output mismatch for %s\nwant:\n%s\ngot:\n%s", name, string(wantBytes), got)
	}
}

func assertValidJSON(t *testing.T, got string) {
	t.Helper()

	var value any
	if err := json.Unmarshal([]byte(got), &value); err != nil {
		t.Fatalf("invalid JSON %q: %v", got, err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func diagnosticCodePresent(values []struct {
	Code string `json:"code"`
}, want string) bool {
	for _, value := range values {
		if value.Code == want {
			return true
		}
	}
	return false
}
