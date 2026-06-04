package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitDryRunIncludesAuditModeConfigAndCI(t *testing.T) {
	stdout, stderr, code := runCLI("init", "--dry-run", "--github-actions", "--gitlab-ci", "--baseline", "--waivers")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	for _, want := range []string{
		"--- .changegate.yaml",
		"mode: audit",
		"--- .github/workflows/changegate.yml",
		"changegate review github",
		"--- .gitlab-ci.yml",
		"changegate review gitlab",
		"--- .changegate/waivers.yaml",
		"--- .changegate/README.md",
		"baseline create",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("dry-run output missing %q:\n%s", want, stdout)
		}
	}
}

func TestInitWritesFilesAndRefusesOverwrite(t *testing.T) {
	tempDir := t.TempDir()
	stdout, stderr, code := runCLI("init", "--dir", tempDir, "--github-actions", "--gitlab-ci", "--baseline", "--waivers")
	if code != exitAllowed {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitAllowed, stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	for _, path := range []string{
		".changegate.yaml",
		".changegate/README.md",
		".changegate/waivers.yaml",
		".github/workflows/changegate.yml",
		".gitlab-ci.yml",
	} {
		if _, err := os.Stat(filepath.Join(tempDir, filepath.FromSlash(path))); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	stdout, stderr, code = runCLI("init", "--dir", tempDir)
	if code != exitUsage {
		t.Fatalf("overwrite exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitUsage, stdout, stderr)
	}
	if !strings.Contains(stderr, "already exists") || !strings.Contains(stderr, "--force") {
		t.Fatalf("overwrite error missing guidance:\n%s", stderr)
	}
}
