package ci

import (
	"strings"
	"testing"
)

func TestDetectProviders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		env        map[string]string
		provider   Provider
		pr         bool
		annotation bool
	}{
		{
			name: "github pull request",
			env: map[string]string{
				"GITHUB_ACTIONS":      "true",
				"GITHUB_EVENT_NAME":   "pull_request",
				"GITHUB_HEAD_REF":     "feature",
				"GITHUB_SHA":          "abc123",
				"GITHUB_REPOSITORY":   "acme/infra",
				"GITHUB_WORKSPACE":    "/work",
				"GITHUB_STEP_SUMMARY": "/tmp/summary",
			},
			provider:   ProviderGitHub,
			pr:         true,
			annotation: true,
		},
		{
			name: "gitlab merge request",
			env: map[string]string{
				"GITLAB_CI":          "true",
				"CI_PIPELINE_SOURCE": "merge_request_event",
				"CI_COMMIT_SHA":      "def456",
				"CI_PROJECT_PATH":    "acme/infra",
			},
			provider: ProviderGitLab,
			pr:       true,
		},
		{
			name:     "local",
			env:      map[string]string{},
			provider: ProviderUnknown,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Detect(tt.env)
			if got.Provider != tt.provider {
				t.Fatalf("provider = %s, want %s", got.Provider, tt.provider)
			}
			if got.PullRequest != tt.pr {
				t.Fatalf("pull request = %t, want %t", got.PullRequest, tt.pr)
			}
			if tt.annotation && !got.SupportsAnnotations {
				t.Fatalf("expected annotations support: %+v", got)
			}
		})
	}
}

func TestSnippets(t *testing.T) {
	t.Parallel()

	github := GitHubWorkflow(SnippetOptions{WorkingDirectory: "infra/prod", PlanPath: "tfplan.json", AuditFirst: true})
	for _, want := range []string{"infrastructure-risk", "pull-requests: write", "changegate scan --plan tfplan.json --mode audit", "changegate review github", "upload-sarif", "changegate-audit.zip"} {
		if !strings.Contains(github, want) {
			t.Fatalf("GitHub snippet missing %q:\n%s", want, github)
		}
	}

	gitlab := GitLabCI(SnippetOptions{WorkingDirectory: "infra/prod"})
	for _, want := range []string{"changegate.json", "gl-code-quality-report.json", "changegate review gitlab", "changegate.junit.xml", "terraform show -json"} {
		if !strings.Contains(gitlab, want) {
			t.Fatalf("GitLab snippet missing %q:\n%s", want, gitlab)
		}
	}
}
