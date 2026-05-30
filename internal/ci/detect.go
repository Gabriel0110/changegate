// Package ci contains CI provider detection and adoption snippets.
package ci

// Provider identifies a supported CI system.
type Provider string

const (
	ProviderUnknown   Provider = "unknown"
	ProviderGitHub    Provider = "github-actions"
	ProviderGitLab    Provider = "gitlab-ci"
	ProviderCircleCI  Provider = "circleci"
	ProviderBuildkite Provider = "buildkite"
	ProviderJenkins   Provider = "jenkins"
	ProviderAtlantis  Provider = "atlantis"
)

// DetectionResult describes the current CI environment without exposing secrets.
type DetectionResult struct {
	Detected            bool     `json:"detected"`
	Provider            Provider `json:"provider"`
	Name                string   `json:"name"`
	PullRequest         bool     `json:"pull_request"`
	Branch              string   `json:"branch,omitempty"`
	CommitSHA           string   `json:"commit_sha,omitempty"`
	Repository          string   `json:"repository,omitempty"`
	Workspace           string   `json:"workspace,omitempty"`
	BuildURL            string   `json:"build_url,omitempty"`
	SupportsSARIF       bool     `json:"supports_sarif"`
	SupportsAnnotations bool     `json:"supports_annotations"`
	SupportsStepSummary bool     `json:"supports_step_summary"`
	Notes               []string `json:"notes,omitempty"`
}

// Detect returns CI metadata from environment variables. Values are intentionally non-secret.
func Detect(env map[string]string) DetectionResult {
	switch {
	case env["GITHUB_ACTIONS"] == "true":
		return detectGitHub(env)
	case env["GITLAB_CI"] == "true":
		return detectGitLab(env)
	case env["CIRCLECI"] == "true":
		return DetectionResult{
			Detected:            true,
			Provider:            ProviderCircleCI,
			Name:                "CircleCI",
			PullRequest:         env["CIRCLE_PULL_REQUEST"] != "",
			Branch:              env["CIRCLE_BRANCH"],
			CommitSHA:           env["CIRCLE_SHA1"],
			Repository:          firstNonEmpty(env["CIRCLE_PROJECT_USERNAME"]+"/"+env["CIRCLE_PROJECT_REPONAME"], env["CIRCLE_PROJECT_REPONAME"]),
			Workspace:           env["CIRCLE_WORKING_DIRECTORY"],
			BuildURL:            env["CIRCLE_BUILD_URL"],
			SupportsSARIF:       false,
			SupportsAnnotations: false,
			SupportsStepSummary: false,
			Notes:               []string{"Use JUnit or Markdown artifacts for CircleCI review surfaces."},
		}
	case env["BUILDKITE"] == "true":
		return DetectionResult{
			Detected:            true,
			Provider:            ProviderBuildkite,
			Name:                "Buildkite",
			PullRequest:         env["BUILDKITE_PULL_REQUEST"] != "" && env["BUILDKITE_PULL_REQUEST"] != "false",
			Branch:              env["BUILDKITE_BRANCH"],
			CommitSHA:           env["BUILDKITE_COMMIT"],
			Repository:          env["BUILDKITE_REPO"],
			Workspace:           env["BUILDKITE_BUILD_CHECKOUT_PATH"],
			BuildURL:            env["BUILDKITE_BUILD_URL"],
			SupportsSARIF:       false,
			SupportsAnnotations: true,
			SupportsStepSummary: false,
			Notes:               []string{"Use annotations or uploaded Markdown artifacts for Buildkite."},
		}
	case env["JENKINS_URL"] != "" || env["BUILD_ID"] != "" && env["WORKSPACE"] != "":
		return DetectionResult{
			Detected:            true,
			Provider:            ProviderJenkins,
			Name:                "Jenkins",
			PullRequest:         env["CHANGE_ID"] != "",
			Branch:              firstNonEmpty(env["BRANCH_NAME"], env["GIT_BRANCH"]),
			CommitSHA:           env["GIT_COMMIT"],
			Repository:          env["GIT_URL"],
			Workspace:           env["WORKSPACE"],
			BuildURL:            env["BUILD_URL"],
			SupportsSARIF:       false,
			SupportsAnnotations: false,
			SupportsStepSummary: false,
			Notes:               []string{"Publish JUnit XML and Markdown artifacts from Jenkins."},
		}
	case env["ATLANTIS_TERRAFORM_VERSION"] != "" || env["ATLANTIS_REPO_OWNER"] != "":
		return DetectionResult{
			Detected:            true,
			Provider:            ProviderAtlantis,
			Name:                "Atlantis",
			PullRequest:         env["PULL_NUM"] != "",
			Branch:              env["HEAD_BRANCH_NAME"],
			CommitSHA:           env["HEAD_COMMIT"],
			Repository:          firstNonEmpty(env["BASE_REPO_OWNER"]+"/"+env["BASE_REPO_NAME"], env["ATLANTIS_REPO_OWNER"]+"/"+env["ATLANTIS_REPO_NAME"]),
			Workspace:           env["DIR"],
			SupportsSARIF:       false,
			SupportsAnnotations: false,
			SupportsStepSummary: false,
			Notes:               []string{"Run ChangeGate after plan JSON generation in an Atlantis custom workflow."},
		}
	default:
		return DetectionResult{
			Provider: ProviderUnknown,
			Name:     "local",
			Notes:    []string{"No supported CI environment variables were detected."},
		}
	}
}

func detectGitHub(env map[string]string) DetectionResult {
	buildURL := ""
	if env["GITHUB_SERVER_URL"] != "" && env["GITHUB_REPOSITORY"] != "" && env["GITHUB_RUN_ID"] != "" {
		buildURL = env["GITHUB_SERVER_URL"] + "/" + env["GITHUB_REPOSITORY"] + "/actions/runs/" + env["GITHUB_RUN_ID"]
	}
	return DetectionResult{
		Detected:            true,
		Provider:            ProviderGitHub,
		Name:                "GitHub Actions",
		PullRequest:         env["GITHUB_EVENT_NAME"] == "pull_request" || env["GITHUB_EVENT_NAME"] == "pull_request_target",
		Branch:              firstNonEmpty(env["GITHUB_HEAD_REF"], env["GITHUB_REF_NAME"]),
		CommitSHA:           env["GITHUB_SHA"],
		Repository:          env["GITHUB_REPOSITORY"],
		Workspace:           env["GITHUB_WORKSPACE"],
		BuildURL:            buildURL,
		SupportsSARIF:       true,
		SupportsAnnotations: true,
		SupportsStepSummary: env["GITHUB_STEP_SUMMARY"] != "",
		Notes:               []string{"Use SARIF upload for code scanning and github-step-summary for PR summaries."},
	}
}

func detectGitLab(env map[string]string) DetectionResult {
	return DetectionResult{
		Detected:            true,
		Provider:            ProviderGitLab,
		Name:                "GitLab CI",
		PullRequest:         env["CI_PIPELINE_SOURCE"] == "merge_request_event" || env["CI_MERGE_REQUEST_IID"] != "",
		Branch:              firstNonEmpty(env["CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"], env["CI_COMMIT_BRANCH"]),
		CommitSHA:           env["CI_COMMIT_SHA"],
		Repository:          env["CI_PROJECT_PATH"],
		Workspace:           env["CI_PROJECT_DIR"],
		BuildURL:            env["CI_PIPELINE_URL"],
		SupportsSARIF:       false,
		SupportsAnnotations: false,
		SupportsStepSummary: false,
		Notes:               []string{"Use gitlab-code-quality and JUnit artifacts for merge request feedback."},
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" && value != "/" {
			return value
		}
	}
	return ""
}
