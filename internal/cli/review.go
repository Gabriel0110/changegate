package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/impact"
	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/Gabriel0110/changegate/internal/output"
	"github.com/Gabriel0110/changegate/internal/review"
	"github.com/spf13/cobra"
)

const maxReviewReportFileBytes = 25 * 1024 * 1024

type githubReviewOptions struct {
	scan        scanOptions
	reportPath  string
	comment     bool
	annotations bool
	dryRun      bool
	stepSummary bool

	repo      string
	pr        int
	commitSHA string
	tokenSpec string
	apiURL    string

	maxFindings    int
	maxPaths       int
	maxCommentSize int
	marker         string
	artifacts      []string
}

type gitLabReviewOptions struct {
	scan       scanOptions
	reportPath string
	comment    bool
	dryRun     bool

	project         string
	mergeRequestIID int
	commitSHA       string
	tokenSpec       string
	apiURL          string

	maxFindings          int
	maxPaths             int
	maxCommentSize       int
	marker               string
	artifacts            []string
	codeQualityURL       string
	codeQualityArtifact  string
	includeCodeQualityCI bool
}

func newReviewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "review",
		Short: "Post infrastructure review output to code review systems",
	}
	cmd.AddCommand(newReviewGitHubCommand())
	cmd.AddCommand(newReviewGitLabCommand())
	return cmd
}

func newReviewGitHubCommand() *cobra.Command {
	opts := &githubReviewOptions{}
	cmd := &cobra.Command{
		Use:   "github --report changegate.json --comment",
		Short: "Post or dry-run a GitHub PR infrastructure review",
		Long: `Post or dry-run a GitHub pull request review from a ChangeGate scan report
or directly from Terraform/OpenTofu plan JSON. The command updates one sticky
summary comment and can emit GitHub Actions workflow annotations.`,
		Args: func(_ *cobra.Command, _ []string) error {
			return validateGitHubReviewOptions(opts)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			report, plansScanned, err := githubReviewReport(cmd, state, opts)
			if err != nil {
				return err
			}
			statement, err := impact.Build(report, impact.Options{
				GeneratedAt:        time.Now().UTC(),
				PlansScanned:       plansScanned,
				TopFindingsLimit:   reviewLimit(opts.maxFindings, impact.DefaultTopFindingsLimit),
				TopGraphPathsLimit: reviewLimit(opts.maxPaths, impact.DefaultTopGraphPathsLimit),
				AttackPathsLimit:   reviewLimit(opts.maxPaths, impact.DefaultAttackPathsLimit),
			})
			if err != nil {
				return internalError(err.Error(), "Report this as a ChangeGate bug.")
			}
			if report.Decision == model.DecisionBlock {
				state.opts.exitCode = exitBlocked
			}

			artifactLinks, err := parseArtifactLinks(opts.artifacts)
			if err != nil {
				return usageError(err.Error(), "Use --artifact 'Label=https://example.test/artifact'.")
			}
			comment := review.RenderComment(statement, review.CommentOptions{
				Marker:         opts.marker,
				MaxFindings:    opts.maxFindings,
				MaxGraphPaths:  opts.maxPaths,
				MaxAttackPaths: opts.maxPaths,
				MaxBytes:       opts.maxCommentSize,
				ArtifactLinks:  artifactLinks,
			})

			actions, err := executeGitHubReview(cmd, state, opts, report, comment)
			if err != nil {
				return err
			}
			return writeGitHubReviewResult(state, opts, actions)
		},
	}
	addGitHubReviewFlags(cmd, opts)
	return cmd
}

func addGitHubReviewFlags(cmd *cobra.Command, opts *githubReviewOptions) {
	cmd.Flags().StringVar(&opts.reportPath, "report", "", "path to changegate scan JSON report")
	cmd.Flags().StringArrayVar(&opts.scan.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON; repeat for multiple plans")
	cmd.Flags().StringVar(&opts.scan.branch, "branch", "", "branch name for branch-specific policy thresholds")
	cmd.Flags().StringVar(&opts.scan.baselinePath, "baseline", "", "baseline file used to classify and suppress existing findings")
	cmd.Flags().BoolVar(&opts.scan.newOnly, "new-only", false, "only enforce findings not present in the baseline unless existing risk worsened")
	cmd.Flags().StringVar(&opts.scan.cloudContext, "cloud-context", "", "optional cloud context provider: aws")
	cmd.Flags().StringVar(&opts.scan.contextFile, "context-file", "", "offline cloud context snapshot file")
	cmd.Flags().StringArrayVar(&opts.scan.importSARIF, "import-sarif", nil, "import SARIF 2.1.0 findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importJSON, "import-json", nil, "import generic ChangeGate JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importCheckov, "import-checkov", nil, "import Checkov JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importTrivy, "import-trivy", nil, "import Trivy JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importKICS, "import-kics", nil, "import KICS JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importGrype, "import-grype", nil, "import Grype JSON findings as external evidence; repeatable")
	cmd.Flags().BoolVar(&opts.scan.failImport, "fail-on-import-error", false, "fail when an external scanner output cannot be imported")
	cmd.Flags().StringVar(&opts.scan.timeout, "timeout", "", "overall review analysis timeout such as 30s, 2m, or 5m")
	cmd.Flags().BoolVar(&opts.scan.changedOnly, "changed-only", false, "only enforce findings on resources changed by the plan")

	cmd.Flags().BoolVar(&opts.comment, "comment", false, "create or update one sticky pull request comment")
	cmd.Flags().BoolVar(&opts.annotations, "annotations", false, "emit GitHub Actions workflow annotations for findings")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print intended API actions without calling GitHub")
	cmd.Flags().BoolVar(&opts.stepSummary, "step-summary", false, "write the review summary to GITHUB_STEP_SUMMARY when set")
	cmd.Flags().StringVar(&opts.repo, "repo", "", "GitHub repository in owner/name form; defaults to GITHUB_REPOSITORY")
	cmd.Flags().IntVar(&opts.pr, "pr", 0, "GitHub pull request number; defaults to GITHUB_EVENT_PATH")
	cmd.Flags().StringVar(&opts.commitSHA, "commit-sha", "", "pull request head commit SHA; defaults to GITHUB_EVENT_PATH or GITHUB_SHA")
	cmd.Flags().StringVar(&opts.tokenSpec, "token", "env:GITHUB_TOKEN", "GitHub token literal or env:VARIABLE reference")
	cmd.Flags().StringVar(&opts.apiURL, "api-url", "", "GitHub API base URL for GitHub Enterprise")
	cmd.Flags().IntVar(&opts.maxFindings, "max-findings", 0, "maximum findings in the impact statement and comment; 0 uses the default")
	cmd.Flags().IntVar(&opts.maxPaths, "max-paths", 0, "maximum graph and attack paths in the impact statement and comment; 0 uses the default")
	cmd.Flags().IntVar(&opts.maxCommentSize, "max-comment-size", 0, "maximum sticky comment size in bytes; 0 uses the default")
	cmd.Flags().StringVar(&opts.marker, "sticky-comment-marker", review.DefaultStickyCommentMarker, "hidden marker used to update one stable review comment")
	cmd.Flags().StringArrayVar(&opts.artifacts, "artifact", nil, "artifact link in Label=https://example.test/file form; repeatable")
}

func newReviewGitLabCommand() *cobra.Command {
	opts := &gitLabReviewOptions{includeCodeQualityCI: true}
	cmd := &cobra.Command{
		Use:   "gitlab --report changegate.json --comment",
		Short: "Post or dry-run a GitLab MR infrastructure review",
		Long: `Post or dry-run a GitLab merge request review from a ChangeGate scan
report or directly from Terraform/OpenTofu plan JSON. The command updates one
sticky merge request note and can include GitLab Code Quality artifact links.`,
		Args: func(_ *cobra.Command, _ []string) error {
			return validateGitLabReviewOptions(opts)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := appFrom(cmd)
			if err != nil {
				return err
			}
			report, plansScanned, err := gitLabReviewReport(cmd, state, opts)
			if err != nil {
				return err
			}
			statement, err := impact.Build(report, impact.Options{
				GeneratedAt:        time.Now().UTC(),
				PlansScanned:       plansScanned,
				TopFindingsLimit:   reviewLimit(opts.maxFindings, impact.DefaultTopFindingsLimit),
				TopGraphPathsLimit: reviewLimit(opts.maxPaths, impact.DefaultTopGraphPathsLimit),
				AttackPathsLimit:   reviewLimit(opts.maxPaths, impact.DefaultAttackPathsLimit),
			})
			if err != nil {
				return internalError(err.Error(), "Report this as a ChangeGate bug.")
			}
			if report.Decision == model.DecisionBlock {
				state.opts.exitCode = exitBlocked
			}

			artifactLinks, err := gitLabArtifactLinks(opts)
			if err != nil {
				return usageError(err.Error(), "Use --artifact 'Label=https://example.test/artifact'.")
			}
			comment := review.RenderComment(statement, review.CommentOptions{
				Marker:         opts.marker,
				MaxFindings:    opts.maxFindings,
				MaxGraphPaths:  opts.maxPaths,
				MaxAttackPaths: opts.maxPaths,
				MaxBytes:       opts.maxCommentSize,
				ArtifactLinks:  artifactLinks,
			})

			actions, err := executeGitLabReview(cmd, opts, comment)
			if err != nil {
				return err
			}
			return writeGitLabReviewResult(state, opts, actions)
		},
	}
	addGitLabReviewFlags(cmd, opts)
	return cmd
}

func addGitLabReviewFlags(cmd *cobra.Command, opts *gitLabReviewOptions) {
	cmd.Flags().StringVar(&opts.reportPath, "report", "", "path to changegate scan JSON report")
	cmd.Flags().StringArrayVar(&opts.scan.planPaths, "plan", nil, "path to Terraform/OpenTofu plan JSON; repeat for multiple plans")
	cmd.Flags().StringVar(&opts.scan.branch, "branch", "", "branch name for branch-specific policy thresholds")
	cmd.Flags().StringVar(&opts.scan.baselinePath, "baseline", "", "baseline file used to classify and suppress existing findings")
	cmd.Flags().BoolVar(&opts.scan.newOnly, "new-only", false, "only enforce findings not present in the baseline unless existing risk worsened")
	cmd.Flags().StringVar(&opts.scan.cloudContext, "cloud-context", "", "optional cloud context provider: aws")
	cmd.Flags().StringVar(&opts.scan.contextFile, "context-file", "", "offline cloud context snapshot file")
	cmd.Flags().StringArrayVar(&opts.scan.importSARIF, "import-sarif", nil, "import SARIF 2.1.0 findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importJSON, "import-json", nil, "import generic ChangeGate JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importCheckov, "import-checkov", nil, "import Checkov JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importTrivy, "import-trivy", nil, "import Trivy JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importKICS, "import-kics", nil, "import KICS JSON findings as external evidence; repeatable")
	cmd.Flags().StringArrayVar(&opts.scan.importGrype, "import-grype", nil, "import Grype JSON findings as external evidence; repeatable")
	cmd.Flags().BoolVar(&opts.scan.failImport, "fail-on-import-error", false, "fail when an external scanner output cannot be imported")
	cmd.Flags().StringVar(&opts.scan.timeout, "timeout", "", "overall review analysis timeout such as 30s, 2m, or 5m")
	cmd.Flags().BoolVar(&opts.scan.changedOnly, "changed-only", false, "only enforce findings on resources changed by the plan")

	cmd.Flags().BoolVar(&opts.comment, "comment", false, "create or update one sticky merge request note")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print intended API actions without calling GitLab")
	cmd.Flags().StringVar(&opts.project, "project", "", "GitLab project ID or path such as group/project; defaults to CI_PROJECT_ID")
	cmd.Flags().IntVar(&opts.mergeRequestIID, "merge-request", 0, "GitLab merge request IID; defaults to CI_MERGE_REQUEST_IID")
	cmd.Flags().StringVar(&opts.commitSHA, "commit-sha", "", "merge request commit SHA; defaults to CI_COMMIT_SHA")
	cmd.Flags().StringVar(&opts.tokenSpec, "token", "env:GITLAB_TOKEN", "GitLab token literal or env:VARIABLE reference")
	cmd.Flags().StringVar(&opts.apiURL, "api-url", "", "GitLab API v4 base URL; defaults to CI_API_V4_URL or gitlab.com")
	cmd.Flags().IntVar(&opts.maxFindings, "max-findings", 0, "maximum findings in the impact statement and note; 0 uses the default")
	cmd.Flags().IntVar(&opts.maxPaths, "max-paths", 0, "maximum graph and attack paths in the impact statement and note; 0 uses the default")
	cmd.Flags().IntVar(&opts.maxCommentSize, "max-comment-size", 0, "maximum sticky note size in bytes; 0 uses the default")
	cmd.Flags().StringVar(&opts.marker, "sticky-comment-marker", review.DefaultStickyCommentMarker, "hidden marker used to update one stable review note")
	cmd.Flags().StringArrayVar(&opts.artifacts, "artifact", nil, "artifact link in Label=https://example.test/file form; repeatable")
	cmd.Flags().StringVar(&opts.codeQualityURL, "code-quality-url", "", "URL to a GitLab Code Quality artifact to include in the MR note")
	cmd.Flags().StringVar(&opts.codeQualityArtifact, "code-quality-artifact", "gl-code-quality-report.json", "GitLab Code Quality artifact path for CI auto-linking")
	cmd.Flags().BoolVar(&opts.includeCodeQualityCI, "gitlab-code-quality-link", opts.includeCodeQualityCI, "auto-link GitLab Code Quality artifact from CI_PROJECT_URL and CI_JOB_ID when available")
}

func validateGitHubReviewOptions(opts *githubReviewOptions) error {
	if opts.reportPath == "" && len(opts.scan.planPaths) == 0 {
		return usageError("missing --report or --plan", "Pass --report changegate.json from changegate scan --format json, or pass --plan tfplan.json.")
	}
	if opts.reportPath != "" && len(opts.scan.planPaths) > 0 {
		return usageError("--report and --plan cannot be combined", "Use a saved report or build the review directly from plan input, not both.")
	}
	if !opts.comment && !opts.annotations && !opts.stepSummary {
		return usageError("missing review output flag", "Pass --comment, --annotations, --step-summary, or a combination.")
	}
	if opts.maxFindings < 0 {
		return usageError("--max-findings must be zero or greater", "Use 0 for the default finding limit, or pass a positive cap.")
	}
	if opts.maxPaths < 0 {
		return usageError("--max-paths must be zero or greater", "Use 0 for the default path limit, or pass a positive cap.")
	}
	if opts.maxCommentSize < 0 {
		return usageError("--max-comment-size must be zero or greater", "Use 0 for the default comment limit, or pass a positive byte limit.")
	}
	return nil
}

func validateGitLabReviewOptions(opts *gitLabReviewOptions) error {
	if opts.reportPath == "" && len(opts.scan.planPaths) == 0 {
		return usageError("missing --report or --plan", "Pass --report changegate.json from changegate scan --format json, or pass --plan tfplan.json.")
	}
	if opts.reportPath != "" && len(opts.scan.planPaths) > 0 {
		return usageError("--report and --plan cannot be combined", "Use a saved report or build the review directly from plan input, not both.")
	}
	if !opts.comment {
		return usageError("missing review output flag", "Pass --comment to create, update, or dry-run a GitLab merge request note.")
	}
	if opts.maxFindings < 0 {
		return usageError("--max-findings must be zero or greater", "Use 0 for the default finding limit, or pass a positive cap.")
	}
	if opts.maxPaths < 0 {
		return usageError("--max-paths must be zero or greater", "Use 0 for the default path limit, or pass a positive cap.")
	}
	if opts.maxCommentSize < 0 {
		return usageError("--max-comment-size must be zero or greater", "Use 0 for the default comment limit, or pass a positive byte limit.")
	}
	return nil
}

func githubReviewReport(cmd *cobra.Command, state *appState, opts *githubReviewOptions) (output.Report, int, error) {
	if opts.reportPath != "" {
		report, err := loadScanReportFile(opts.reportPath)
		if err != nil {
			return output.Report{}, 0, err
		}
		return report, 1, nil
	}
	report, err := buildScanReport(cmd, state, &opts.scan)
	if err != nil {
		return output.Report{}, 0, err
	}
	return report, len(opts.scan.planPaths), nil
}

func gitLabReviewReport(cmd *cobra.Command, state *appState, opts *gitLabReviewOptions) (output.Report, int, error) {
	if opts.reportPath != "" {
		report, err := loadScanReportFile(opts.reportPath)
		if err != nil {
			return output.Report{}, 0, err
		}
		return report, 1, nil
	}
	report, err := buildScanReport(cmd, state, &opts.scan)
	if err != nil {
		return output.Report{}, 0, err
	}
	return report, len(opts.scan.planPaths), nil
}

func loadScanReportFile(path string) (output.Report, error) {
	file, err := os.Open(path)
	if err != nil {
		return output.Report{}, inputError(fmt.Sprintf("read report %q: %v", path, err), "Generate a report with changegate scan --format json --out changegate.json.")
	}
	defer closeReader(file)
	body, err := io.ReadAll(io.LimitReader(file, maxReviewReportFileBytes+1))
	if err != nil {
		return output.Report{}, inputError(fmt.Sprintf("read report %q: %v", path, err), "Generate a report with changegate scan --format json --out changegate.json.")
	}
	if len(body) > maxReviewReportFileBytes {
		return output.Report{}, inputError(fmt.Sprintf("report %q is too large", path), "Pass a ChangeGate scan JSON report smaller than 25 MiB.")
	}
	var report output.Report
	if err := json.Unmarshal(body, &report); err != nil {
		return output.Report{}, inputError(fmt.Sprintf("parse report %q: %v", path, err), "Use a ChangeGate scan JSON report.")
	}
	if report.SchemaVersion != output.ReportSchemaVersion {
		return output.Report{}, inputError(fmt.Sprintf("report %q has schema_version %q", path, report.SchemaVersion), "Use changegate scan --format json output for --report.")
	}
	return report, nil
}

func executeGitHubReview(cmd *cobra.Command, state *appState, opts *githubReviewOptions, report output.Report, comment string) ([]review.GitHubReviewAction, error) {
	var actions []review.GitHubReviewAction
	if opts.stepSummary {
		if opts.dryRun {
			actions = append(actions, review.GitHubReviewAction{Action: "dry-run write GITHUB_STEP_SUMMARY", BodyBytes: len(comment)})
		} else {
			if err := writeGitHubStepSummary(comment); err != nil {
				return nil, err
			}
			actions = append(actions, review.GitHubReviewAction{Action: "wrote GITHUB_STEP_SUMMARY", BodyBytes: len(comment)})
		}
	}
	if opts.annotations {
		annotations := output.RenderGitHubAnnotations(report)
		if opts.dryRun {
			actions = append(actions, review.GitHubReviewAction{Action: "dry-run emit workflow annotations", BodyBytes: len(annotations)})
		} else if annotations != "" {
			if _, err := state.renderer.out.Write([]byte(annotations)); err != nil {
				return nil, err
			}
		}
	}
	if !opts.comment {
		return actions, nil
	}

	env := review.DetectGitHubEnvironment(os.Getenv)
	repo := firstNonEmpty(opts.repo, env.Repo)
	pr := opts.pr
	commitSHA := firstNonEmpty(opts.commitSHA, env.SHA)
	if (pr == 0 || commitSHA == "") && env.EventPath != "" {
		eventCtx, err := parseGitHubEventFile(env.EventPath)
		if err != nil {
			return nil, inputError(err.Error(), "Check GITHUB_EVENT_PATH or pass --repo and --pr explicitly.")
		}
		if pr == 0 {
			pr = eventCtx.PullRequest
		}
		if commitSHA == "" {
			commitSHA = eventCtx.CommitSHA
		}
	}
	if repo == "" {
		return nil, usageError("missing GitHub repository", "Set GITHUB_REPOSITORY or pass --repo owner/name.")
	}
	if pr <= 0 {
		return nil, usageError("missing GitHub pull request number", "Set GITHUB_EVENT_PATH from a pull_request event or pass --pr.")
	}

	token, err := review.ResolveTokenSpec(opts.tokenSpec, os.Getenv)
	if err != nil && !opts.dryRun {
		return nil, usageError(err.Error(), "Set GITHUB_TOKEN or pass --token env:NAME.")
	}
	if token == "" && !opts.dryRun {
		return nil, usageError("missing GitHub token", "Set GITHUB_TOKEN or pass --token env:NAME.")
	}

	client := review.NewHTTPGitHubClient(token)
	if opts.apiURL != "" {
		client.SetBaseURL(opts.apiURL)
	}
	action, err := review.PublishGitHubStickyComment(cmd.Context(), client, review.GitHubReviewRequest{
		Repo:        repo,
		PullRequest: pr,
		Marker:      opts.marker,
		Body:        comment,
		DryRun:      opts.dryRun,
	})
	if err != nil {
		return nil, internalError(err.Error(), "Check GitHub permissions: issues:write and pull-requests:write.")
	}
	if commitSHA != "" {
		action.Action += " for commit " + shortSHA(commitSHA)
	}
	actions = append(actions, action)
	return actions, nil
}

func executeGitLabReview(cmd *cobra.Command, opts *gitLabReviewOptions, comment string) ([]review.GitLabReviewAction, error) {
	env := review.DetectGitLabEnvironment(os.Getenv)
	project := firstNonEmpty(opts.project, env.ProjectID)
	mergeRequestIID := opts.mergeRequestIID
	commitSHA := firstNonEmpty(opts.commitSHA, env.CommitSHA)
	if mergeRequestIID == 0 && env.MergeRequestIID != "" {
		parsed, err := strconv.Atoi(env.MergeRequestIID)
		if err != nil {
			return nil, usageError("CI_MERGE_REQUEST_IID must be numeric", "Pass --merge-request explicitly or run from a GitLab merge request pipeline.")
		}
		mergeRequestIID = parsed
	}
	if project == "" {
		return nil, usageError("missing GitLab project", "Set CI_PROJECT_ID or pass --project.")
	}
	if mergeRequestIID <= 0 {
		return nil, usageError("missing GitLab merge request IID", "Set CI_MERGE_REQUEST_IID or pass --merge-request.")
	}

	token, err := review.ResolveTokenSpec(opts.tokenSpec, os.Getenv)
	if err != nil && !opts.dryRun {
		return nil, usageError(err.Error(), "Set GITLAB_TOKEN or pass --token env:NAME.")
	}
	if token == "" && !opts.dryRun {
		return nil, usageError("missing GitLab token", "Set GITLAB_TOKEN or pass --token env:NAME.")
	}

	client := review.NewHTTPGitLabClient(token)
	apiURL := firstNonEmpty(opts.apiURL, env.APIURL)
	if apiURL != "" {
		client.SetBaseURL(apiURL)
	}
	action, err := review.PublishGitLabStickyNote(cmd.Context(), client, review.GitLabReviewRequest{
		Project:         project,
		MergeRequestIID: mergeRequestIID,
		Marker:          opts.marker,
		Body:            comment,
		DryRun:          opts.dryRun,
	})
	if err != nil {
		return nil, internalError(err.Error(), "Check GitLab permissions: api scope or permissions to create merge request notes.")
	}
	if commitSHA != "" {
		action.Action += " for commit " + shortSHA(commitSHA)
	}
	return []review.GitLabReviewAction{action}, nil
}

func parseGitHubEventFile(path string) (review.GitHubEventContext, error) {
	file, err := os.Open(path)
	if err != nil {
		return review.GitHubEventContext{}, fmt.Errorf("open GitHub event payload %q: %w", path, err)
	}
	defer closeReader(file)
	return review.ParseGitHubEventContext(file)
}

func writeGitHubStepSummary(comment string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return inputError("GITHUB_STEP_SUMMARY is not set", "Run inside GitHub Actions or omit --step-summary.")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return inputError(fmt.Sprintf("open GITHUB_STEP_SUMMARY %q: %v", path, err), "Check the workflow summary file path.")
	}
	if _, err := file.Write([]byte(comment)); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return inputError(fmt.Sprintf("close GITHUB_STEP_SUMMARY %q after write error: %v", path, closeErr), "Check the workflow summary file path.")
		}
		return inputError(fmt.Sprintf("write GITHUB_STEP_SUMMARY %q: %v", path, err), "Check the workflow summary file path.")
	}
	if err := file.Close(); err != nil {
		return inputError(fmt.Sprintf("close GITHUB_STEP_SUMMARY %q: %v", path, err), "Check the workflow summary file path.")
	}
	return nil
}

func writeGitHubReviewResult(state *appState, opts *githubReviewOptions, actions []review.GitHubReviewAction) error {
	if !opts.dryRun {
		if opts.comment && !opts.annotations {
			_, err := fmt.Fprintln(state.renderer.out, "ChangeGate GitHub review comment published.")
			return err
		}
		return nil
	}
	if state.opts.format == "json" {
		return writeJSON(state.renderer.out, jsonEnvelope{OK: true, Command: "review github", Result: actions})
	}
	_, err := state.renderer.out.Write([]byte(review.RenderGitHubReviewActions(actions)))
	return err
}

func writeGitLabReviewResult(state *appState, opts *gitLabReviewOptions, actions []review.GitLabReviewAction) error {
	if !opts.dryRun {
		_, err := fmt.Fprintln(state.renderer.out, "ChangeGate GitLab review note published.")
		return err
	}
	if state.opts.format == "json" {
		return writeJSON(state.renderer.out, jsonEnvelope{OK: true, Command: "review gitlab", Result: actions})
	}
	_, err := state.renderer.out.Write([]byte(review.RenderGitLabReviewActions(actions)))
	return err
}

func gitLabArtifactLinks(opts *gitLabReviewOptions) ([]review.ArtifactLink, error) {
	links, err := parseArtifactLinks(opts.artifacts)
	if err != nil {
		return nil, err
	}
	codeQualityURL := opts.codeQualityURL
	if codeQualityURL == "" && opts.includeCodeQualityCI {
		codeQualityURL = review.GitLabCodeQualityArtifactURL(review.DetectGitLabEnvironment(os.Getenv), opts.codeQualityArtifact)
	}
	if codeQualityURL != "" {
		links = append(links, review.ArtifactLink{Label: "GitLab Code Quality", URL: codeQualityURL})
	}
	return links, nil
}

func parseArtifactLinks(values []string) ([]review.ArtifactLink, error) {
	links := make([]review.ArtifactLink, 0, len(values))
	for _, value := range values {
		label, rawURL, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(label) == "" || strings.TrimSpace(rawURL) == "" {
			return nil, fmt.Errorf("invalid artifact link %q", value)
		}
		cleanURL := strings.TrimSpace(rawURL)
		parsed, err := url.Parse(cleanURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || strings.ContainsAny(cleanURL, "\r\n\t ") {
			return nil, fmt.Errorf("invalid artifact URL %q", rawURL)
		}
		links = append(links, review.ArtifactLink{Label: strings.TrimSpace(label), URL: cleanURL})
	}
	return links, nil
}

func reviewLimit(value int, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func shortSHA(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
