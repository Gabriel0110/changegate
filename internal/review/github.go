package review

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultGitHubAPIBaseURL = "https://api.github.com"

// GitHubComment is the subset of an issue comment needed for sticky updates.
type GitHubComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

// GitHubClient describes the GitHub issue comment operations used by reviews.
type GitHubClient interface {
	ListIssueComments(ctx context.Context, repo string, issueNumber int) ([]GitHubComment, error)
	CreateIssueComment(ctx context.Context, repo string, issueNumber int, body string) (GitHubComment, error)
	UpdateIssueComment(ctx context.Context, repo string, commentID int64, body string) (GitHubComment, error)
}

// GitHubReviewRequest describes a sticky GitHub review comment operation.
type GitHubReviewRequest struct {
	Repo        string
	PullRequest int
	Marker      string
	Body        string
	DryRun      bool
}

// GitHubReviewAction records an intended or completed GitHub review action.
type GitHubReviewAction struct {
	Action        string `json:"action"`
	Repo          string `json:"repo"`
	PullRequest   int    `json:"pull_request"`
	CommentID     int64  `json:"comment_id,omitempty"`
	BodyBytes     int    `json:"body_bytes"`
	ExistingFound bool   `json:"existing_found"`
}

// PublishGitHubStickyComment creates or updates a single marked PR comment.
func PublishGitHubStickyComment(ctx context.Context, client GitHubClient, req GitHubReviewRequest) (GitHubReviewAction, error) {
	if req.Marker == "" {
		req.Marker = DefaultStickyCommentMarker
	}
	if req.Repo == "" {
		return GitHubReviewAction{}, fmt.Errorf("github repo is required")
	}
	if req.PullRequest <= 0 {
		return GitHubReviewAction{}, fmt.Errorf("github pull request number is required")
	}
	if req.Body == "" {
		return GitHubReviewAction{}, fmt.Errorf("github review comment body is required")
	}
	if !strings.Contains(req.Body, req.Marker) {
		return GitHubReviewAction{}, fmt.Errorf("github review comment body does not contain sticky marker")
	}
	if req.DryRun {
		return GitHubReviewAction{
			Action:      "dry-run upsert sticky comment",
			Repo:        req.Repo,
			PullRequest: req.PullRequest,
			BodyBytes:   len(req.Body),
		}, nil
	}
	if client == nil {
		return GitHubReviewAction{}, fmt.Errorf("github client is required")
	}

	comments, err := client.ListIssueComments(ctx, req.Repo, req.PullRequest)
	if err != nil {
		return GitHubReviewAction{}, fmt.Errorf("list github issue comments: %w", err)
	}
	for _, comment := range comments {
		if strings.Contains(comment.Body, req.Marker) {
			updated, err := client.UpdateIssueComment(ctx, req.Repo, comment.ID, req.Body)
			if err != nil {
				return GitHubReviewAction{}, fmt.Errorf("update github issue comment %d: %w", comment.ID, err)
			}
			return GitHubReviewAction{
				Action:        "updated sticky comment",
				Repo:          req.Repo,
				PullRequest:   req.PullRequest,
				CommentID:     updated.ID,
				BodyBytes:     len(req.Body),
				ExistingFound: true,
			}, nil
		}
	}

	created, err := client.CreateIssueComment(ctx, req.Repo, req.PullRequest, req.Body)
	if err != nil {
		return GitHubReviewAction{}, fmt.Errorf("create github issue comment: %w", err)
	}
	return GitHubReviewAction{
		Action:      "created sticky comment",
		Repo:        req.Repo,
		PullRequest: req.PullRequest,
		CommentID:   created.ID,
		BodyBytes:   len(req.Body),
	}, nil
}

// GitHubEnvironment captures GitHub Actions context used by review commands.
type GitHubEnvironment struct {
	Token     string
	Repo      string
	EventPath string
	SHA       string
	Ref       string
}

// DetectGitHubEnvironment reads GitHub Actions environment variables.
func DetectGitHubEnvironment(getenv func(string) string) GitHubEnvironment {
	return GitHubEnvironment{
		Token:     getenv("GITHUB_TOKEN"),
		Repo:      getenv("GITHUB_REPOSITORY"),
		EventPath: getenv("GITHUB_EVENT_PATH"),
		SHA:       getenv("GITHUB_SHA"),
		Ref:       getenv("GITHUB_REF"),
	}
}

// GitHubEventContext contains PR metadata parsed from a GitHub event payload.
type GitHubEventContext struct {
	PullRequest int
	CommitSHA   string
}

// ParseGitHubEventContext parses pull request metadata from a GitHub event payload.
func ParseGitHubEventContext(r io.Reader) (GitHubEventContext, error) {
	var payload struct {
		Number      int    `json:"number"`
		After       string `json:"after"`
		PullRequest struct {
			Number int `json:"number"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return GitHubEventContext{}, fmt.Errorf("decode github event payload: %w", err)
	}
	ctx := GitHubEventContext{PullRequest: payload.Number, CommitSHA: payload.After}
	if payload.PullRequest.Number > 0 {
		ctx.PullRequest = payload.PullRequest.Number
	}
	if payload.PullRequest.Head.SHA != "" {
		ctx.CommitSHA = payload.PullRequest.Head.SHA
	}
	return ctx, nil
}

// ResolveTokenSpec resolves literal tokens and env:NAME token references.
func ResolveTokenSpec(spec string, getenv func(string) string) (string, error) {
	if spec == "" {
		return "", nil
	}
	if !strings.HasPrefix(spec, "env:") {
		return spec, nil
	}
	name := strings.TrimPrefix(spec, "env:")
	if name == "" {
		return "", fmt.Errorf("token env reference is missing a variable name")
	}
	value := getenv(name)
	if value == "" {
		return "", fmt.Errorf("environment variable %s is empty", name)
	}
	return value, nil
}

// HTTPGitHubClient is a minimal GitHub REST client for issue comments.
type HTTPGitHubClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewHTTPGitHubClient creates a GitHub REST client.
func NewHTTPGitHubClient(token string) *HTTPGitHubClient {
	return &HTTPGitHubClient{
		baseURL:    defaultGitHubAPIBaseURL,
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBaseURL sets the API base URL. It is intended for tests and GitHub Enterprise.
func (c *HTTPGitHubClient) SetBaseURL(baseURL string) {
	c.baseURL = strings.TrimRight(baseURL, "/")
}

// ListIssueComments lists issue comments for a pull request.
func (c *HTTPGitHubClient) ListIssueComments(ctx context.Context, repo string, issueNumber int) ([]GitHubComment, error) {
	var all []GitHubComment
	for page := 1; ; page++ {
		path := fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", repo, issueNumber, page)
		var comments []GitHubComment
		if err := c.do(ctx, http.MethodGet, path, nil, &comments); err != nil {
			return nil, err
		}
		all = append(all, comments...)
		if len(comments) < 100 {
			break
		}
	}
	return all, nil
}

// CreateIssueComment creates an issue comment on a pull request.
func (c *HTTPGitHubClient) CreateIssueComment(ctx context.Context, repo string, issueNumber int, body string) (GitHubComment, error) {
	path := fmt.Sprintf("/repos/%s/issues/%d/comments", repo, issueNumber)
	var comment GitHubComment
	if err := c.do(ctx, http.MethodPost, path, map[string]string{"body": body}, &comment); err != nil {
		return GitHubComment{}, err
	}
	return comment, nil
}

// UpdateIssueComment updates an existing issue comment.
func (c *HTTPGitHubClient) UpdateIssueComment(ctx context.Context, repo string, commentID int64, body string) (GitHubComment, error) {
	path := fmt.Sprintf("/repos/%s/issues/comments/%d", repo, commentID)
	var comment GitHubComment
	if err := c.do(ctx, http.MethodPatch, path, map[string]string{"body": body}, &comment); err != nil {
		return GitHubComment{}, err
	}
	return comment, nil
}

func (c *HTTPGitHubClient) do(ctx context.Context, method string, path string, body any, out any) error {
	if c == nil {
		return fmt.Errorf("github client is nil")
	}
	if c.token == "" {
		return fmt.Errorf("github token is required")
	}
	baseURL := c.baseURL
	if baseURL == "" {
		baseURL = defaultGitHubAPIBaseURL
	}
	endpoint, err := url.JoinPath(baseURL, strings.TrimPrefix(path, "/"))
	if err != nil {
		return fmt.Errorf("build github url: %w", err)
	}
	if strings.Contains(path, "?") {
		parts := strings.SplitN(path, "?", 2)
		endpoint, err = url.JoinPath(baseURL, strings.TrimPrefix(parts[0], "/"))
		if err != nil {
			return fmt.Errorf("build github url: %w", err)
		}
		endpoint += "?" + parts[1]
	}

	reader, err := marshalProviderRequest("github", body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("create github request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "changegate")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send github request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return providerError("github", method, path, resp.Status, resp.Body, c.token)
	}
	return decodeProviderResponse("github", resp.Body, out)
}

// RenderGitHubReviewActions renders intended/completed actions for dry-run output.
func RenderGitHubReviewActions(actions []GitHubReviewAction) string {
	var b strings.Builder
	b.WriteString("ChangeGate GitHub review actions\n\n")
	if len(actions) == 0 {
		b.WriteString("- No GitHub API actions requested.\n")
		return b.String()
	}
	for _, action := range actions {
		line := "- " + action.Action
		if action.Repo != "" {
			line += " on " + action.Repo
		}
		if action.PullRequest > 0 {
			line += "#" + strconv.Itoa(action.PullRequest)
		}
		if action.CommentID > 0 {
			line += " comment_id=" + strconv.FormatInt(action.CommentID, 10)
		}
		if action.BodyBytes > 0 {
			line += " body_bytes=" + strconv.Itoa(action.BodyBytes)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}
