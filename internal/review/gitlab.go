package review

import (
	"bytes"
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

const defaultGitLabAPIBaseURL = "https://gitlab.com/api/v4"

// GitLabNote is the subset of a merge request note needed for sticky updates.
type GitLabNote struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

// GitLabClient describes the GitLab merge request note operations used by reviews.
type GitLabClient interface {
	ListMergeRequestNotes(ctx context.Context, project string, mergeRequestIID int) ([]GitLabNote, error)
	CreateMergeRequestNote(ctx context.Context, project string, mergeRequestIID int, body string) (GitLabNote, error)
	UpdateMergeRequestNote(ctx context.Context, project string, mergeRequestIID int, noteID int64, body string) (GitLabNote, error)
}

// GitLabReviewRequest describes a sticky GitLab merge request note operation.
type GitLabReviewRequest struct {
	Project         string
	MergeRequestIID int
	Marker          string
	Body            string
	DryRun          bool
}

// GitLabReviewAction records an intended or completed GitLab review action.
type GitLabReviewAction struct {
	Action          string `json:"action"`
	Project         string `json:"project"`
	MergeRequestIID int    `json:"merge_request_iid"`
	NoteID          int64  `json:"note_id,omitempty"`
	BodyBytes       int    `json:"body_bytes"`
	ExistingFound   bool   `json:"existing_found"`
}

// PublishGitLabStickyNote creates or updates a single marked merge request note.
func PublishGitLabStickyNote(ctx context.Context, client GitLabClient, req GitLabReviewRequest) (GitLabReviewAction, error) {
	if req.Marker == "" {
		req.Marker = DefaultStickyCommentMarker
	}
	if req.Project == "" {
		return GitLabReviewAction{}, fmt.Errorf("gitlab project is required")
	}
	if req.MergeRequestIID <= 0 {
		return GitLabReviewAction{}, fmt.Errorf("gitlab merge request IID is required")
	}
	if req.Body == "" {
		return GitLabReviewAction{}, fmt.Errorf("gitlab review note body is required")
	}
	if !strings.Contains(req.Body, req.Marker) {
		return GitLabReviewAction{}, fmt.Errorf("gitlab review note body does not contain sticky marker")
	}
	if req.DryRun {
		return GitLabReviewAction{
			Action:          "dry-run upsert sticky note",
			Project:         req.Project,
			MergeRequestIID: req.MergeRequestIID,
			BodyBytes:       len(req.Body),
		}, nil
	}
	if client == nil {
		return GitLabReviewAction{}, fmt.Errorf("gitlab client is required")
	}

	notes, err := client.ListMergeRequestNotes(ctx, req.Project, req.MergeRequestIID)
	if err != nil {
		return GitLabReviewAction{}, fmt.Errorf("list gitlab merge request notes: %w", err)
	}
	for _, note := range notes {
		if strings.Contains(note.Body, req.Marker) {
			updated, err := client.UpdateMergeRequestNote(ctx, req.Project, req.MergeRequestIID, note.ID, req.Body)
			if err != nil {
				return GitLabReviewAction{}, fmt.Errorf("update gitlab merge request note %d: %w", note.ID, err)
			}
			return GitLabReviewAction{
				Action:          "updated sticky note",
				Project:         req.Project,
				MergeRequestIID: req.MergeRequestIID,
				NoteID:          updated.ID,
				BodyBytes:       len(req.Body),
				ExistingFound:   true,
			}, nil
		}
	}

	created, err := client.CreateMergeRequestNote(ctx, req.Project, req.MergeRequestIID, req.Body)
	if err != nil {
		return GitLabReviewAction{}, fmt.Errorf("create gitlab merge request note: %w", err)
	}
	return GitLabReviewAction{
		Action:          "created sticky note",
		Project:         req.Project,
		MergeRequestIID: req.MergeRequestIID,
		NoteID:          created.ID,
		BodyBytes:       len(req.Body),
	}, nil
}

// GitLabEnvironment captures GitLab CI context used by review commands.
type GitLabEnvironment struct {
	Token           string
	APIURL          string
	ProjectID       string
	ProjectURL      string
	MergeRequestIID string
	CommitSHA       string
	JobID           string
}

// DetectGitLabEnvironment reads GitLab CI environment variables.
func DetectGitLabEnvironment(getenv func(string) string) GitLabEnvironment {
	return GitLabEnvironment{
		Token:           getenv("GITLAB_TOKEN"),
		APIURL:          getenv("CI_API_V4_URL"),
		ProjectID:       getenv("CI_PROJECT_ID"),
		ProjectURL:      getenv("CI_PROJECT_URL"),
		MergeRequestIID: getenv("CI_MERGE_REQUEST_IID"),
		CommitSHA:       getenv("CI_COMMIT_SHA"),
		JobID:           getenv("CI_JOB_ID"),
	}
}

// GitLabCodeQualityArtifactURL returns a link to a job artifact when GitLab CI metadata is available.
func GitLabCodeQualityArtifactURL(env GitLabEnvironment, artifactPath string) string {
	if artifactPath == "" {
		artifactPath = "gl-code-quality-report.json"
	}
	if env.ProjectURL == "" || env.JobID == "" {
		return ""
	}
	return strings.TrimRight(env.ProjectURL, "/") + "/-/jobs/" + env.JobID + "/artifacts/file/" + strings.TrimLeft(artifactPath, "/")
}

// HTTPGitLabClient is a minimal GitLab REST client for merge request notes.
type HTTPGitLabClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewHTTPGitLabClient creates a GitLab REST client.
func NewHTTPGitLabClient(token string) *HTTPGitLabClient {
	return &HTTPGitLabClient{
		baseURL:    defaultGitLabAPIBaseURL,
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBaseURL sets the API base URL. It is intended for tests and self-managed GitLab.
func (c *HTTPGitLabClient) SetBaseURL(baseURL string) {
	c.baseURL = strings.TrimRight(baseURL, "/")
}

// ListMergeRequestNotes lists merge request notes.
func (c *HTTPGitLabClient) ListMergeRequestNotes(ctx context.Context, project string, mergeRequestIID int) ([]GitLabNote, error) {
	var all []GitLabNote
	for page := 1; ; page++ {
		path := fmt.Sprintf("/projects/%s/merge_requests/%d/notes?per_page=100&page=%d", gitLabProjectPath(project), mergeRequestIID, page)
		var notes []GitLabNote
		if err := c.do(ctx, http.MethodGet, path, nil, &notes); err != nil {
			return nil, err
		}
		all = append(all, notes...)
		if len(notes) < 100 {
			break
		}
	}
	return all, nil
}

// CreateMergeRequestNote creates a merge request note.
func (c *HTTPGitLabClient) CreateMergeRequestNote(ctx context.Context, project string, mergeRequestIID int, body string) (GitLabNote, error) {
	path := fmt.Sprintf("/projects/%s/merge_requests/%d/notes", gitLabProjectPath(project), mergeRequestIID)
	var note GitLabNote
	if err := c.do(ctx, http.MethodPost, path, map[string]string{"body": body}, &note); err != nil {
		return GitLabNote{}, err
	}
	return note, nil
}

// UpdateMergeRequestNote updates a merge request note.
func (c *HTTPGitLabClient) UpdateMergeRequestNote(ctx context.Context, project string, mergeRequestIID int, noteID int64, body string) (GitLabNote, error) {
	path := fmt.Sprintf("/projects/%s/merge_requests/%d/notes/%d", gitLabProjectPath(project), mergeRequestIID, noteID)
	var note GitLabNote
	if err := c.do(ctx, http.MethodPut, path, map[string]string{"body": body}, &note); err != nil {
		return GitLabNote{}, err
	}
	return note, nil
}

func (c *HTTPGitLabClient) do(ctx context.Context, method string, path string, body any, out any) error {
	if c == nil {
		return fmt.Errorf("gitlab client is nil")
	}
	if c.token == "" {
		return fmt.Errorf("gitlab token is required")
	}
	baseURL := c.baseURL
	if baseURL == "" {
		baseURL = defaultGitLabAPIBaseURL
	}
	endpoint := strings.TrimRight(baseURL, "/") + path
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode gitlab request: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("create gitlab request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "changegate")
	req.Header.Set("PRIVATE-TOKEN", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send gitlab request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gitlab API %s %s failed with %s: %s", method, path, resp.Status, strings.TrimSpace(string(limited)))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode gitlab response: %w", err)
	}
	return nil
}

func gitLabProjectPath(project string) string {
	return url.PathEscape(project)
}

// RenderGitLabReviewActions renders intended/completed actions for dry-run output.
func RenderGitLabReviewActions(actions []GitLabReviewAction) string {
	var b strings.Builder
	b.WriteString("ChangeGate GitLab review actions\n\n")
	if len(actions) == 0 {
		b.WriteString("- No GitLab API actions requested.\n")
		return b.String()
	}
	for _, action := range actions {
		line := "- " + action.Action
		if action.Project != "" {
			line += " on " + action.Project
		}
		if action.MergeRequestIID > 0 {
			line += "!" + strconv.Itoa(action.MergeRequestIID)
		}
		if action.NoteID > 0 {
			line += " note_id=" + strconv.FormatInt(action.NoteID, 10)
		}
		if action.BodyBytes > 0 {
			line += " body_bytes=" + strconv.Itoa(action.BodyBytes)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}
